# Логика взаимодействия клиента и сервера NovaVPN

> **Назначение**: практическое руководство для разработчиков новых клиентов NovaVPN.  
> Описывает **логику взаимодействия** между клиентом и сервером — жизненный цикл соединения, машину состояний, обработку ошибок и переподключение.  
> Детальную спецификацию формата пакетов и криптографии см. в [NOVAVPN_PROTOCOL.md](NOVAVPN_PROTOCOL.md).

---

## 1. Общая архитектура

```
┌─────────────────────┐         UDP (порт 443)         ┌──────────────────────┐
│     VPN-клиент      │ ◄─────────────────────────────► │     VPN-сервер       │
│                     │    Маскировка под QUIC             │                      │
│  ┌───────────────┐  │                                 │  ┌────────────────┐  │
│  │  UDP-сокет    │──┼── Handshake / Data / Keepalive ─┼──│  UDP-listener  │  │
│  └───────┬───────┘  │                                 │  └────────┬───────┘  │
│          │          │                                 │           │          │
│  ┌───────▼───────┐  │                                 │  ┌────────▼───────┐  │
│  │  TUN-адаптер  │  │         IP-пакеты               │  │ TUN-интерфейс  │  │
│  └───────────────┘  │                                 │  └────────────────┘  │
└─────────────────────┘                                 └──────────────────────┘
```

**Протокол**: собственный, поверх UDP с маскировкой под QUIC Short Header.  
**Шифрование**: ChaCha20 (данные) / ChaCha20-Poly1305 AEAD (рукопожатие).  
**Обмен ключами**: ECDH Curve25519 (ephemeral).  
**Аутентификация**: email + пароль.

---

## 2. Машина состояний клиента

```
                    ┌──────────────────┐
                    │  Disconnected    │ ◄──── Начальное состояние
                    │   (Отключён)     │
                    └────────┬─────────┘
                             │ Connect()
                             ▼
                    ┌──────────────────┐
              ┌────►│   Connecting     │ ◄──── Handshake / Reconnect
              │     │  (Подключение)   │
              │     └────────┬─────────┘
              │              │ Handshake OK
              │              ▼
              │     ┌──────────────────┐
              │     │   Connected      │ ◄──── Туннель работает
              │     │   (Подключён)    │
              │     └──┬───────────┬───┘
              │        │           │
   Потеря     │        │           │ Disconnect()
   соединения │        │           ▼
              └────────┘  ┌──────────────────┐
                          │  Disconnecting   │
                          │  (Отключение)    │
                          └────────┬─────────┘
                                   │
                                   ▼
                          ┌──────────────────┐
                          │  Disconnected    │
                          └──────────────────┘
```

### Переходы состояний

| Из | В | Триггер |
|----|---|---------|
| Disconnected | Connecting | Вызов `Connect()` |
| Connecting | Connected | Успешный handshake |
| Connecting | Disconnected | Все попытки исчерпаны или вызван `Disconnect()` |
| Connected | Connecting | Потеря соединения (auto-reconnect) |
| Connected | Disconnecting | Вызов `Disconnect()` |
| Disconnecting | Disconnected | Завершение очистки |

---

## 3. Жизненный цикл соединения

### 3.1. Подключение (Connect)

```
1. Загрузить конфиг (server_addr, email, password, psk)
2. Состояние → Connecting
3. Определить PSK:
   - Есть сохранённый PSK → использовать его
   - Нет PSK → нулевой ключ [32]byte{0x00...} (bootstrap-режим)
4. Создать UDP-сокет к серверу
5. Выполнить handshake (см. раздел 4)
6. Создать TUN-адаптер с полученными параметрами:
   - IP-адрес: AssignedIP из HandshakeResp
   - Маска подсети: SubnetMask из HandshakeResp
   - MTU: из HandshakeResp
7. Настроить DNS (DNS1, DNS2 из HandshakeResp)
8. Настроить маршруты:
   - Windows/Linux/macOS: split routes (0/1 + 128/1) + серверный маршрут через физический шлюз
   - Android: addRoute("0.0.0.0", 0) + addDisallowedApplication + protect(socket)
9. Запустить 4 рабочих цикла:
   - Чтение из UDP → расшифровка → запись в TUN
   - Чтение из TUN → шифрование → отправка в UDP
   - Keepalive каждые 10-20 секунд (рандомизированный, crypto/rand)
   - Мониторинг физической сети (каждые 2 сек / ConnectivityManager)
10. Запустить health monitor (active probe + wake detection + passive, проверка каждые 3-7 сек)
11. Состояние → Connected
```

### 3.2. Обмен данными (Connected)

В состоянии Connected работают три параллельных цикла:

**Цикл приёма (UDP → TUN)**:
```
loop:
  conn.SetReadDeadline(сейчас + 30 сек)  // failsafe: timeout = healthLostThreshold
  data = udp.Read()
  если ошибка чтения (или timeout):
    запустить reconnect()
    выйти из цикла
  healthMonitor.RecordActivity()  // atomic store, ~1 нс
  разобрать пакет:
    если Data (0x10):  расшифровать → записать в TUN
    если Keepalive (0x20): игнорировать (активность уже зафиксирована)
    если Disconnect (0x30): сервер отключает → очистить resume-данные → закрыть conn
```

**Цикл отправки (TUN → UDP)**:
```
loop:
  если stopped: выйти
  packet = tun.Read()
  если идёт reconnect: пропустить (дропнуть пакет)
  зашифровать пакет → udp.Write()
  если ошибка записи: залогировать, продолжить (не выходить!)
```

**Цикл keepalive**:
```
loop:
  interval = randomKeepaliveInterval()  // 10-20 сек, crypto/rand
  ждать interval (с проверкой stopCh)
  если идёт reconnect: пропустить
  err = отправить keepalive (50-160 байт, с random padding и обфускацией заголовка)
  если ошибка записи: закрыть conn (маршрут мёртв) → udpReadLoop получит ошибку → reconnect
  healthMonitor.RecordKeepaliveSent()  // только если нет ожидающего probe
```

**Health monitor** (отдельная горутина, active probe + passive + wake detection):
```
loop:
  interval = randomCheckInterval()  // 3-7 сек
  wallBefore = currentTimeMillis()
  ждать interval
  wallAfter = currentTimeMillis()

  // Wake Detection: если wall clock прыгнул (sleep/hibernate)
  если (wallAfter - wallBefore) > interval * 3:
      → HealthLost (устройство спало) → закрыть conn → reconnect

  elapsed = сейчас - lastActivity

  // Active Probe: keepalive отправлен, но ответ не пришёл за 15 сек
  если lastActivity < lastKeepaliveSent И (сейчас - lastKeepaliveSent) >= 15 сек:
      → HealthLost (probe expired) → закрыть conn → reconnect

  // Passive: пороги по lastActivity
  определить уровень:
    < 20 сек  → HealthGood (стабильно)
    20-30 сек → HealthDegraded (нестабильно)
    > 30 сек  → HealthLost (потеряно)
  если уровень изменился:
    вызвать HealthCallback
    если HealthLost: закрыть conn → reconnect
```

### 3.3. Отключение (Disconnect)

```
1. Состояние → Disconnecting
2. Установить флаг stopped = true
3. Закрыть stopCh (сигнал всем циклам)
4. Дождаться завершения reconnect, если он в процессе
5. Сохранить данные для 0-RTT resume:
   - SessionID, ключи, sendCounter
   - IP, DNS, MTU, SubnetMask
6. Отправить Disconnect-пакет серверу (50-160 байт, с random padding и обфускацией заголовка)
7. Остановить все циклы:
   - Отменить контекст (остановить keepalive)
   - Закрыть UDP conn (разблокировать UDP Read)
   - Закрыть TUN (разблокировать TUN Read)
8. Дождаться завершения всех горутин/потоков
9. Очистить сессию
10. Состояние → Disconnected
```

---

## 4. Рукопожатие (1-RTT Handshake)

### 4.1. Общая схема

```
Клиент                                          Сервер
  │                                               │
  │  1. HandshakeInit (0x01)                       │
  │  (ClientPubKey + EncCreds + HMAC)              │
  │  ──────────────────────────────────────────►   │
  │                                               │ Проверка HMAC (PSK/zeroPSK)
  │                                               │ Расшифровка credentials
  │                                               │ Аутентификация email+пароль
  │                                               │ Создание сессии
  │                                               │ ECDH → сессионные ключи
  │  2. HandshakeResp (0x02)                       │
  │  (ServerPubKey + зашифрованные параметры)      │
  │  ◄──────────────────────────────────────────   │
  │                                               │ ★ Сессия активна сразу
  │ ECDH → сессионные ключи                       │
  │ Расшифровка параметров сессии                 │
  │ [Сохранение PSK если bootstrap]               │
  │                                               │
  │  ════════ Туннель установлен (1-RTT) ════════  │
  │  Можно отправлять Data сразу!                  │
  │                                               │
  │  3. HandshakeComplete (0x03)                   │
  │  (fire-and-forget, потеря не критична)         │
  │  ──────────────────────────────────────────►   │
```

> **1-RTT**: сервер активирует сессию сразу после отправки HandshakeResp. Клиент может передавать данные сразу после получения Resp, не дожидаясь подтверждения Complete.

### 4.2. Алгоритм клиента

```python
# Шаг 1: Формирование и отправка HandshakeInit
clientPriv, clientPub = curve25519_keygen()
timestamp = time.now_unix()

# Шифрование credentials (email + password)
credsPlaintext = marshal_credentials(email, password)
credsNonce = random(12)
credsCiphertext = chacha20poly1305_seal(PSK, credsNonce, credsPlaintext)
encCreds = credsNonce + credsCiphertext

# HMAC для проверки знания PSK
hmacData = clientPub + uint64_be(timestamp) + encCreds
hmac = hmac_sha256(PSK, hmacData)

# Сборка payload с random padding (100-400 байт)
payload = clientPub + uint64_be(timestamp) + uint16_be(len(encCreds)) + encCreds + hmac
padding = random_bytes(random(100, 400))
payload = payload + padding

# Отправка с QUIC Short Header и обфускацией
packet = marshal_handshake(type=0x01, sessionID=0, nonce=zeros(12), payload=payload)
ObfuscateHeader(packet[5:], headerMask, isData=false)
udp.send(packet)

# Шаг 2: Приём и обработка HandshakeResp
packet = recv_packet(timeout)
assert packet.type == 0x02

serverPub = packet.payload[:32]
encryptedResp = packet.payload[32:]

# ECDH и вывод сессионных ключей
sharedSecret = ecdh(clientPriv, serverPub)
keys = hkdf_sha256(ikm=sharedSecret, salt=PSK, info="novavpn-session-keys-v1", len=96)
recvKey  = keys[0:32]     # key1 = RecvKey для клиента
sendKey  = keys[32:64]    # key2 = SendKey для клиента
hmacKey  = keys[64:96]    # key3 = HMACKey (одинаковый)

# Расшифровка параметров сессии
respData = chacha20poly1305_open(recvKey, packet.nonce, encryptedResp)
sessionID  = parse_uint32_be(respData[32:36])
assignedIP = parse_ipv4(respData[36:40])
subnetMask = respData[40]
dns1       = parse_ipv4(respData[41:45])
dns2       = parse_ipv4(respData[45:49])
mtu        = parse_uint16_be(respData[49:51])
serverHMAC = respData[51:83]

# Проверка HMAC
assert hmac_sha256(hmacKey, respData[:51]) == serverHMAC

# Сохранение PSK (если bootstrap)
if respData[83] == 1 and len(respData) >= 116:
    newPSK = respData[84:116]
    save_psk(newPSK)

# Шаг 3: HandshakeComplete (fire-and-forget)
confirmData = f"novavpn-confirm-{sessionID}".encode()
confirmHMAC = hmac_sha256(hmacKey, confirmData)

# Random padding 100-400 байт перед шифрованием
paddedPayload = confirmHMAC + random_bytes(random(100, 400))
completeNonce = random(12)
encrypted = chacha20poly1305_seal(sendKey, completeNonce, paddedPayload)

packet = marshal_handshake(type=0x03, sessionID=sessionID, nonce=completeNonce, payload=encrypted)
ObfuscateHeader(packet[5:], headerMask, isData=false)
udp.send(packet)
# ↑ Потеря этого пакета не влияет на работу (сессия уже активна)
```

### 4.3. PSK Bootstrap (первое подключение)

При первом подключении клиент не имеет PSK:

```
1. Клиент использует нулевой PSK → [32]byte{0x00...}
2. Сервер проверяет HMAC:
   - Сначала с настоящим PSK → не совпадает
   - Затем с нулевым PSK → совпадает (bootstrap-режим)
3. Сервер аутентифицирует email+пароль
4. Сервер включает настоящий PSK в HandshakeResp (HasPSK=1)
5. Клиент сохраняет PSK в конфиг для будущих подключений
```

### 4.4. Fallback при смене PSK на сервере

```
1. Клиент отправляет HandshakeInit со старым PSK
2. Сервер отклоняет МОЛЧА (не отправляя Error-пакет)
3. Клиент ждёт 2 секунды → таймаут
4. Клиент автоматически повторяет с нулевым PSK (bootstrap)
5. Сервер принимает → передаёт новый PSK
```

**Полный алгоритм клиента:**
```
если есть_сохранённый_psk:
    попробовать handshake(psk=сохранённый, timeout=2с)
    если ошибка:
        попробовать handshake(psk=нулевой, timeout=10с)
иначе:
    handshake(psk=нулевой, timeout=10с)
```

---

## 5. Keepalive и мониторинг здоровья соединения

### 5.1. Клиент → Сервер

- **Интервал**: **10-20 секунд** (рандомизированный, `crypto/rand`)
- **Рандомизация**: каждый раз новый интервал — защита от DPI-детектирования регулярных паттернов
- **Формат**: 50-160 байт (QUIC header + SessionID + тип 0x20 + random padding)
- **Цель**: поддержание NAT-маппинга, подтверждение живости

### 5.2. Сервер → Клиент

- **Интервал**: **25 ± 7 секунд** (рандомизированный, 18–32 сек)
- **Рандомизация**: анти-DPI мера, интервал пересчитывается после каждой отправки
- **Формат**: 50-160 байт (аналогичный, с random padding)

### 5.3. Мониторинг здоровья соединения (Health Monitor)

Клиент запускает `connectionMonitor` — отдельный lock-free компонент с **тремя механизмами обнаружения** мёртвого соединения:

1. **Active Probe** — при отправке keepalive фиксируется `lastKeepaliveSent`. Если ответ (любой пакет) не пришёл за 15 сек — соединение мертво.
2. **Wake Detection** — сравнение wall clock до и после `sleep/delay`. Если дельта >> ожидаемого интервала — устройство спало (Android TV sleep, ноутбук hibernate). Немедленный reconnect.
3. **Passive Thresholds** — время с последнего полученного пакета. Три уровня:

**Три уровня здоровья:**

| Уровень | Условие | Действие |
|---------|---------|----------|
| `HealthGood` (Стабильно) | < 20 сек без пакетов | Нормальная работа |
| `HealthDegraded` (Нестабильно) | 20-30 сек без пакетов | Уведомление UI (жёлтый) |
| `HealthLost` (Потеряно) | > 30 сек без пакетов | Закрытие conn → reconnect |

**Почему 20 секунд** для `Degraded`:
Макс. клиентский keepalive = 20 сек. Если за 20 сек не пришёл ни один пакет — что-то не так.

**Почему 30 секунд** для `Lost`:
Макс. серверный keepalive = 32 сек (25 + 7). За 30 сек должен был прийти хотя бы один ответ на наш keepalive.

**Active Probe (зачем нужен):**
Пассивные пороги медленные — нужно ждать 30 сек. Active probe обнаруживает потерю за 15 сек: если мы отправили keepalive и за 15 сек не получили **ни одного** пакета — сервер не отвечает.

**Wake Detection (зачем нужен):**
После сна устройства (Android TV, ноутбук) `System.nanoTime()` / `time.Now()` могут не отразить пропущенное время. Wall clock (`currentTimeMillis`) надёжнее. Если дельта wall clock сильно превышает ожидаемый интервал проверки — устройство спало, и соединение гарантированно мертво (сервер уже удалил сессию через 120 сек).

```
при каждом полученном пакете:
    healthMonitor.RecordActivity()  // atomic store, ~1 нс

при каждой отправке keepalive:
    healthMonitor.RecordKeepaliveSent()  // atomic store

каждые 3-7 секунд (рандомизировано):
    wallBefore = currentTimeMillis()
    delay(interval)
    wallAfter = currentTimeMillis()

    // 1. Wake Detection
    если (wallAfter - wallBefore) > interval * 3:
        → HealthLost → reconnect

    // 2. Active Probe
    если lastActivity < lastKeepaliveSent И
       (сейчас - lastKeepaliveSent) >= 15 сек:
        → HealthLost → reconnect

    // 3. Passive Thresholds
    elapsed = сейчас - lastActivity
    newHealth = определить_уровень(elapsed)  // 20/30 сек
    если newHealth != currentHealth:
        вызвать HealthCallback(newHealth)
        если newHealth == HealthLost:
            закрыть UDP-соединение → reconnect
```

**Ресурсоэффективность:**
| Аспект | Затраты |
|--------|---------|
| Сеть | 0 доп. пакетов (использует существующие keepalive) |
| CPU | 2 atomic store на keepalive + 1 проверка каждые 3-7 сек |
| Память | ~192 байт (3 atomic + колбэки) |
| Аллокации | 0 (lock-free) |

**Платформо-специфичные механизмы:**

| Платформа | Механизм | Описание |
|-----------|----------|----------|
| Windows | `networkMonitorLoop` | Каждые 2 сек опрашивает физические IPv4. Обнаруживает **пропажу** сети И **смену** сети (другой IP/шлюз → стейл маршрут). При любом изменении → немедленный reconnect |
| Android TV | `ConnectivityManager` | Системный callback `onLost()`/`onAvailable()`. При потере сети → немедленный `forceReconnect()` |

**Таймауты:**
| Параметр | Значение | Описание |
|----------|----------|----------|
| Keepalive интервал (клиент) | 10-20 сек | Рандомизированный (crypto/rand) |
| Keepalive интервал (сервер) | 25±7 сек | Рандомизированный |
| Active Probe таймаут | 15 сек | Ожидание ответа после keepalive |
| Health: Degraded порог | 20 сек | Макс. клиентский keepalive |
| Health: Lost порог | 30 сек | Макс. серверный keepalive |
| Health check интервал | 3-7 сек | Рандомизированный (локальный) |
| Network monitor интервал | 2 сек | Проверка физических интерфейсов (Windows) |
| Таймаут сессии (сервер) | 120 сек | Без активности — удаление сессии |

### 5.4. Address Migration (смена IP клиента)

При получении keepalive от клиента сервер проверяет адрес отправителя:
```
если session.ClientAddr != remoteAddr:
    обновить session.ClientAddr = remoteAddr
    логировать "Address migration"
```

Это позволяет клиенту продолжать работу после:
- Смены IP провайдером
- Переключения Wi-Fi ↔ Mobile
- NAT rebind
- 0-RTT resume с нового адреса

---

## 6. Автоматическое переподключение (Auto-Reconnect)

### 6.1. Когда срабатывает

- Ошибка чтения UDP (`conn.Read()` → error)
- Dead-peer detection (active probe: 15 сек, passive: 30 сек без данных — health monitor `HealthLost`)
- Network monitor: потеря физической сети ИЛИ смена сети (другой IP/шлюз при переключении Wi-Fi)
- Сервер отправил Disconnect (перезагрузка/остановка)

### 6.2. Алгоритм

```
reconnect():
  // Защита от параллельного запуска
  если reconnecting уже запущен: выйти
  установить reconnecting = true

  Состояние → Connecting

  // Сохранить данные для 0-RTT resume
  сохранить SessionID, ключи, sendCounter, IP, DNS, MTU

  закрыть старый UDP-сокет

  // Очистка VPN-маршрутов (0.0.0.0/1, 128.0.0.0/1, server/32)
  // Без этого трафик к серверу идёт через мёртвый TUN
  очистить VPN-маршруты

  // Цикл переподключения (до 60 попыток)
  для attempt = 1..60:
    если stopped: → Disconnected, выйти

    ждать backoff_delay  // 1с → 2с → 4с → ... → 30с (макс)

    // Проверка физической сети
    если нет физической сети:
      логировать "нет сети, ожидание"
      backoff = 2с  // не увеличиваем backoff без сети
      продолжить цикл

    создать новый UDP-сокет

    // Попытка 1: 0-RTT resume (быстрый путь)
    если есть resume-данные:
      отправить keepalive probe с сохранённым SessionID
      ждать ответ 1 секунду
      если получен keepalive-ответ:
        восстановить сессию из сохранённых данных
        → успех!
      иначе:
        очистить resume-данные

    // Попытка 2: полный handshake
    если не resumed:
      выполнить performHandshake(timeout=5с)
      если ошибка:
        закрыть сокет
        увеличить backoff (×2, макс 30с)
        продолжить цикл

    // Перенастраиваем сеть ВСЕГДА (маршруты, DNS)
    // Физический шлюз мог измениться (другой WiFi)
    перенастроить сеть (IP, DNS, маршруты)

    // Успех — запустить рабочие циклы
    запустить UDP-цикл приёма
    запустить keepalive-цикл
    Состояние → Connected
    выйти

  // Все попытки исчерпаны
  Состояние → Disconnected
```

### 6.3. Экспоненциальный backoff

```
Попытка 1:  backoff = 1 сек
Попытка 2:  backoff = 2 сек
Попытка 3:  backoff = 4 сек
Попытка 4:  backoff = 8 сек
Попытка 5:  backoff = 16 сек
Попытка 6+: backoff = 30 сек (максимум)
```

### 6.4. Координация с Disconnect

Reconnect проверяет флаг `stopped` и канал `stopCh` на каждом шаге:
- Если `Disconnect()` вызван во время reconnect → reconnect прерывается
- Backoff-задержка прерывается через `stopCh` (не нужно ждать полный таймаут)
- Параллельные reconnect предотвращаются через атомарный флаг `reconnecting`

---

## 7. 0-RTT Session Resume

### 7.1. Принцип

При штатном отключении или потере соединения клиент сохраняет данные сессии для мгновенного восстановления без полного handshake:

```
Сохраняемые данные:
- SessionID
- Сессионные ключи (SendKey, RecvKey, HMACKey)
- SendCounter (для предотвращения повторного использования nonce!)
- AssignedIP, DNS, MTU, SubnetMask
```

### 7.2. Алгоритм

```
Клиент                                          Сервер
  │                                               │
  │  Keepalive probe (50-160 байт, с padding)        │
  │  (SessionID = сохранённый)                     │
  │  ──────────────────────────────────────────►   │
  │                                               │ Находит сессию по SessionID
  │                                               │ Обновляет адрес клиента
  │  Keepalive response (50-160 байт, с padding)   │
  │  ◄──────────────────────────────────────────   │
  │                                               │
  │  Сессия восстановлена за 0-RTT!                │
```

- Таймаут ожидания ответа: **1 секунда**
- Если ответ не получен → очистить resume-данные, выполнить полный handshake
- `sendCounter` **обязательно** восстанавливается → nonce никогда не повторяется

### 7.3. Когда 0-RTT НЕ работает

- Сервер был перезагружен (все сессии утеряны)
- Сессия истекла по таймауту на сервере (120 сек без активности)
- Клиент получил Disconnect от сервера (resume-данные очищаются)

---

## 8. Поведение при перезагрузке сервера

### 8.1. Graceful shutdown (SIGTERM/SIGINT)

```
Сервер                                          Клиент
  │                                               │
  │  PacketDisconnect (0x30) → всем клиентам       │
  │  ──────────────────────────────────────────►   │
  │                                               │ Получен Disconnect:
  │  Сервер завершает работу                       │ - Очистить resume-данные
  │                                               │ - Закрыть соединение
  │                                               │ - Запустить reconnect
  │  ...сервер перезагружается...                   │ - Backoff: 1с → 2с → ...
  │                                               │
  │  Сервер запущен                                │
  │                                               │ - Полный handshake (0-RTT невозможен)
  │  ◄─── HandshakeInit ──────────────────────────│
  │  ──── HandshakeResp ──────────────────────────►│
  │                                               │ Туннель восстановлен
```

### 8.2. Аварийная остановка (kill -9, сбой питания)

```
Сервер                                          Клиент
  │                                               │
  │  Сервер внезапно недоступен                     │ Keepalive отправляются, ответа нет
  │                                               │
  │  ...ожидание...                                │ 60 сек без данных от сервера
  │                                               │ → Dead-peer detection
  │                                               │ → Закрыть соединение → reconnect
  │                                               │
  │  Сервер запущен                                │ - 0-RTT resume (если < 120с)
  │                                               │ - Или полный handshake
```

> **Разница**: при graceful shutdown клиент начинает переподключение мгновенно (получил Disconnect), при аварийной — через ~15-30 секунд (active probe за ~15с, passive dead-peer detection за ~30с).

---

## 9. Обработка ошибок

### 9.1. Ошибки handshake

| Ошибка | Причина | Действие клиента |
|--------|---------|-----------------|
| Таймаут (нет ответа) | Сервер недоступен / PSK не подходит / неверный логин | Повторить с нулевым PSK (fallback) |
| Ошибка расшифровки Resp | Повреждение данных / несовместимость ключей | Повторить handshake |
| HMAC не совпадает | Повреждение данных | Отбросить пакет |

> **Примечание:** сервер не отправляет Error-пакеты ((удалены для защиты от DPI). Любая ошибка выглядит как таймаут для клиента.

### 9.2. Ошибки передачи данных

| Ошибка | Действие |
|--------|----------|
| UDP Read error | Запустить auto-reconnect |
| UDP Write error | Залогировать, продолжить (не выходить из цикла!) |
| Decrypt error | Залогировать, пропустить пакет |
| TUN Write error | Залогировать, пропустить пакет |
| TUN Read error | Завершить цикл отправки (если не stopped) |

### 9.3. Принцип обработки

- **UDP — ненадёжный транспорт**: потеря пакетов — норма, не ошибка
- **Ошибки записи**: не критичны, не прерывают работу
- **Ошибки чтения (UDP)**: критичны → переподключение
- **Сервер молчит при любой ошибке**: не отправляет Error-пакеты, просто игнорирует (молчаливый drop)

---

## 10. Шифрование данных (Data-пакеты)

### 10.1. Counter-Nonce схема

Data-пакеты используют **counter-nonce** вместо случайного nonce:

```
nonce_prefix = HMAC-SHA256(sendKey, "nova-nonce-prefix")[:4]   // 4 байта
counter      = atomic_increment()                               // uint64
wire_counter = uint32(counter)                                  // на wire: 4 байта
nonce        = nonce_prefix [4 байта] + BigEndian_uint64(wire_counter) [8 байт] = 12 байт
```

### 10.2. Отправка (шифрование)

```
plaintext  = IP-пакет из TUN
counter    = sendCounter.increment()
wireCtr    = uint32(counter)
nonce      = send_nonce_prefix + BigEndian_uint64(wireCtr)

# Padding: выравнивание + случайная добавка (см. 10.4)
padLen     = computeDataPadLen(len(plaintext))
paddedData = plaintext + zeros(padLen) + byte(padLen)
ciphertext = ChaCha20_XOR(sendKey, nonce, paddedData)  // plain ChaCha20, без auth tag!

# Сборка пакета
wireBytes  = QUIC_Header(5) + SessionID(4) + 0x10(1) + wireCtr(4) + ciphertext

# Обфускация заголовка (XOR-маска из PSK)
ObfuscateHeader(wireBytes[5:], headerMask, isData=true)  // SID + Type + Counter

udp.send(wireBytes)
```

### 10.3. Приём (расшифровка)

```
пропустить QUIC Short Header (5 байт) → raw

# Деобфускация заголовка (XOR-маска из PSK)
DeobfuscateHeader(raw, headerMask, isData=true)  // SID + Type + Counter

sessionID  = BigEndian_uint32(raw[0:4])
type       = raw[4]    // 0x10
counter    = BigEndian_uint32(raw[5:9])
ciphertext = raw[9:]
nonce      = recv_nonce_prefix + BigEndian_uint64(counter)
paddedData = ChaCha20_XOR(recvKey, nonce, ciphertext)

# Снятие padding: последний расшифрованный байт = padLen
padLen     = paddedData[len(paddedData) - 1]
plaintext  = paddedData[:len(paddedData) - 1 - padLen]
tun.write(plaintext)
```

> **Важно**: Data-пакеты используют **plain ChaCha20 XOR** без Poly1305 и без auth tag. Padding (нули) после XOR с keystream выглядит как случайные данные.

### 10.4. Data Padding

Каждый data-пакет дополняется padding для маскировки размера:

```
computeDataPadLen(plaintextLen):
    minPadded    = plaintextLen + 1           // +1 для байта padLen
    alignedTarget = ceil(minPadded / 64) * 64  // выравнивание до 64 байт
    padLen       = alignedTarget - minPadded
    padLen      += random(0, 32)               // случайная добавка 0-32 байт
    если padLen > 255: padLen = 255
    вернуть padLen
```

**Формат padded данных:**
```
| plaintext | zeros(padLen) | byte(padLen) |
```

- Нули после ChaCha20 XOR становятся случайными байтами (raw keystream)
- Последний байт plaintext = длина padding → получатель знает, сколько отрезать
- Минимальный IP-пакет после снятия padding ≥ 20 байт (валидация)

---

## 11. Типы пакетов (сводка)

| Код | Тип | Направление | Размер | Описание |
|-----|-----|-------------|--------|----------|
| `0x01` | HandshakeInit | Клиент → Сервер | переменный | Начало рукопожатия |
| `0x02` | HandshakeResp | Сервер → Клиент | переменный | Параметры сессии |
| `0x03` | HandshakeComplete | Клиент → Сервер | переменный | Подтверждение (fire-and-forget) |
| `0x10` | Data | Двунаправленный | 14 + padded payload | Зашифрованный IP-пакет (с padding) |
| `0x20` | Keepalive | Двунаправленный | 50-160 байт | Поддержание сессии (с random padding) |
| `0x30` | Disconnect | Двунаправленный | 50-160 байт | Завершение/остановка (с random padding) |

> Тип `0xF0` (Error) удалён. Сервер использует молчаливый drop при ошибках.

### Формат на wire

Все пакеты обёрнуты в QUIC Short Header (5 байт). Поля SessionID, Type и Counter обфусцированы XOR-маской из PSK (см. ниже).

**Handshake-пакеты** (0x01, 0x02, 0x03):
```
QUIC_Header(5) + [SessionID(4) + Type(1)]_obfuscated + Nonce(12) + Encrypted_Payload(+padding)
```

**Data-пакеты** (0x10):
```
QUIC_Header(5) + [SessionID(4) + Type(1) + Counter(4)]_obfuscated + ChaCha20_XOR(padded_data)
```

**Keepalive/Disconnect** (0x20, 0x30):
```
QUIC_Header(5) + [SessionID(4) + Type(1)]_obfuscated + RandomPadding(40-150)
```

### Обфускация заголовков (XOR Header Mask)

Для сокрытия метаданных (SessionID, PacketType, Counter) от DPI все пакеты используют XOR-обфускацию заголовка:

```
headerMask = HMAC-SHA256(PSK, "nova-header-mask")[:9]   // 9 байт, вычисляется ОДИН раз

// Обфускация (отправка) и деобфускация (приём) — одинаковая операция (XOR)
ObfuscateHeader(buf_after_quic, headerMask, isData):
    buf[0:4] ^= headerMask[0:4]   // SessionID (4 байта) — всегда
    buf[4]   ^= headerMask[4]     // PacketType (1 байт) — всегда
    если isData:
        buf[5:9] ^= headerMask[5:9]   // Counter (4 байта) — только data-пакеты
```

- При **bootstrap** (нулевой PSK) используется маска из нулевого PSK
- Сервер пробует обе маски (PSK + нулевой PSK) для поддержки bootstrap

---

## 12. Сессионные ключи

### 12.1. Вывод ключей

```
HKDF-SHA256(
    IKM    = sharedSecret,     // 32 байта от ECDH
    salt   = PSK,              // 32 байта (или нулевой при bootstrap)
    info   = "novavpn-session-keys-v1",
    length = 96
) → key1(32) + key2(32) + key3(32)
```

### 12.2. Зеркальное распределение

| Ключ | Сервер | Клиент |
|------|--------|--------|
| key1 (байты 0–31) | SendKey | **RecvKey** |
| key2 (байты 32–63) | RecvKey | **SendKey** |
| key3 (байты 64–95) | HMACKey | HMACKey |

> **Внимание**: SendKey сервера = RecvKey клиента и наоборот!

---

## 13. Сервер: обработка пакетов от клиента

Для понимания, как сервер реагирует на разные действия клиента:

### 13.1. HandshakeInit (0x01)

```
1. Проверить timestamp (±30 сек от текущего времени)
2. Проверить HMAC:
   - Сначала с настоящим PSK
   - Если не подошёл — с нулевым PSK (bootstrap)
   - Если ни один не подошёл — молча игнорировать
3. Расшифровать credentials (email + пароль)
4. Аутентифицировать пользователя
5. Если ошибка → молчаливый drop (без Error-пакета)
6. Создать сессию, выделить VPN IP
7. ECDH → вывести сессионные ключи
8. Отправить HandshakeResp
9. Сессия сразу переходит в Active (1-RTT)
```

### 13.2. Data (0x10) — inline обработка

```
1. Найти сессию по SessionID
2. Если сессия не найдена или не Active → игнорировать
3. Расшифровать payload (counter-nonce + ChaCha20)
4. Обновить lastActivity сессии
5. Записать plaintext в TUN
```

### 13.3. Keepalive (0x20)

```
1. Найти сессию по SessionID
2. Обновить lastActivity
3. Если адрес клиента изменился → address migration
4. Отправить keepalive-ответ (50-160 байт, с random padding и обфускацией)
```

### 13.4. Disconnect (0x30)

```
1. Найти сессию по SessionID
2. Обновить lastActivity
3. НЕ удалять сессию (сохранить для 0-RTT resume)
4. Сессия истечёт по таймауту (120 сек)
```

### 13.5. Очистка сессий

```
каждые 30 секунд:
    для каждой сессии:
        если (сейчас - lastActivity) > sessionTimeout (120 сек):
            удалить сессию
            освободить VPN IP
            обнулить ключи
```

---

## 14. Рекомендации для реализации нового клиента

### 14.1. Минимальные зависимости

| Библиотека | Назначение |
|-----------|-----------|
| Curve25519 | ECDH обмен ключами |
| ChaCha20-Poly1305 | AEAD шифрование (handshake) |
| ChaCha20 (plain) | XOR шифрование (данные) |
| HKDF-SHA256 | Вывод сессионных ключей |
| HMAC-SHA256 | Целостность при handshake, nonce prefix |
| TUN driver | Платформенный сетевой интерфейс |
| UDP socket | Транспорт |

### 14.2. TUN-адаптер по платформам

| Платформа | API | Примечания |
|-----------|-----|-----------|
| Windows | WinTUN (`wintun.dll`) | Без установки драйверов |
| Linux | `/dev/net/tun` + `ioctl` | Требует `CAP_NET_ADMIN` |
| macOS | `utun` через `sys/socket` | Стандартный API |
| Android | `VpnService.Builder` | Android VPN API |
| iOS | `NEPacketTunnelProvider` | Network Extension |

### 14.3. Маршрутизация (full tunnel)

**Windows/Linux/macOS** — split routes:
```
1. route add <serverIP>/32 via <physicalGateway>      # прямой путь к серверу
2. route add 0.0.0.0/1 via <vpnGateway>               # первая половина интернета
3. route add 128.0.0.0/1 via <vpnGateway>             # вторая половина интернета
```

Где `vpnGateway` — первый IP подсети (напр. `10.8.0.1` для `10.8.0.0/16`).

**Android** — VPN API:
```
VpnService.Builder()
    .addAddress(assignedIP, subnetMask)
    .addRoute("0.0.0.0", 0)                    // весь трафик через VPN
    .addDisallowedApplication(packageName)      // исключить себя → предотвратить routing loop
    .addDnsServer(dns1)
    .addDnsServer(dns2)
    .setMtu(mtu)
    .establish()

// UDP-сокет к серверу должен быть защищён через protect():
protect(socket.fileDescriptor)                  // исключить из VPN-маршрутизации
```

> **Важно**: на всех платформах UDP-сокет к VPN-серверу должен быть привязан к **физическому** интерфейсу (Windows: bind к адресу шлюза; Android: `protect()` + `addDisallowedApplication()`), иначе возникнет петля маршрутизации.

### 14.4. Минимальная конфигурация от пользователя

| Параметр | Обязательный | Описание |
|----------|-------------|----------|
| server_addr | ✅ | host:port (UDP) |
| email | ✅ | Логин |
| password | ✅ | Пароль |
| psk | ❌ | Получается автоматически при первом подключении |

### 14.5. Потоки/горутины

Клиент должен запустить минимум 3 параллельных потока:

1. **UDP Reader**: `udp.Read()` → расшифровка → `tun.Write()`
2. **TUN Reader**: `tun.Read()` → шифрование → `udp.Write()`
3. **Keepalive**: каждые 10-20 сек (рандомизированный, crypto/rand) отправка keepalive
4. **Health Monitor**: пассивный мониторинг здоровья (3-7 сек, dead-peer detection)

Дополнительно рекомендуется:
5. **Reconnect**: автоматическое переподключение при потере связи

### 14.6. Чек-лист реализации

- [ ] Создание UDP-сокета к серверу
- [ ] Вычисление headerMask = `HMAC-SHA256(PSK, "nova-header-mask")[:9]`
- [ ] Handshake с PSK bootstrap (fallback на нулевой PSK)
- [ ] Вывод сессионных ключей (HKDF, зеркальные ключи)
- [ ] Создание TUN-адаптера
- [ ] Настройка IP, DNS, маршрутов
- [ ] Цикл приёма: UDP → деобфускация заголовка → ChaCha20 decrypt → снятие padding → TUN
- [ ] Цикл отправки: TUN → padding → ChaCha20 encrypt → обфускация заголовка → UDP
- [ ] QUIC Short Header для всех исходящих пакетов
- [ ] XOR-обфускация/деобфускация заголовков всех пакетов
- [ ] Random padding: keepalive/disconnect (40-150 байт), handshake (100-400 байт), data (выравнивание до 64)
- [ ] Keepalive каждые 10-20 сек (50-160 байт, рандомизированный интервал)
- [ ] Dead-peer detection (active probe 15с + passive 30с — `healthLostThreshold`)
- [ ] Обработка Disconnect от сервера
- [ ] Auto-reconnect с экспоненциальным backoff
- [ ] 0-RTT session resume
- [ ] Отправка Disconnect при отключении
- [ ] Корректная остановка всех потоков

---

## 15. Известные особенности

1. **SessionID и PacketType обфусцированы** XOR-маской (`HMAC-SHA256(PSK, "nova-header-mask")[:9]`) — не видны DPI, но восстановимы сервером с O(1) затратами
2. **Data-пакеты без аутентификации** — plain ChaCha20 XOR без Poly1305 (trade-off: производительность)
3. **Сервер молчит при неверном HMAC** — не отправляет ошибку (анти-сканирование)
4. **Counter wrap-around** — uint32 на wire (~4.3 млрд пакетов, ~11 часов при 100k pkt/s)
5. **0-RTT resume ключи в памяти** — не защищены дополнительно
6. **UDP без гарантии доставки** — потеря handshake-пакетов обрабатывается таймаутами на клиенте
