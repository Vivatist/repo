# Логика взаимодействия клиента и сервера NovaVPN

> **Назначение**: практическое руководство для разработчиков новых клиентов NovaVPN.  
> Описывает **логику взаимодействия** между клиентом и сервером — жизненный цикл соединения, машину состояний, обработку ошибок и переподключение.  
> Детальную спецификацию формата пакетов и криптографии см. в [NOVAVPN_PROTOCOL.md](NOVAVPN_PROTOCOL.md).

---

## 1. Общая архитектура

```
┌─────────────────────┐         UDP (порт 443)         ┌──────────────────────┐
│     VPN-клиент      │ ◄─────────────────────────────► │     VPN-сервер       │
│                     │    Маскировка под TLS 1.2       │                      │
│  ┌───────────────┐  │                                 │  ┌────────────────┐  │
│  │  UDP-сокет    │──┼── Handshake / Data / Keepalive ─┼──│  UDP-listener  │  │
│  └───────┬───────┘  │                                 │  └────────┬───────┘  │
│          │          │                                 │           │          │
│  ┌───────▼───────┐  │                                 │  ┌────────▼───────┐  │
│  │  TUN-адаптер  │  │         IP-пакеты               │  │ TUN-интерфейс  │  │
│  └───────────────┘  │                                 │  └────────────────┘  │
└─────────────────────┘                                 └──────────────────────┘
```

**Протокол**: собственный, поверх UDP с маскировкой под TLS 1.2 Application Data.  
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
8. Настроить маршруты (split routes: 0/1 + 128/1)
9. Запустить 3 рабочих цикла:
   - Чтение из UDP → расшифровка → запись в TUN
   - Чтение из TUN → шифрование → отправка в UDP
   - Keepalive каждые 15 секунд
10. Состояние → Connected
```

### 3.2. Обмен данными (Connected)

В состоянии Connected работают три параллельных цикла:

**Цикл приёма (UDP → TUN)**:
```
loop:
  data = udp.Read()
  если ошибка чтения:
    запустить reconnect()
    выйти из цикла
  обновить lastRecvTime  // для dead-peer detection
  разобрать пакет:
    если Data (0x10):  расшифровать → записать в TUN
    если Keepalive (0x20): игнорировать (lastRecvTime уже обновлён)
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
каждые 15 секунд:
  если идёт reconnect: пропустить
  
  // Dead-peer detection
  если (сейчас - lastRecvTime) > 45 секунд:
    закрыть conn  // цикл приёма получит ошибку → reconnect
    выйти
  
  отправить keepalive (10 байт)
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
6. Отправить Disconnect-пакет серверу (10 байт)
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

# Сборка и отправка
payload = clientPub + uint64_be(timestamp) + uint16_be(len(encCreds)) + encCreds + hmac
send_packet(type=0x01, sessionID=0, nonce=zeros(12), payload=payload)

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
completeNonce = random(12)
encrypted = chacha20poly1305_seal(sendKey, completeNonce, confirmHMAC)
send_packet(type=0x03, sessionID=sessionID, nonce=completeNonce, payload=encrypted)
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

## 5. Keepalive и обнаружение недоступности

### 5.1. Клиент → Сервер

- **Интервал**: каждые **15 секунд**
- **Формат**: 10 байт (TLS header + SessionID + тип 0x20)
- **Цель**: поддержание NAT-маппинга, подтверждение живости

### 5.2. Сервер → Клиент

- **Интервал**: **25 ± 7 секунд** (рандомизированный, 18–32 сек)
- **Рандомизация**: анти-DPI мера, интервал пересчитывается после каждой отправки
- **Формат**: 10 байт (аналогичный)

### 5.3. Dead-Peer Detection (DPD)

Клиент отслеживает время последнего полученного пакета от сервера (**любого** типа — Data, Keepalive и т.д.):

```
при каждом полученном пакете:
    lastRecvTime = текущее_время

каждые 15 секунд (в keepalive-цикле):
    elapsed = текущее_время - lastRecvTime
    если elapsed > 45 секунд:   // 3 пропущенных keepalive
        логировать "Dead peer detected"
        закрыть UDP-соединение
        → автоматический reconnect
```

**Таймауты:**
| Параметр | Значение | Описание |
|----------|----------|----------|
| Keepalive интервал (клиент) | 15 сек | Фиксированный |
| Keepalive интервал (сервер) | 25±7 сек | Рандомизированный |
| Dead-peer порог | 45 сек | 3 пропущенных keepalive |
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
- Dead-peer detection (45 секунд без данных от сервера)
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

  // Цикл переподключения (до 60 попыток)
  для attempt = 1..60:
    если stopped: → Disconnected, выйти

    ждать backoff_delay  // 1с → 2с → 4с → ... → 30с (макс)

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
      перенастроить сеть если IP изменился

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
  │  Keepalive probe (10 байт)                     │
  │  (SessionID = сохранённый)                     │
  │  ──────────────────────────────────────────►   │
  │                                               │ Находит сессию по SessionID
  │                                               │ Обновляет адрес клиента
  │  Keepalive response (10 байт)                  │
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
  │  ...ожидание...                                │ 45 сек без данных от сервера
  │                                               │ → Dead-peer detection
  │                                               │ → Закрыть соединение → reconnect
  │                                               │
  │  Сервер запущен                                │ - 0-RTT resume (если < 120с)
  │                                               │ - Или полный handshake
```

> **Разница**: при graceful shutdown клиент начинает переподключение мгновенно (получил Disconnect), при аварийной — через ~45 секунд (dead-peer detection).

---

## 9. Обработка ошибок

### 9.1. Ошибки handshake

| Ошибка | Причина | Действие клиента |
|--------|---------|-----------------|
| Таймаут (нет ответа) | Сервер недоступен / PSK не подходит | Повторить с нулевым PSK (fallback) |
| Error-пакет `auth_failed` | Неверный email/пароль | Показать ошибку пользователю, не повторять |
| Ошибка расшифровки Resp | Повреждение данных / несовместимость ключей | Повторить handshake |
| HMAC не совпадает | Повреждение данных | Отбросить пакет |

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
- **Сервер молчит при неверном HMAC**: не отправляет ошибку, просто игнорирует
- **Error-пакет (0xF0)**: отправляется только при ошибке аутентификации (`auth_failed`)

---

## 10. Шифрование данных (Data-пакеты)

### 10.1. Counter-Nonce схема

Data-пакеты используют **counter-nonce** вместо случайного nonce:

```
nonce_prefix = HMAC-SHA256(sendKey, "nova-nonce-prefix")[:4]   // 4 байта
counter      = atomic_increment()                               // uint64
wire_counter = uint32(counter)                                  // на wire: 4 байта
nonce        = nonce_prefix(4) + BigEndian_uint64(wire_counter)(8) = 12 байт
```

### 10.2. Отправка (шифрование)

```
plaintext  = IP-пакет из TUN
counter    = sendCounter.increment()
wireCtr    = uint32(counter)
nonce      = send_nonce_prefix + BigEndian_uint64(wireCtr)
ciphertext = ChaCha20_XOR(sendKey, nonce, plaintext)  // plain ChaCha20, без auth tag!
wireBytes  = TLS_Header(5) + SessionID(4) + 0x10(1) + wireCtr(4) + ciphertext
udp.send(wireBytes)
```

### 10.3. Приём (расшифровка)

```
удалить TLS заголовок (5 байт) → raw
sessionID  = BigEndian_uint32(raw[0:4])
type       = raw[4]    // 0x10
counter    = BigEndian_uint32(raw[5:9])
ciphertext = raw[9:]
nonce      = recv_nonce_prefix + BigEndian_uint64(counter)
plaintext  = ChaCha20_XOR(recvKey, nonce, ciphertext)
tun.write(plaintext)
```

> **Важно**: Data-пакеты используют **plain ChaCha20 XOR** без Poly1305 и без auth tag. Размер ciphertext равен размеру plaintext.

---

## 11. Типы пакетов (сводка)

| Код | Тип | Направление | Размер | Описание |
|-----|-----|-------------|--------|----------|
| `0x01` | HandshakeInit | Клиент → Сервер | переменный | Начало рукопожатия |
| `0x02` | HandshakeResp | Сервер → Клиент | переменный | Параметры сессии |
| `0x03` | HandshakeComplete | Клиент → Сервер | переменный | Подтверждение (fire-and-forget) |
| `0x10` | Data | Двунаправленный | 14 + payload | Зашифрованный IP-пакет |
| `0x20` | Keepalive | Двунаправленный | 10 байт | Поддержание сессии |
| `0x30` | Disconnect | Двунаправленный | 10 байт | Завершение/остановка |
| `0xF0` | Error | Сервер → Клиент | переменный | Ошибка (auth_failed) |

### Формат на wire

**Handshake-пакеты** (0x01, 0x02, 0x03):
```
TLS_Header(5) + SessionID(4) + Type(1) + Nonce(12) + Encrypted_Payload
```

**Data-пакеты** (0x10):
```
TLS_Header(5) + SessionID(4) + Type(1) + Counter(4) + ChaCha20_XOR_data
```

**Keepalive/Disconnect** (0x20, 0x30):
```
TLS_Header(5) + SessionID(4) + Type(1)
```

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
5. Если ошибка → отправить Error (auth_failed)
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
4. Отправить keepalive-ответ (10 байт)
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

```
1. route add <serverIP>/32 via <physicalGateway>      # прямой путь к серверу
2. route add 0.0.0.0/1 via <vpnGateway>               # первая половина интернета
3. route add 128.0.0.0/1 via <vpnGateway>             # вторая половина интернета
```

Где `vpnGateway` — первый IP подсети (напр. `10.8.0.1` для `10.8.0.0/24`).

> **Важно**: UDP-сокет к VPN-серверу должен быть привязан к **физическому** интерфейсу, иначе возникнет петля маршрутизации.

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
3. **Keepalive**: каждые 15 сек отправка keepalive + dead-peer detection

Дополнительно рекомендуется:
4. **Reconnect**: автоматическое переподключение при потере связи

### 14.6. Чек-лист реализации

- [ ] Создание UDP-сокета к серверу
- [ ] Handshake с PSK bootstrap (fallback на нулевой PSK)
- [ ] Вывод сессионных ключей (HKDF, зеркальные ключи)
- [ ] Создание TUN-адаптера
- [ ] Настройка IP, DNS, маршрутов
- [ ] Цикл приёма: UDP → ChaCha20 decrypt → TUN
- [ ] Цикл отправки: TUN → ChaCha20 encrypt → UDP
- [ ] Keepalive каждые 15 сек (10 байт)
- [ ] Dead-peer detection (45 сек без данных от сервера)
- [ ] Обработка Disconnect от сервера
- [ ] Auto-reconnect с экспоненциальным backoff
- [ ] 0-RTT session resume
- [ ] Отправка Disconnect при отключении
- [ ] Корректная остановка всех потоков

---

## 15. Известные особенности

1. **SessionID и PacketType открыты** (не зашифрованы) — необходимы для маршрутизации на сервере
2. **Data-пакеты без аутентификации** — plain ChaCha20 XOR без Poly1305 (trade-off: производительность)
3. **Сервер молчит при неверном HMAC** — не отправляет ошибку (анти-сканирование)
4. **Counter wrap-around** — uint32 на wire (~4 млрд пакетов, ~12 часов при 100k pkt/s)
5. **0-RTT resume ключи в памяти** — не защищены дополнительно
6. **UDP без гарантии доставки** — потеря handshake-пакетов обрабатывается таймаутами на клиенте
