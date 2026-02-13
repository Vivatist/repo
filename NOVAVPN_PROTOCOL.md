# NovaVPN Protocol Specification v2

> Версия документа: 2.0  
> Назначение: спецификация для создания клиентов на любой платформе

---

## 1. Обзор

NovaVPN — собственный VPN-протокол поверх **UDP** с маскировкой под TLS 1.2 (stealth).

**Ключевые характеристики:**
- Транспорт: UDP
- Шифрование: ChaCha20-Poly1305 (AEAD)
- Обмен ключами: ECDH Curve25519 (ephemeral)
- Аутентификация: email + пароль (Argon2id на сервере)
- Маскировка: пакеты обёрнуты в TLS 1.2 Application Data Record Header (обход DPI)
- PSK: автоматически получается при первом подключении (bootstrap)

**Сервер по умолчанию:** `212.118.54.76:443` (UDP), systemd-сервис `novavpn`.

---

## 2. Формат пакета (Wire Format)

Каждый пакет оборачивается в TLS Record Header для имитации HTTPS-трафика.

### 2.1. Общий формат

```
┌─────────────────────────────┬───────────┬──────┬───────┬───────────────────┐
│    TLS Record Header (5B)   │ SessionID │ Type │ Nonce │ Encrypted Payload │
│ 0x17 0x03 0x03 [len: 2B]   │    4B     │  1B  │  12B  │     variable      │
└─────────────────────────────┴───────────┴──────┴───────┴───────────────────┘
```

### 2.2. TLS Record Header (5 байт)

| Смещение | Размер | Значение | Описание |
|----------|--------|----------|----------|
| 0 | 1 | `0x17` | Content Type = Application Data |
| 1 | 1 | `0x03` | TLS Major Version |
| 2 | 1 | `0x03` | TLS Minor Version (1.2) |
| 3-4 | 2 | Big-Endian uint16 | Длина данных **после** этого заголовка |

### 2.3. Открытые поля (после TLS Header)

| Смещение (от начала данных) | Размер | Описание |
|-----------------------------|--------|----------|
| 0-3 | 4 | **SessionID** — идентификатор сессии (Big-Endian uint32). `0` для HandshakeInit. |
| 4 | 1 | **Type** — тип пакета (см. ниже) |
| 5-16 | 12 | **Nonce** — случайный nonce для ChaCha20-Poly1305 |
| 17+ | var | **Payload** — зашифрованные данные (или открытый payload для Handshake) |

### 2.4. Типы пакетов

| Код | Имя | Направление | Описание |
|-----|-----|-------------|----------|
| `0x01` | HandshakeInit | Клиент → Сервер | Инициация рукопожатия |
| `0x02` | HandshakeResp | Сервер → Клиент | Ответ с параметрами сессии |
| `0x03` | HandshakeComplete | Клиент → Сервер | Подтверждение завершения |
| `0x10` | Data | Двунаправленный | Зашифрованный IP-пакет |
| `0x20` | Keepalive | Двунаправленный | Поддержание сессии |
| `0x30` | Disconnect | Двунаправленный | Завершение сессии |
| `0xF0` | Error | Сервер → Клиент | Ошибка (auth_failed и т.д.) |

### 2.5. Константы

| Константа | Значение | Формула |
|-----------|----------|---------|
| TLSHeaderSize | 5 | type(1) + version(2) + length(2) |
| SessionIDSize | 4 | — |
| PacketTypeSize | 1 | — |
| NonceSize | 12 | ChaCha20-Poly1305 стандарт |
| AuthTagSize | 16 | ChaCha20-Poly1305 стандарт |
| HeaderSize | 22 | TLS(5) + SessionID(4) + Type(1) + Nonce(12) |
| TotalOverhead | 38 | TLS(5) + SessionID(4) + Type(1) + Nonce(12) + AuthTag(16) |

---

## 3. Криптография

### 3.1. Алгоритмы

| Операция | Алгоритм | Детали |
|----------|----------|--------|
| Обмен ключами | ECDH Curve25519 | Ephemeral ключевые пары на каждую сессию |
| Вывод ключей | HKDF-SHA256 | salt=PSK, info=`"novavpn-session-keys-v1"` |
| Шифрование | ChaCha20-Poly1305 (AEAD) | 12B random nonce, 16B auth tag |
| Целостность | HMAC-SHA256 | Проверка при handshake |
| Пароли (сервер) | Argon2id | time=3, memory=64MB, threads=4, keyLen=32 |

### 3.2. Сессионные ключи

HKDF из `sharedSecret` (ECDH) с `psk` как salt, выводит 96 байт (3 × 32):

```
HKDF-SHA256(
    IKM    = sharedSecret,     // 32 байта от ECDH
    salt   = PSK,              // 32 байта (или нулевой при bootstrap)
    info   = "novavpn-session-keys-v1",
    length = 96
) → key1(32) + key2(32) + key3(32)
```

| Ключ | Сервер | Клиент |
|------|--------|--------|
| key1 (байты 0-31) | SendKey | RecvKey |
| key2 (байты 32-63) | RecvKey | SendKey |
| key3 (байты 64-95) | HMACKey | HMACKey |

> **Важно**: сервер и клиент используют **зеркальные** ключи — SendKey сервера = RecvKey клиента и наоборот.

### 3.3. PSK (Pre-Shared Key)

- 32 байта, хранится в hex (64 символа)
- Генерируется на сервере при первом развёртывании
- **Bootstrap-режим**: клиент без PSK использует нулевой ключ (`[32]byte{}`)
- При bootstrap сервер передаёт настоящий PSK в HandshakeResp
- Клиент сохраняет полученный PSK и использует его для последующих подключений

---

## 4. Рукопожатие (3-way Handshake)

### 4.1. Общая схема

```
Клиент                                          Сервер
  │                                               │
  │  1. HandshakeInit                              │
  │  (ClientPubKey + EncCreds + HMAC)              │
  │  ──────────────────────────────────────────►   │
  │                                               │ Проверка HMAC (PSK или zeroPSK)
  │                                               │ Расшифровка credentials
  │                                               │ Аутентификация email+пароль
  │                                               │ Создание сессии, выделение VPN IP
  │                                               │ ECDH → sessionKeys
  │  2. HandshakeResp                              │
  │  (ServerPubKey + Enc(сессионные параметры))    │
  │  ◄──────────────────────────────────────────   │
  │ ECDH → sessionKeys                            │
  │ Расшифровка параметров                        │
  │ Сохранение SessionID, VPN IP, DNS, MTU        │
  │ [Сохранение PSK если bootstrap]               │
  │                                               │
  │  3. HandshakeComplete                          │
  │  (Enc(ConfirmHMAC))                            │
  │  ──────────────────────────────────────────►   │
  │                                               │ Проверка HMAC → сессия Active
  │                                               │
  │  ═══════ Туннель установлен ═══════           │
```

### 4.2. Шаг 1: HandshakeInit (Клиент → Сервер)

**Тип пакета**: `0x01`  
**SessionID**: `0`  
**Nonce**: нулевой (не используется для шифрования)  
**Payload**: открытый (не зашифрован), защищён HMAC

#### Формат Payload

```
┌──────────────────┬────────────┬──────────┬────────────────────────┬──────────┐
│ ClientPubKey     │ Timestamp  │ CredsLen │ EncryptedCredentials   │ HMAC     │
│     32B          │    8B      │   2B     │      variable          │  32B     │
└──────────────────┴────────────┴──────────┴────────────────────────┴──────────┘
```

| Поле | Размер | Формат | Описание |
|------|--------|--------|----------|
| ClientPubKey | 32 | raw bytes | Ephemeral Curve25519 public key клиента |
| Timestamp | 8 | Big-Endian uint64 | Unix time в секундах. Сервер допускает ±30 сек. |
| CredsLen | 2 | Big-Endian uint16 | Длина EncryptedCredentials |
| EncryptedCredentials | variable | см. ниже | Зашифрованные email + пароль |
| HMAC | 32 | raw bytes | HMAC-SHA256(PSK, ClientPubKey + Timestamp + EncryptedCredentials) |

#### Формат EncryptedCredentials

```
┌──────────┬───────────────────────────────────────┐
│ Nonce    │ ChaCha20-Poly1305(PSK, Credentials)   │
│  12B     │    Ciphertext + AuthTag(16B)           │
└──────────┴───────────────────────────────────────┘
```

Plaintext Credentials:
```
┌────────────┬─────────┬────────────┬──────────┐
│ EmailLen   │ Email   │ PassLen    │ Password │
│ 2B (BE)    │ var     │ 2B (BE)    │ var      │
└────────────┴─────────┴────────────┴──────────┘
```

#### Алгоритм формирования (клиент)

```
1. clientKP = Curve25519.GenerateKeyPair()
2. credsPlaintext = MarshalCredentials(email, password)
3. credsNonce = random(12)
4. credsCiphertext = ChaCha20Poly1305.Seal(PSK, credsNonce, credsPlaintext, nil)
5. encCreds = credsNonce + credsCiphertext
6. timestamp = time.Now().Unix()
7. hmacData = clientKP.PublicKey(32) + BigEndian_uint64(timestamp) + encCreds
8. hmac = HMAC-SHA256(PSK, hmacData)
9. payload = clientKP.PublicKey + BigEndian_uint64(timestamp) + BigEndian_uint16(len(encCreds)) + encCreds + hmac
```

> **PSK**: если клиент не имеет PSK (первое подключение), использовать `[32]byte{0x00...}` (нулевой ключ).

#### Обработка на сервере

1. Разобрать payload → извлечь ClientPubKey, Timestamp, EncryptedCredentials, HMAC
2. Проверить Timestamp (±30 сек от текущего времени)
3. Построить hmacData = ClientPubKey + BigEndian_uint64(Timestamp) + EncryptedCredentials
4. Попробовать `VerifyHMAC(serverPSK, hmacData, clientHMAC)`
5. Если не совпало — попробовать `VerifyHMAC(zeroPSK, hmacData, clientHMAC)` (bootstrap-режим)
6. Если ни один HMAC не подошёл — отбросить пакет **молча**
7. Определить `activePSK` (серверный PSK или нулевой — какой подошёл)
8. Расшифровать credentials с `activePSK`
9. Аутентифицировать email + пароль
10. При ошибке аутентификации — отправить пакет Error (`auth_failed`)

### 4.3. Шаг 2: HandshakeResp (Сервер → Клиент)

**Тип пакета**: `0x02`  
**SessionID**: назначенный сервером  
**Nonce**: случайный (используется для шифрования)

#### Формат Payload

```
┌──────────────────────────────┬──────────────────────────────────────────────────┐
│ ServerPubKey (32B, открытый) │ Encrypted(SendKey, Nonce, HandshakeRespData)     │
└──────────────────────────────┴──────────────────────────────────────────────────┘
```

> **ServerPublicKey** передаётся **открыто** — клиенту нужен он для ECDH **до** расшифровки.

#### HandshakeRespData (plaintext перед шифрованием)

```
┌──────────────┬───────────┬────────────┬────────┬──────┬──────┬─────┬────────────┬────────┬──────────┐
│ ServerPubKey │ SessionID │ AssignedIP │ Subnet │ DNS1 │ DNS2 │ MTU │ ServerHMAC │ HasPSK │ [PSK]    │
│     32B      │    4B     │   4B (v4)  │  1B    │ 4B   │ 4B   │ 2B  │    32B     │  1B    │ 0 or 32B │
└──────────────┴───────────┴────────────┴────────┴──────┴──────┴─────┴────────────┴────────┴──────────┘
 Байты: [0:32]   [32:36]     [36:40]     [40]   [41:45] [45:49] [49:51] [51:83]    [83]    [84:116]
```

| Поле | Смещение | Размер | Формат | Описание |
|------|----------|--------|--------|----------|
| ServerPubKey | 0 | 32 | raw | Ephemeral Curve25519 public key сервера |
| SessionID | 32 | 4 | BE uint32 | Назначенный ID сессии |
| AssignedIP | 36 | 4 | IPv4 bytes | VPN IP-адрес клиента (напр. 10.8.0.2) |
| SubnetMask | 40 | 1 | uint8 | Маска подсети (CIDR, напр. 24) |
| DNS1 | 41 | 4 | IPv4 bytes | Первый DNS-сервер |
| DNS2 | 45 | 4 | IPv4 bytes | Второй DNS-сервер |
| MTU | 49 | 2 | BE uint16 | MTU туннеля (напр. 1400) |
| ServerHMAC | 51 | 32 | raw | HMAC-SHA256(HMACKey, respData[:51]) |
| HasPSK | 83 | 1 | 0 или 1 | Флаг наличия PSK |
| PSK | 84 | 32 | raw | Настоящий PSK сервера (только при bootstrap) |

**Размер**: 84 байта без PSK, 116 байт с PSK.

#### Шифрование ответа (сервер)

```
1. serverKP = Curve25519.GenerateKeyPair()
2. sharedSecret = ECDH(serverKP.PrivateKey, clientPubKey)
3. sessionKeys = HKDF(sharedSecret, activePSK, "novavpn-session-keys-v1")
4. Заполнить HandshakeRespData
5. serverHMAC = HMAC-SHA256(sessionKeys.HMACKey, respData[:51])
6. Если bootstrap: HasPSK=1, PSK=serverPSK
7. respBytes = Marshal(HandshakeRespData)
8. nonce, encrypted = ChaCha20Poly1305.Seal(sessionKeys.SendKey, respBytes, nil)
9. payload = serverKP.PublicKey(32) + encrypted
```

#### Расшифровка ответа (клиент)

```
1. serverPubKey = payload[:32]
2. sharedSecret = ECDH(clientKP.PrivateKey, serverPubKey)
3. sessionKeys = HKDF(sharedSecret, PSK, "novavpn-session-keys-v1")  // тот же PSK что в Init
4. respPlaintext = ChaCha20Poly1305.Open(sessionKeys.RecvKey, nonce, payload[32:], nil)
5. Разобрать HandshakeRespData
6. Проверить ServerHMAC = HMAC-SHA256(HMACKey, respData[:51])
7. Если HasPSK == 1 и len(respPlaintext) >= 116: сохранить PSK для будущих подключений
8. Сохранить SessionID, AssignedIP, DNS, MTU
```

### 4.4. Шаг 3: HandshakeComplete (Клиент → Сервер)

**Тип пакета**: `0x03`  
**SessionID**: полученный из HandshakeResp  
**Nonce**: случайный

#### Формат (plaintext перед шифрованием)

```
┌────────────────┐
│ ConfirmHMAC    │
│     32B        │
└────────────────┘
```

```
confirmData = "novavpn-confirm-{SessionID}"    // строка, напр. "novavpn-confirm-42"
ConfirmHMAC = HMAC-SHA256(sessionKeys.HMACKey, confirmData)
```

Шифруется `sessionKeys.SendKey` (клиентский), отправляется как обычный пакет.

---

## 5. Bootstrap PSK (автоматическое получение ключа)

### 5.1. Проблема

PSK — 32 байта (64 hex символа), вводить вручную неудобно (особенно на устройствах типа Smart TV).

### 5.2. Решение

1. При **первом подключении** клиент не имеет PSK — использует нулевой (`[32]byte{}`)
2. Сервер принимает HMAC с нулевым PSK (bootstrap-режим), проверяет email+пароль
3. При успешной аутентификации сервер включает в HandshakeResp **настоящий PSK** (`HasPSK=1`)
4. Клиент сохраняет PSK в конфиг для последующих подключений
5. Все дальнейшие подключения используют настоящий PSK

### 5.3. Fallback при смене PSK на сервере

Если PSK на сервере сменился, а у клиента сохранён старый:

1. Клиент отправляет HandshakeInit со старым PSK
2. Сервер отклоняет (HMAC не совпадает) — **молча** (без Error-пакета)
3. Клиент ждёт 2 секунды → таймаут
4. Клиент автоматически повторяет с нулевым PSK (bootstrap)
5. Сервер принимает, передаёт новый PSK

### 5.4. Алгоритм клиента (полный)

```
hasStoredPSK = (config.PSK != "" и не нулевой)

if hasStoredPSK:
    // Быстрая попытка с сохранённым PSK (таймаут 2 сек)
    err = performHandshake(email, password, timeout=2s)
    if err:
        log("Сохранённый PSK не подошёл, пробуем bootstrap")
        PSK = [32]byte{0x00...}
        err = performHandshake(email, password, timeout=10s)
        if err: return error
        // Bootstrap удался — PSK автоматически сохранён через callback
else:
    // Bootstrap-режим напрямую (таймаут 10 сек)
    PSK = [32]byte{0x00...}
    err = performHandshake(email, password, timeout=10s)
    if err: return error
```

### 5.5. Безопасность

PSK **не является дополнительным фактором** аутентификации. Реальная аутентификация — email+пароль. PSK используется как salt в HKDF и оптимизирует повторные подключения.

---

## 6. Передача данных

После завершения handshake обе стороны обмениваются Data-пакетами.

### 6.1. Шифрование Data-пакета (отправка)

```
1. plaintext = IP-пакет из TUN-адаптера
2. nonce = random(12)
3. ciphertext = ChaCha20Poly1305.Seal(sessionKeys.SendKey, nonce, plaintext, AAD=nil)
4. wireBytes = TLSHeader(5) + SessionID(4) + Type=0x10(1) + nonce(12) + ciphertext
5. Отправить wireBytes по UDP на сервер
```

### 6.2. Расшифровка Data-пакета (приём)

```
1. Удалить TLS заголовок (5B) → raw
2. sessionID = BigEndian_uint32(raw[0:4])
3. type = raw[4]
4. nonce = raw[5:17]
5. ciphertext = raw[17:]
6. plaintext = ChaCha20Poly1305.Open(sessionKeys.RecvKey, nonce, ciphertext, AAD=nil)
7. Записать plaintext (IP-пакет) в TUN
```

> **AAD**: в текущей реализации = `nil` (не используется). Это упрощает реализацию на разных платформах.

### 6.3. Keepalive

- Тип пакета: `0x20`
- Payload: пустой
- Nonce: нулевой
- Шифрование: нет (чистый пакет Header + пустой payload)
- Сессия истекает на сервере через **120 сек** без активности

**Интервалы:**

| Сторона | Интервал | Примечание |
|---------|----------|------------|
| Клиент → Сервер | каждые **15 секунд** | Фиксированный интервал |
| Сервер → Клиент | **25 ± 7 секунд** | Рандомизированный (18-32 сек) для снижения DPI fingerprinting |

> **DPI anti-fingerprinting**: сервер намеренно рандомизирует интервал keepalive при каждой отправке, чтобы трафик не имел детерминированного паттерна.

### 6.4. Disconnect

- Тип пакета: `0x30`
- Payload: пустой
- Отправляется клиентом при отключении

---

## 7. Сетевая настройка (клиент)

### 7.1. TUN-адаптер

Создание TUN-интерфейса — платформенно-зависимая часть:

| Платформа | API | Примечания |
|-----------|-----|-----------|
| Windows | WinTUN (`wintun.dll`) | Бинарный DLL, без установки драйверов |
| Linux | `/dev/net/tun` + `ioctl` | Требует `CAP_NET_ADMIN` |
| macOS | `utun` через `sys/socket` | Стандартный macOS API |
| Android | `VpnService.Builder` | Android VPN API |
| iOS | `NEPacketTunnelProvider` | Network Extension framework |

### 7.2. Маршрутизация (full tunnel)

Принцип: **split routes** (0/1 + 128/1) вместо замены default route.

```
1. route add <serverIP>/32 via <physicalGateway> metric 1  # прямой путь к VPN-серверу
2. route add 0.0.0.0/1 via <vpnGateway> metric 3           # первая половина интернета
3. route add 128.0.0.0/1 via <vpnGateway> metric 3         # вторая половина интернета
```

Где:
- `vpnGateway` = первый IP подсети (напр. `10.8.0.1` для `10.8.0.0/24`)
- `physicalGateway` = гейтвей физического адаптера

### 7.3. DNS

Назначить DNS-серверы из HandshakeResp на TUN-интерфейс. На Windows — через `netsh`, на Linux — через `resolvectl`, на macOS — через `scutil`.

### 7.4. UDP-сокет

**Важно**: UDP-сокет должен быть привязан к **физическому** сетевому адаптеру, а не к VPN-интерфейсу. Иначе после настройки маршрутов трафик к серверу пойдёт через туннель → петля.

На Android/iOS: используется `protect()` / routing exclusion для сокета VPN-сервера.

---

## 8. Конфигурация

### 8.1. Сервер — `/etc/novavpn/server.yaml`

```yaml
listen_addr: "0.0.0.0"
listen_port: 443
vpn_subnet: "10.8.0.0/24"
server_vpn_ip: "10.8.0.1"
tun_name: "nova0"
mtu: 1400
dns: ["1.1.1.1", "8.8.8.8"]
pre_shared_key: "<64 hex chars>"
users_file: "/etc/novavpn/users.yaml"
max_clients: 256
keepalive_interval: 25
session_timeout: 120
enable_nat: true
external_interface: "eth0"
log_level: "info"           # debug, info, warn, error
```

### 8.2. Клиент — конфиг-файл (JSON)

```json
{
  "server_addr": "212.118.54.76:443",
  "psk": "",
  "email": "user@example.com",
  "password": "secret",
  "auto_start": false,
  "was_connected": false
}
```

> `psk` — пустая строка при первом подключении. Заполняется автоматически после bootstrap.

### 8.3. Минимально необходимые поля от пользователя

| Параметр | Обязательный | Описание |
|----------|-------------|----------|
| server_addr | ✅ | host:port (UDP) |
| email | ✅ | Логин пользователя |
| password | ✅ | Пароль |
| psk | ❌ | Автоматически получается при первом подключении |

---

## 9. Управление пользователями (сервер)

```bash
novavpn-server -adduser  -email user@example.com -password secret
novavpn-server -deluser  -email user@example.com
novavpn-server -listusers
novavpn-server -passwd   -email user@example.com -password newpass
novavpn-server -disable  -email user@example.com
novavpn-server -enable   -email user@example.com
```

Пароли хранятся: `hex(salt16B):hex(argon2id_hash32B)` в `/etc/novavpn/users.yaml`.

---

## 10. Справочник для реализации клиента

### 10.1. Минимальный набор зависимостей

| Библиотека | Назначение |
|-----------|-----------|
| Curve25519 | ECDH обмен ключами |
| ChaCha20-Poly1305 | AEAD шифрование |
| HKDF-SHA256 | Вывод сессионных ключей |
| HMAC-SHA256 | Целостность при handshake |
| TUN driver | Платформенный сетевой интерфейс |
| UDP socket | Транспорт |

### 10.2. Последовательность действий клиента

```
 1. Загрузить конфиг (server_addr, email, password, psk)
 2. Определить PSK: если пустой → [32]byte{0}, иначе hex_decode(psk)
 3. Создать UDP-сокет к серверу (привязать к физическому интерфейсу!)
 4. Определить hasStoredPSK
 5. Если hasStoredPSK:
      a. performHandshake(psk=сохранённый, timeout=2s)
      b. При ошибке → performHandshake(psk=нулевой, timeout=10s)
    Иначе:
      a. performHandshake(psk=нулевой, timeout=10s)
 6. Если в HandshakeResp получен PSK → сохранить в конфиг
 7. Создать TUN-адаптер (IP = AssignedIP, маска из SubnetMask)
 8. Настроить DNS
 9. Настроить маршруты (split routes)
10. Запустить 3 горутины/потока:
      - UDP → расшифровка → TUN (входящие)
      - TUN → шифрование → UDP (исходящие)
      - Keepalive каждые 25 сек
11. При отключении: отправить Disconnect, удалить маршруты, закрыть TUN
```

### 10.3. Построение пакета (пошагово)

```python
# ===== Отправка =====
def build_packet(pkt_type, session_id, nonce, payload):
    raw = b""
    raw += struct.pack(">I", session_id)    # 4 байта, Big-Endian uint32
    raw += bytes([pkt_type])                # 1 байт
    raw += nonce                            # 12 байт
    raw += payload                          # переменная длина

    tls_header = bytes([0x17, 0x03, 0x03]) + struct.pack(">H", len(raw))
    return tls_header + raw

# ===== Приём =====
def parse_packet(data):
    assert data[0] == 0x17               # TLS Application Data
    tls_len = struct.unpack(">H", data[3:5])[0]
    raw = data[5 : 5 + tls_len]

    session_id = struct.unpack(">I", raw[0:4])[0]
    pkt_type   = raw[4]
    nonce      = raw[5:17]
    payload    = raw[17:]
    return session_id, pkt_type, nonce, payload
```

### 10.4. Пример: полный handshake (псевдокод)

```python
# ═══════════════════════════════════════════════════════
# Шаг 1: HandshakeInit (Клиент → Сервер)
# ═══════════════════════════════════════════════════════
client_priv, client_pub = curve25519_keygen()
timestamp = int(time.time())

# Шифруем credentials
creds = (struct.pack(">H", len(email)) + email.encode() +
         struct.pack(">H", len(password)) + password.encode())

creds_nonce = os.urandom(12)
creds_encrypted = chacha20poly1305_seal(
    key=PSK, nonce=creds_nonce, plaintext=creds, aad=None
)
enc_creds = creds_nonce + creds_encrypted

# HMAC
hmac_data = client_pub + struct.pack(">Q", timestamp) + enc_creds
hmac_val = hmac_sha256(key=PSK, data=hmac_data)

# Payload
payload = (client_pub +
           struct.pack(">Q", timestamp) +
           struct.pack(">H", len(enc_creds)) +
           enc_creds +
           hmac_val)

# Отправка
packet = build_packet(
    pkt_type=0x01,
    session_id=0,
    nonce=bytes(12),      # нулевой nonce
    payload=payload
)
udp_send(packet)

# ═══════════════════════════════════════════════════════
# Шаг 2: Приём HandshakeResp (Сервер → Клиент)
# ═══════════════════════════════════════════════════════
data = udp_recv()
session_id, pkt_type, nonce, payload = parse_packet(data)
assert pkt_type == 0x02

# Первые 32 байта payload — открытый ServerPubKey
server_pub = payload[:32]
encrypted_resp = payload[32:]

# ECDH и вывод сессионных ключей
shared_secret = curve25519_ecdh(client_priv, server_pub)
keys = hkdf_sha256(
    ikm=shared_secret,
    salt=PSK,
    info=b"novavpn-session-keys-v1",
    length=96
)
recv_key  = keys[0:32]    # для клиента key1 = RecvKey
send_key  = keys[32:64]   # для клиента key2 = SendKey
hmac_key  = keys[64:96]   # key3 = HMACKey (одинаковый)

# Расшифровка
resp_data = chacha20poly1305_open(
    key=recv_key, nonce=nonce, ciphertext=encrypted_resp, aad=None
)

# Разбор полей
server_pub2       = resp_data[0:32]       # дублируется
session_id        = struct.unpack(">I", resp_data[32:36])[0]
assigned_ip       = ipv4_from_bytes(resp_data[36:40])   # напр. "10.8.0.2"
subnet_mask       = resp_data[40]                        # напр. 24
dns1              = ipv4_from_bytes(resp_data[41:45])
dns2              = ipv4_from_bytes(resp_data[45:49])
mtu               = struct.unpack(">H", resp_data[49:51])[0]
server_hmac       = resp_data[51:83]
has_psk           = resp_data[83]

# Проверка HMAC
expected_hmac = hmac_sha256(key=hmac_key, data=resp_data[:51])
assert expected_hmac == server_hmac

# Сохранение PSK (если bootstrap)
if has_psk == 1 and len(resp_data) >= 116:
    received_psk = resp_data[84:116]
    save_psk_to_config(received_psk.hex())

# ═══════════════════════════════════════════════════════
# Шаг 3: HandshakeComplete (Клиент → Сервер)
# ═══════════════════════════════════════════════════════
confirm_data = f"novavpn-confirm-{session_id}".encode()
confirm_hmac = hmac_sha256(key=hmac_key, data=confirm_data)

complete_nonce = os.urandom(12)
complete_encrypted = chacha20poly1305_seal(
    key=send_key, nonce=complete_nonce, plaintext=confirm_hmac, aad=None
)

packet = build_packet(
    pkt_type=0x03,
    session_id=session_id,
    nonce=complete_nonce,
    payload=complete_encrypted
)
udp_send(packet)

# ═══════ Туннель установлен ═══════
# Теперь можно пересылать Data-пакеты
```

---

## 11. Структура файлов (эталонная реализация)

### Сервер (Go, Linux)

```
vpn-server/
├── cmd/vpnserver/main.go          # Точка входа, CLI, graceful shutdown
├── config/config.go               # ServerConfig, YAML
├── internal/
│   ├── auth/auth.go               # Argon2id, CRUD пользователей
│   ├── protocol/
│   │   ├── crypto.go              # ECDH, HKDF, ChaCha20-Poly1305, HMAC
│   │   ├── packet.go              # Wire format, marshal/unmarshal
│   │   └── handshake.go           # HandshakeInit/Resp/Complete
│   ├── server/
│   │   ├── server.go              # UDP loop, TUN loop, maintenance
│   │   ├── handler.go             # Обработка пакетов (handshake, data, keepalive)
│   │   ├── session.go             # Session, SessionManager
│   │   └── ippool.go              # Пул VPN IP-адресов
│   └── tun/tun_linux.go           # Linux TUN, NAT, routing
└── go.mod
```

### Клиент (Go, Windows — эталонная реализация, Clean Architecture)

```
vpn-client-windows/
├── cmd/
│   ├── novavpn/main.go                        # GUI точка входа
│   └── novavpn-service/main.go                # Windows Service точка входа
├── internal/
│   ├── domain/                                # Доменные интерфейсы
│   │   ├── crypto/interfaces.go               # Session, KeyExchange
│   │   ├── vpn/interfaces.go                  # Client, ConnectParams, States
│   │   ├── network/interfaces.go              # TunnelDevice, NetworkConfigurator
│   │   ├── ipc/interfaces.go                  # IPCClient, IPCServer
│   │   └── config/interfaces.go               # ConfigManager
│   ├── infrastructure/                        # Реализации
│   │   ├── crypto/session.go                  # ChaCha20Session, Curve25519KeyExchange
│   │   ├── vpn/
│   │   │   ├── client.go                      # NovaVPNClient, UDP/TUN loops
│   │   │   └── handshake/performer.go         # 3-way handshake, PSK bootstrap
│   │   ├── network/
│   │   │   ├── wintun.go                      # WinTUN-адаптер
│   │   │   └── configurator.go                # Маршруты, DNS, интерфейсы
│   │   ├── ipc/
│   │   │   ├── client.go                      # Named Pipe IPC клиент (GUI)
│   │   │   └── server.go                      # Named Pipe IPC сервер (Service)
│   │   └── config/manager.go                  # JSON конфиг менеджер
│   ├── application/vpnservice/service.go      # Бизнес-логика VPN-сервиса
│   ├── gui/app.go                             # Walk GUI
│   ├── ipc/ipc.go                             # IPC протокол (команды/ответы)
│   ├── protocol/protocol.go                   # Wire format (packet, handshake)
│   ├── service/service.go                     # Windows Service handler
│   ├── config/config.go                       # Типы конфигурации
│   └── elevation/elevation.go                 # UAC elevation helper
└── go.mod
```

> **Архитектура**: GUI-процесс (`novavpn.exe`) взаимодействует с Windows Service (`novavpn-service.exe`) через Named Pipe IPC (`\\.\pipe\NovaVPN`). VPN-логика выполняется в контексте сервиса с правами администратора.

---

## 12. Деплой сервера

```bash
# Сборка
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o novavpn-server ./cmd/vpnserver/

# Systemd unit: /etc/systemd/system/novavpn.service
[Unit]
Description=NovaVPN Server
After=network.target

[Service]
ExecStart=/usr/local/bin/novavpn-server -config /etc/novavpn/server.yaml
Restart=always
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

---

## 13. Известные особенности и ограничения

1. **DPI обход**: все пакеты обёрнуты в TLS 1.2 Application Data header. Для DPI трафик выглядит как обычный HTTPS. Порт 443 усиливает маскировку.

2. **Нет Client Hello / Server Hello**: TCP handshake TLS не имитируется (транспорт — UDP). При глубоком анализе DPI может обнаружить отсутствие TLS handshake на TCP.

3. **SessionID открыт**: необходим для маршрутизации пакетов к правильной сессии на сервере до расшифровки.

4. **PacketType открыт**: вынесен из зашифрованной части для маршрутизации на уровне сервера (handshake vs data).

5. **Replay protection**: в текущей реализации отсутствует проверка sequence number для Data-пакетов. Nonce случайный.

6. **UDP**: нет гарантии доставки. При потере пакета handshake — таймаут и retry на уровне клиента.

7. **Bootstrap безопасность**: нулевой PSK позволяет любому с валидными credentials подключиться. Это by design — PSK не является фактором аутентификации.
