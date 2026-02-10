# NovaVPN — Описание протокола и реализации

## 1. Архитектура

Собственный VPN-протокол поверх **UDP**. Две кодовых базы на Go:

| Компонент | Платформа | Модуль | Путь |
|---|---|---|---|
| Сервер | Linux (Ubuntu 22.04) | `github.com/novavpn/vpn-server` | `c:\Users\andre\repo\vpn-server\` |
| Клиент | Windows | `github.com/novavpn/vpn-client-windows` | `c:\Users\andre\repo\vpn-client-windows\` |

**Развёрнутый сервер:** `212.118.43.43:51820`, systemd-сервис `novavpn`, конфиг `/etc/novavpn/server.yaml`.

**Зависимости:**
- `golang.org/x/crypto` — ChaCha20-Poly1305, Curve25519, HKDF, Argon2id
- `golang.org/x/sys` — системные вызовы (TUN на Linux, Windows API)
- `gopkg.in/yaml.v3` — конфигурация сервера
- `github.com/lxn/walk` + `github.com/lxn/win` — Win32 GUI (клиент)
- `golang.zx2c4.com/wintun` — WinTUN-драйвер (клиент)

---

## 2. Формат пакета

```
┌──────────┬─────────┬──────┬───────────┬────────────┬────────────┬───────┬─────────────────────┐
│ Magic 2B │ Ver 1B  │ Type │ SessionID │ SequenceNo │ PayloadLen │ Nonce │  Encrypted Payload  │
│  0x4E56  │  0x01   │  1B  │    4B     │     4B     │    2B      │ 12B   │     variable        │
└──────────┴─────────┴──────┴───────────┴────────────┴────────────┴───────┴─────────────────────┘
         ←————————— Header: 14 байт ——————————→        ←12B→
```

| Константа | Значение | Описание |
|---|---|---|
| `ProtocolMagic` | `0x4E56` ("NV") | Магические байты |
| `ProtocolVersion` | `0x01` | Версия протокола |
| `HeaderSize` | 14 | Magic(2)+Ver(1)+Type(1)+SessionID(4)+Seq(4)+PayloadLen(2) |
| `NonceSize` | 12 | ChaCha20-Poly1305 nonce |
| `AuthTagSize` | 16 | AEAD authentication tag |
| `TotalOverhead` | 42 | Header(14)+Nonce(12)+AuthTag(16) |

### Типы пакетов

| Код | Имя | Направление |
|---|---|---|
| `0x01` | `HandshakeInit` | Клиент → Сервер |
| `0x02` | `HandshakeResp` | Сервер → Клиент |
| `0x03` | `HandshakeComplete` | Клиент → Сервер |
| `0x10` | `Data` | Двунаправленный |
| `0x20` | `Keepalive` | Двунаправленный |
| `0x30` | `Disconnect` | Двунаправленный |
| `0xF0` | `Error` | Сервер → Клиент |

---

## 3. Криптография

| Операция | Алгоритм | Детали |
|---|---|---|
| Обмен ключами | ECDH Curve25519 | Ephemeral ключевые пары на каждую сессию |
| Вывод ключей | HKDF-SHA256 | salt=PSK, info=`"novavpn-session-keys-v1"` |
| Шифрование | ChaCha20-Poly1305 (AEAD) | 12B nonce (случайный), 16B auth tag |
| Целостность | HMAC-SHA256 | Проверка при handshake (PSK + HMACKey) |
| Пароли | Argon2id | time=3, memory=64MB, threads=4, keyLen=32 |

### Сессионные ключи

HKDF выводит 96 байт (3 × 32), разделяемых на:

| Ключ | Сервер | Клиент |
|---|---|---|
| key1 (первые 32B) | SendKey | RecvKey |
| key2 (следующие 32B) | RecvKey | SendKey |
| key3 (последние 32B) | HMACKey | HMACKey |

### AAD для Data-пакетов

AAD = сериализованный `PacketHeader` (14 байт). **Важно:** `PayloadLen` в AAD = длина **открытого** текста (plaintext), а не ciphertext. На проводе в Header уходит тот же PayloadLen. Получатель строит AAD из полученного заголовка.

### PSK (Pre-Shared Key)

- 32 байта (64 hex-символа)
- Используется для: шифрования credentials в HandshakeInit, HMAC при handshake, salt в HKDF
- Текущий PSK: `95c6646b379581a2b51b5926747e36a4f254449246e33a7d1731dfb68f39fe46`

---

## 4. Рукопожатие (3-way handshake)

### Шаг 1: HandshakeInit (Клиент → Сервер)

```
Payload (без шифрования, только HMAC):
┌──────────────────┬──────────┬──────────┬────────────────────────┬──────────┐
│ ClientPubKey 32B │ Timestamp│ CredsLen │ EncryptedCredentials   │ HMAC 32B │
│                  │    8B    │   2B     │      variable          │          │
└──────────────────┴──────────┴──────────┴────────────────────────┴──────────┘
```

- **ClientPubKey**: Ephemeral Curve25519 public key
- **Timestamp**: Unix time (окно ±30 сек — anti-replay)
- **EncryptedCredentials**: `Nonce(12) + ChaCha20-Poly1305(PSK, EmailLen(2) + Email + PassLen(2) + Password)`
- **HMAC**: `HMAC-SHA256(PSK, ClientPubKey + Timestamp + EncryptedCredentials)`

**Сервер:**
1. Проверяет timestamp (±30 сек)
2. Проверяет HMAC → подтверждение знания PSK
3. Расшифровывает credentials PSK-ключом
4. Аутентифицирует email+пароль (Argon2id)
5. Создаёт сессию, выделяет VPN IP из пула
6. Генерирует ephemeral серверный ключ Curve25519
7. ECDH → shared secret → HKDF → 3 сессионных ключа
8. Отправляет HandshakeResp

### Шаг 2: HandshakeResp (Сервер → Клиент)

```
Payload:
┌──────────────────────────┬──────────────────────────────────────────────┐
│ ServerPubKey 32B (откр.) │ Encrypted(SendKey, HandshakeRespData 83B)   │
└──────────────────────────┴──────────────────────────────────────────────┘

HandshakeRespData:
┌──────────────────┬───────────┬────────────┬────────┬──────┬──────┬─────┬────────────┐
│ ServerPubKey 32B │ SessionID │ AssignedIP │ Subnet │ DNS1 │ DNS2 │ MTU │ ServerHMAC │
│                  │    4B     │    4B      │  1B    │  4B  │  4B  │ 2B  │   32B      │
└──────────────────┴───────────┴────────────┴────────┴──────┴──────┴─────┴────────────┘
```

**Клиент:**
1. Извлекает ServerPublicKey (открытая часть, первые 32 байта payload)
2. ECDH(clientPrivKey, serverPubKey) → shared secret
3. HKDF(sharedSecret, PSK, "novavpn-session-keys-v1") → 3 ключа (isServer=false)
4. Расшифровывает HandshakeResp сессионным RecvKey
5. Проверяет ServerHMAC
6. Сохраняет SessionID, VPN IP, DNS, MTU

### Шаг 3: HandshakeComplete (Клиент → Сервер)

```
Encrypted(SendKey, ConfirmHMAC 32B)
ConfirmHMAC = HMAC-SHA256(HMACKey, "novavpn-confirm-{SessionID}")
```

Сервер проверяет HMAC → сессия переходит в `Active`.

---

## 5. Передача данных

### Шифрование Data-пакета (отправка)

1. Формируем `PacketHeader` с `PayloadLen = len(plaintext)`
2. `AAD = header.MarshalHeader()` (14 байт)
3. `nonce, ciphertext = ChaCha20-Poly1305.Seal(SendKey, plaintext, AAD)`
4. Собираем пакет: `Header + Nonce(12) + Ciphertext` — при этом `PayloadLen` в заголовке = длина plaintext
5. Отправляем по UDP

### Дешифровка Data-пакета (приём)

1. Unmarshal заголовка → получаем `PacketHeader` (с `PayloadLen` = длина plaintext)
2. `AAD = header.MarshalHeader()`
3. `plaintext = ChaCha20-Poly1305.Open(RecvKey, nonce, ciphertext, AAD)`
4. Пишем plaintext (IP-пакет) в TUN

### Серверный data flow (3 горутины)

1. **`udpReadLoop`**: UDP → `handlePacket()` → dispatch по типу → для Data: расшифровка (RecvKey, AAD=header) → `tunDev.Write(plaintext)`
2. **`tunReadLoop`**: TUN read → `ExtractDstIP()` → поиск сессии по VPN IP → `sendToClient()` → шифровка (SendKey, AAD=header) → `udpConn.WriteToUDP()`
3. **`maintenanceLoop`**: cleanup expired sessions / stats / keepalives

### Клиентский data flow (3 горутины)

1. **`udpReadLoop`**: UDP read → unmarshal → для Data: расшифровка → `tun.Write()`
2. **`tunReadLoop`**: TUN read → шифровка → `conn.Write()`
3. **`keepaliveLoop`**: keepalive каждые 25 сек

---

## 6. Управление сессиями (сервер)

**Состояния:** `Handshake` → `Active` → `Expired`

**SessionManager** — 3 карты для O(1) поиска:
- `map[uint32]*Session` — по SessionID
- `map[string]*Session` — по VPN IP (для маршрутизации TUN → клиент)
- `map[string]*Session` — по UDP addr (для приёма)

**IPPool** — выделение адресов из VPN-подсети (10.8.0.0/24):
- Автоматическое выделение / освобождение
- Поддержка фиксированных IP per-user
- Исключение серверного IP (.1) и broadcast (.255)

**Обслуживание (каждые 30 сек):**
- Очистка истёкших сессий (timeout: 120 сек без keepalive)
- Keepalive всем активным клиентам (каждые 25 сек)
- Статистика (каждые 60 сек в лог)

---

## 7. TUN-реализация

### Сервер — Linux (`internal/tun/tun_linux.go`)

- `/dev/net/tun` + `ioctl TUNSETIFF` (IFF_TUN | IFF_NO_PI)
- IP: `ip addr add 10.8.0.1/24 dev nova0`
- MTU: `ip link set nova0 mtu 1400`
- NAT: `iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE`
- FORWARD: правила для nova0 ↔ ens3
- `sysctl net.ipv4.ip_forward=1`

### Клиент — Windows (`internal/tunnel/wintun.go`)

- **WinTUN API**: `CreateAdapter("NovaVPN", "NovaVPN")` → `StartSession(8MB)` → `ReceivePacket/AllocateSendPacket/SendPacket`
- **Настройка сети через netsh:**
  - `netsh interface ip set address "NovaVPN" static 10.8.0.X 255.255.255.0`
  - `netsh interface ip set dns "NovaVPN" static 1.1.1.1`
  - `netsh interface ip set interface "NovaVPN" metric=5`
  - `netsh interface ipv4 set subinterface "NovaVPN" mtu=1400`
- **Маршрутизация (full tunnel):**
  - `route add <serverIP> mask 255.255.255.255 <physGW> metric 1 IF <physIF>` — прямой путь к серверу через физический шлюз
  - `route add 0.0.0.0 mask 128.0.0.0 <vpnGW> metric 3 IF <tunIF>` — весь трафик через VPN
  - `route add 128.0.0.0 mask 128.0.0.0 <vpnGW> metric 3 IF <tunIF>`
- **Определение физического адаптера** (`GetPhysicalLocalIP`, `getPhysicalGateway`):
  - Фильтрация: исключаем `Tailscale|Wintun|NovaVPN|TAP|TUN|Loopback|VirtualBox`
  - Привязка маршрутов по IF index конкретного адаптера
- **UDP-сокет**: привязан к физическому IP адаптера (`net.DialUDP(localAddr=physIP)`) — обход WFP фильтров Tailscale

---

## 8. Аутентификация (сервер)

Файл: `internal/auth/auth.go`

- Хранение: YAML-файл `/etc/novavpn/users.yaml`
- Формат пароля: `hex(salt16B):hex(argon2id_hash32B)`
- Argon2id: time=3, memory=64MB, threads=4, keyLen=32
- Защита от timing-атак: при отсутствии email — фиктивное хеширование
- Проверка через `subtle.ConstantTimeCompare`
- Поля User: email, password_hash, assigned_ip, enabled, max_devices

**CLI-управление пользователями:**
```bash
novavpn-server -adduser  -email user@example.com -password secret
novavpn-server -deluser  -email user@example.com
novavpn-server -listusers
novavpn-server -passwd   -email user@example.com -password newpass
novavpn-server -disable  -email user@example.com
novavpn-server -enable   -email user@example.com
```

Тестовый пользователь: `test@novavpn.com` / `TestPass123!`

---

## 9. Конфигурация

### Сервер — `/etc/novavpn/server.yaml`

```yaml
listen_addr: "0.0.0.0"
listen_port: 51820
vpn_subnet: "10.8.0.0/24"
server_vpn_ip: "10.8.0.1"
tun_name: "nova0"
mtu: 1400
dns: ["1.1.1.1", "8.8.8.8"]
pre_shared_key: "95c6646b379581a2b51b5926747e36a4f254449246e33a7d1731dfb68f39fe46"
users_file: "/etc/novavpn/users.yaml"
max_clients: 256
keepalive_interval: 25
session_timeout: 120
enable_nat: true
external_interface: "ens3"
log_level: "debug"
```

### Клиент — `%APPDATA%\NovaVPN\novavpn-config.json`

```json
{
  "server_addr": "212.118.43.43:51820",
  "psk": "95c6646b379581a2b51b5926747e36a4f254449246e33a7d1731dfb68f39fe46",
  "email": "test@novavpn.com",
  "password": "TestPass123!",
  "auto_start": false,
  "was_connected": false
}
```

---

## 10. GUI (Windows)

Файл: `internal/gui/app.go`, фреймворк: **lxn/walk** (нативные Win32-контролы).

- Главное окно: поля Сервер / PSK / Email / Пароль + кнопка Подключиться/Отключиться
- Статистика: ↑ отправлено / ↓ получено (обновляется раз в секунду)
- Системный трей: иконка + контекстное меню (Подключить / Отключить / Настройки / Выход)
- Закрытие окна → сворачивание в трей (приложение продолжает работать)
- Автоподключение при запуске (если `was_connected=true`)
- `runtime.LockOSThread()` обязателен для Walk (COM/Win32)
- Манифест встроен через `rsrc` (для визуальных стилей, UAC)

---

## 11. Структура файлов

### Сервер

```
vpn-server/
├── cmd/vpnserver/main.go          # Точка входа, CLI, graceful shutdown
├── config/config.go               # Структура VPNConfig, валидация, YAML
├── internal/
│   ├── auth/auth.go               # Argon2id, CRUD пользователей, YAML хранение
│   ├── crypto/crypto.go           # ECDH, HKDF, ChaCha20-Poly1305, HMAC
│   ├── protocol/
│   │   ├── packet.go              # Формат пакетов, marshal/unmarshal
│   │   └── handshake.go           # Структуры HandshakeInit/Resp/Complete
│   ├── server/
│   │   ├── server.go              # Главная логика: UDP loop, TUN loop, dispatch
│   │   └── session.go             # SessionManager, IPPool, Session state
│   └── tun/tun_linux.go           # Linux TUN через /dev/net/tun, NAT, routing
├── configs/
│   ├── server.example.yaml
│   └── users.example.yaml
└── go.mod / go.sum
```

### Клиент

```
vpn-client-windows/
├── cmd/
│   ├── novavpn/main.go            # GUI точка входа, LockOSThread, -autostart
│   ├── test/main.go               # CLI тест handshake
│   ├── testdata/main.go           # CLI тест data path (ICMP ping)
│   └── sshcmd/main.go             # Go SSH-утилита (обход Tailscale WFP)
├── internal/
│   ├── crypto/crypto.go           # Клиентская крипто (зеркало сервера)
│   ├── protocol/protocol.go       # Клиентский протокол (зеркало сервера)
│   ├── vpnclient/client.go        # Connect/Disconnect, handshake, data loops
│   ├── tunnel/wintun.go           # WinTUN, ConfigureNetwork, маршруты, GetPhysicalLocalIP
│   ├── gui/app.go                 # Walk GUI, трей, статистика
│   ├── config/config.go           # JSON конфиг в %APPDATA%
│   └── autostart/autostart.go     # Автозапуск через реестр
├── novavpn.manifest               # Windows manifest (UAC, visual styles)
├── wintun.dll                     # WinTUN драйвер (amd64)
└── go.mod / go.sum
```

---

## 12. Деплой

### Сервер

- Systemd-сервис: `/etc/systemd/system/novavpn.service`
- ExecStart: `/usr/local/bin/novavpn-server -config /etc/novavpn/server.yaml`
- Capabilities: `CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE`
- `systemctl restart novavpn` / `journalctl -u novavpn -f`

### Клиент

- Сборка: `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-H windowsgui" -o NovaVPN.exe ./cmd/novavpn/`
- Манифест: `rsrc -manifest novavpn.manifest -o rsrc.syso` (перед сборкой)
- Требует: `wintun.dll` рядом с exe
- Требует: запуск от администратора (TUN, маршруты)

---

## 13. Известные особенности

1. **Tailscale совместимость**: клиент определяет физический адаптер, исключая Tailscale/VirtualBox/Wintun. UDP-сокет явно привязывается к физическому IP. Маршруты ставятся с привязкой к IF index.

2. **AAD-консистентность**: при шифровании Data-пакетов `PayloadLen` в заголовке = длина plaintext (не ciphertext). Пакет собирается через `&protocol.Packet{Header: header, ...}`, а не через `NewPacket()` (который перезаписал бы PayloadLen).

3. **ServerPublicKey в HandshakeResp** отправляется открыто (первые 32 байта payload) — это необходимо, чтобы клиент мог выполнить ECDH до расшифровки остальной части ответа (chicken-and-egg).

4. **wintun.dll** должен лежать рядом с exe (или в PATH). Версия: 0.14 amd64.

5. **Клиент использует split-tunnel маршруты** (0.0.0.0/1 + 128.0.0.0/1) вместо замены default route — это надёжнее на Windows и не конфликтует с системным маршрутом.
