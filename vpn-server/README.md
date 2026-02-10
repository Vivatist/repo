# NovaVPN Server

Серверная часть VPN с собственным протоколом **NovaVPN**. Написан на Go, оптимизирован для Ubuntu 22.04.

## Возможности

- **Собственный протокол** поверх UDP — минимальная задержка
- **Аутентификация по email + паролю** — простая настройка клиентов
- **Argon2id** — надёжное хэширование паролей (OWASP-рекомендация)
- **ChaCha20-Poly1305** — современное AEAD-шифрование
- **ECDH (Curve25519)** — безопасный обмен ключами
- **HKDF-SHA256** — криптографически стойкий вывод сессионных ключей
- **Pre-Shared Key** — дополнительный уровень аутентификации
- **TUN-интерфейс** — полноценное туннелирование L3 трафика
- **NAT/Masquerade** — автоматическая настройка маршрутизации
- **Пул IP-адресов** — автоматическая выдача VPN IP клиентам
- **Graceful shutdown** — корректное завершение с очисткой правил
- **Systemd** — работа как системный сервис

## Архитектура протокола

### Формат пакета

```
┌──────────┬─────────┬──────┬───────────┬─────┬────────────┬───────┬───────────────────┐
│ Magic 2B │ Ver 1B  │ Type │ SessionID │ Seq │ PayloadLen │ Nonce │ Encrypted Payload │
│ 0x4E56   │  0x01   │ 1B   │    4B     │ 4B  │    2B      │ 12B   │    variable        │
└──────────┴─────────┴──────┴───────────┴─────┴────────────┴───────┴───────────────────┘
```

- **Magic bytes** `0x4E56` ("NV") — идентификатор протокола
- **Overhead**: 26B заголовок + 12B nonce + 16B auth tag = **54 байта**

### Типы пакетов

| Тип | Код | Описание |
|-----|-----|----------|
| HandshakeInit | `0x01` | Инициация рукопожатия (клиент → сервер) |
| HandshakeResp | `0x02` | Ответ на рукопожатие (сервер → клиент) |
| HandshakeComplete | `0x03` | Завершение рукопожатия (клиент → сервер) |
| Data | `0x10` | Зашифрованный IP-пакет |
| Keepalive | `0x20` | Поддержание сессии |
| Disconnect | `0x30` | Отключение |
| Error | `0xF0` | Ошибка (например, неверные учётные данные) |

### Рукопожатие (3-way handshake)

```
Клиент                                       Сервер
  │                                            │
  │  HandshakeInit                             │
  │  [EphemeralPubKey + Timestamp +            │
  │   EncryptedCredentials(email,pass) + HMAC] │
  │───────────────────────────────────────────►│
  │                                            │ Расшифровывает credentials (PSK),
  │                                            │ проверяет email+пароль (Argon2id),
  │                                            │ генерирует сессионные ключи
  │  HandshakeResp                             │
  │  [ServerPubKey + SessionID + VPN IP]       │
  │◄───────────────────────────────────────────│
  │                                            │
  │  HandshakeComplete                         │
  │  [ConfirmHMAC]                             │
  │───────────────────────────────────────────►│
  │                                            │ Сессия активна
  │  ══════ Зашифрованный трафик ═══════      │
  │◄──────────────────────────────────────────►│
```

### Криптография

1. **Аутентификация**: Email + пароль, зашифрованный PSK через ChaCha20-Poly1305
2. **Хэширование паролей**: Argon2id (time=3, memory=64MB, threads=4, keylen=32)
3. **Обмен ключами**: ECDH на Curve25519 — ephemeral ключи для каждой сессии
4. **Вывод ключей**: HKDF-SHA256(shared_secret, PSK) → SendKey + RecvKey + HMACKey
5. **Шифрование**: ChaCha20-Poly1305 (AEAD) с random nonce
6. **Целостность**: Poly1305 MAC + Additional Data (заголовок пакета)

### Формат EncryptedCredentials

```
┌──────────┬────────────────────────────────────────────┬───────────┐
│ Nonce    │ ChaCha20-Poly1305(EmailLen + Email +       │ AuthTag   │
│ 12B      │                   PassLen + Password)      │ 16B       │
└──────────┴────────────────────────────────────────────┴───────────┘
```

Ключ шифрования: HKDF-SHA256("novavpn-credentials", PSK)

## Установка

### Быстрая установка (Ubuntu 22.04)

```bash
git clone https://github.com/novavpn/vpn-server.git
cd vpn-server
sudo bash scripts/setup.sh
```

### Ручная сборка

```bash
# Требования: Go 1.21+
go mod tidy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o novavpn-server ./cmd/vpnserver/
sudo cp novavpn-server /usr/local/bin/
```

## Настройка

### 1. Генерация PSK

```bash
novavpn-server -genkey
```

### 2. Конфигурация сервера

```bash
# Генерация шаблона конфигурации
novavpn-server -genconfig > /etc/novavpn/server.yaml
```

Файл `/etc/novavpn/server.yaml`:

```yaml
listen_addr: "0.0.0.0"
listen_port: 51820
vpn_subnet: "10.8.0.0/24"
server_vpn_ip: "10.8.0.1"
tun_name: "nova0"
mtu: 1400
dns:
  - "1.1.1.1"
  - "8.8.8.8"
pre_shared_key: "<ваш PSK>"
users_file: "/etc/novavpn/users.yaml"
max_clients: 256
keepalive_interval: 25
session_timeout: 120
enable_nat: true
external_interface: "eth0"
log_level: "info"
```

### 3. Управление пользователями

```bash
# Добавить пользователя
novavpn-server -adduser -email user@example.com -password mysecretpass

# Добавить с фиксированным IP и лимитом устройств
novavpn-server -adduser -email vip@example.com -password pass123 -ip 10.8.0.10 -maxdevices 3

# Список пользователей
novavpn-server -listusers

# Сменить пароль
novavpn-server -passwd -email user@example.com -password newpassword

# Заблокировать пользователя
novavpn-server -disable -email user@example.com

# Разблокировать
novavpn-server -enable -email user@example.com

# Удалить пользователя
novavpn-server -deluser -email user@example.com
```

Или интерактивно:

```bash
sudo bash scripts/add-user.sh
```

### 4. Запуск

```bash
# Через systemd
sudo systemctl start novavpn
sudo systemctl status novavpn

# Логи
journalctl -u novavpn -f

# Или напрямую (для отладки)
sudo novavpn-server -config /etc/novavpn/server.yaml
```

## Данные для клиентов

Для подключения клиенту необходимо сообщить:

| Параметр | Описание |
|----------|----------|
| **Сервер** | IP-адрес и порт сервера |
| **PSK** | Pre-Shared Key (общий секрет) |
| **Email** | Email-логин пользователя |
| **Пароль** | Пароль пользователя |

> **Важно:** PSK нужно передать клиенту по безопасному каналу (лично, Signal, и т.д.)

## Структура проекта

```
vpn-server/
├── cmd/
│   └── vpnserver/
│       └── main.go              # Точка входа, CLI
├── config/
│   └── config.go                # Конфигурация сервера
├── internal/
│   ├── auth/
│   │   └── auth.go              # Argon2id, хранилище пользователей
│   ├── protocol/
│   │   ├── packet.go            # Формат пакетов протокола
│   │   └── handshake.go         # Структуры рукопожатия
│   ├── crypto/
│   │   └── crypto.go            # ECDH, ChaCha20, HKDF, HMAC
│   ├── server/
│   │   ├── server.go            # Основной VPN-сервер
│   │   └── session.go           # Управление сессиями + IP-пул
│   └── tun/
│       └── tun_linux.go         # TUN-интерфейс для Linux
├── scripts/
│   ├── setup.sh                 # Установка на Ubuntu
│   └── add-user.sh              # Добавление пользователя (интерактивное)
├── configs/
│   ├── server.example.yaml      # Пример конфигурации
│   └── users.example.yaml       # Пример файла пользователей
├── go.mod
└── README.md
```

## Клиенты

Протокол разработан для кросс-платформенных клиентов:

| Платформа | Статус | Заметки |
|-----------|--------|---------|
| Windows | Планируется | TAP/Wintun адаптер |
| Android | Планируется | VpnService API |
| iOS | Планируется | NetworkExtension (Packet Tunnel) |

Для клиента необходимо реализовать:
1. Формат пакетов (`internal/protocol/`)
2. Криптографию (`internal/crypto/`)
3. Аутентификацию по email + паролю (шифрование credentials PSK-ключом)
4. Платформенный TUN/TAP адаптер
5. 3-way handshake

## Безопасность

- **Argon2id** — защита паролей от перебора (OWASP-рекомендованные параметры)
- **Шифрование credentials** — пароль никогда не передаётся в открытом виде
- **Timing-attack protection** — constant-time сравнение + dummy хэш при отсутствии email
- **Perfect Forward Secrecy** — ephemeral ECDH ключи для каждой сессии
- **Replay Protection** — timestamp + sequence numbers
- **PSK аутентификация** — защита от неавторизованных подключений
- **AEAD шифрование** — ChaCha20-Poly1305 с authenticated encryption
- **Обнуление ключей** — ключи обнуляются в памяти при удалении сессии

## Лицензия

MIT
