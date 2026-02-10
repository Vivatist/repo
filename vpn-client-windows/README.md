# NovaVPN Client для Windows

GUI-клиент для подключения к VPN-серверу NovaVPN. Нативное Windows-приложение с иконкой в системном трее.

## Возможности

- **Простое подключение** — введите адрес сервера, PSK, email и пароль
- **Иконка в трее** — отображение текущего статуса подключения
- **Автозапуск** — при старте Windows восстанавливает предыдущее соединение
- **Статистика** — объём переданного и полученного трафика в реальном времени
- **Full-tunnel** — весь трафик идёт через VPN
- **WinTUN** — современный TUN-адаптер (как в WireGuard)

## Требования для сборки

- **Go 1.21+** — https://go.dev/dl/
- **rsrc** — для встраивания Windows-манифеста (устанавливается автоматически)
- **wintun.dll** — скачать с https://www.wintun.net/

## Сборка

### Вариант 1: build.bat

```cmd
build.bat
```

### Вариант 2: вручную

```powershell
go install github.com/akavel/rsrc@latest
cd cmd\novavpn
rsrc -manifest NovaVPN.exe.manifest -o rsrc.syso
cd ..\..
go build -ldflags="-s -w -H windowsgui" -o NovaVPN.exe ./cmd/novavpn/
```

## Установка

1. Скачайте `wintun.dll` с https://www.wintun.net/ (amd64 версию)
2. Положите `wintun.dll` рядом с `NovaVPN.exe`
3. Запустите `NovaVPN.exe` от имени администратора

Файловая структура:
```
NovaVPN/
├── NovaVPN.exe
└── wintun.dll
```

## Использование

### Первый запуск

1. Запустите `NovaVPN.exe` (запросит права администратора)
2. Заполните поля:
   - **Сервер** — адрес:порт (например `212.118.43.43:51820`)
   - **PSK** — Pre-Shared Key с сервера
   - **Email** — ваш логин
   - **Пароль** — ваш пароль
3. Нажмите **Подключиться**
4. Иконка в трее покажет статус

### Системный трей

- **Двойной клик** — открыть окно настроек
- **ПКМ → Подключить/Отключить** — управление VPN
- **ПКМ → Настройки** — окно настроек
- **ПКМ → Выход** — закрыть приложение

### Автозапуск

Установите галочку **"Запускать при старте Windows"**. При следующем включении:
- Если VPN был подключён до перезагрузки → автоматически подключится
- Если VPN был отключён → останется отключённым

### Настройки

Хранятся в `%APPDATA%\NovaVPN\config.json`.  
Логи: `%APPDATA%\NovaVPN\novavpn.log`.

## Структура проекта

```
vpn-client-windows/
├── cmd/
│   └── novavpn/
│       ├── main.go                     # Точка входа
│       └── NovaVPN.exe.manifest        # Windows-манифест (UAC admin)
├── internal/
│   ├── crypto/
│   │   └── crypto.go                   # ECDH, ChaCha20, HKDF, HMAC
│   ├── protocol/
│   │   └── protocol.go                 # Формат пакетов, handshake
│   ├── vpnclient/
│   │   └── client.go                   # VPN-подключение, I/O
│   ├── tunnel/
│   │   └── wintun.go                   # WinTUN-адаптер, маршруты, DNS
│   ├── config/
│   │   └── config.go                   # Настройки (JSON)
│   ├── autostart/
│   │   └── autostart.go                # Реестр Windows (автозагрузка)
│   └── gui/
│       └── app.go                      # Walk GUI + системный трей
├── build.bat                           # Скрипт сборки
├── Makefile
├── go.mod
└── README.md
```

## Технологии

| Компонент | Технология |
|-----------|-----------|
| GUI | lxn/walk (нативные Windows-виджеты) |
| Трей | walk.NotifyIcon |
| TUN | WinTUN (golang.zx2c4.com/wintun) |
| Шифрование | ChaCha20-Poly1305 |
| Обмен ключами | ECDH Curve25519 |
| Хэши | HKDF-SHA256, HMAC-SHA256 |
| Маршрутизация | netsh / route (Windows) |

## Безопасность

- Пароль зашифрован PSK при передаче (ChaCha20-Poly1305)
- Perfect Forward Secrecy (ephemeral ECDH)
- Ключи обнуляются в памяти после использования
- Приложение запрашивает права администратора (для TUN)

## Лицензия

MIT
