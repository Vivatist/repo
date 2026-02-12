# Отчет по рефакторингу Windows клиента NovaVPN

**Дата:** 12 февраля 2026  
**Анализируемый компонент:** vpn-client-windows  
**Версия:** текущая (main branch)  

---

## 📋 Исполнительное резюме

Windows клиент NovaVPN реализован на языке Go и следует **двухпроцессной архитектуре** с разделением привилегий. Код имеет **хорошую высокоуровневую структуру**, но страдает от:

- ❌ **Монолитных компонентов** (GUI 671 строк, VPN клиент 633 строки)
- ❌ **Высокой связанности** между модулями
- ❌ **Неиспользуемого кода** (пакет autostart, тестовые утилиты)
- ❌ **Проблем безопасности** (хранение паролей в открытом виде)
- ⚠️ **Отсутствия слоевой архитектуры** (прямые вызовы системных API)

**Оценка технического долга:** СРЕДНЯЯ  
**Приоритет рефакторинга:** ВЫСОКИЙ

---

## 1. Текущая архитектура

### 1.1 Общая структура

```
┌─────────────────────────────────────────────────────────────────┐
│  NovaVPN.exe (GUI процесс)                                      │
│  ├─ Графический интерфейс (Walk framework)                      │
│  ├─ IPC клиент (Named Pipe)                                     │
│  ├─ Управление конфигурацией                                     │
│  └─ Повышение привилегий (UAC)                                  │
└──────────────────┬──────────────────────────────────────────────┘
                   │ IPC через Named Pipe (\\.\pipe\NovaVPN)
┌──────────────────▼──────────────────────────────────────────────┐
│  novavpn-service.exe (Системная служба Windows)                │
│  ├─ IPC сервер                                                  │
│  ├─ VPN клиент (протокол, handshake, шифрование)               │
│  ├─ Управление WinTUN адаптером                                 │
│  └─ Настройка маршрутов и DNS                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Структура пакетов

| Пакет | Строк кода | Зависимости | Ответственность |
|-------|-----------|-------------|-----------------|
| **crypto/** | ~200 | stdlib | Шифрование ChaCha20-Poly1305, ECDH, HKDF |
| **protocol/** | ~300 | stdlib | Формат пакетов, handshake сообщения |
| **vpnclient/** | **633** | crypto, protocol, tunnel | **VPN соединение, конечный автомат** |
| **tunnel/** | **388** | wintun, stdlib | WinTUN адаптер, маршруты, DNS |
| **service/** | ~250 | ipc, vpnclient | Служба Windows, SCM интеграция |
| **ipc/** | ~300 | go-winio | Named Pipe клиент/сервер |
| **gui/** | **671** | walk, config, ipc | **Графический интерфейс, логика UI** |
| **config/** | ~100 | stdlib | JSON конфигурация |
| **autostart/** | ~50 | stdlib | ⚠️ **НЕ ИСПОЛЬЗУЕТСЯ** |
| **elevation/** | ~50 | sys/windows | UAC повышение привилегий |

### 1.3 Точки входа (entry points)

```
cmd/
├── novavpn/main.go           # GUI приложение (пользовательский режим)
├── novavpn-service/main.go   # Установка/управление службой Windows
├── sshcmd/main.go            # ⚠️ Тестовая утилита SSH (не используется в продакшене)
├── testdata/main.go          # ⚠️ Тест handshake (не используется в продакшене)
└── icongen/main.go           # Генератор иконок (build-time утилита)
```

---

## 2. Проблемы текущей архитектуры

### 2.1 ❌ КРИТИЧЕСКИЕ проблемы

#### Проблема 1: Монолитный GUI модуль (gui/app.go - 671 строка)

**Симптомы:**
- Один файл содержит 10+ различных обязанностей
- Смешивает UI логику, IPC коммуникацию, управление службой, пинг-тесты
- Невозможно тестировать изолированно

**Текущий код:**
```go
type App struct {
    // UI компоненты
    mainWindow *walk.MainWindow
    ni         *walk.NotifyIcon
    connectBtn *walk.PushButton
    // Конфигурация
    config *config.Config
    // IPC клиент
    ipcClient *ipc.Client
    // Состояние
    status VPNStatus
}

// Один тип делает все:
func (a *App) connectToVPN() { ... }      // Логика подключения
func (a *App) createUI() { ... }          // Создание UI
func (a *App) startStatusPoller() { ... } // Фоновая задача
func (a *App) pingServer() { ... }        // Сетевая диагностика
func (a *App) installService() { ... }    // Управление службой
```

**Проблемы связанности:**
- `App` напрямую зависит от `ipc.Client`, `config.Config`, `walk.*`
- Невозможно заменить IPC на другую реализацию без изменения `App`
- Тесты требуют инициализации полного GUI

**Рекомендация:** Разделить на 4 слоя (см. раздел 3.2)

---

#### Проблема 2: Хранение паролей в открытом виде

**Файл:** `internal/config/config.go`

```go
type Config struct {
    Server       string `json:"server"`
    Username     string `json:"username"`
    Password     string `json:"password"`      // пароль (TODO: DPAPI encryption)
    PreSharedKey string `json:"pre_shared_key"`
}
```

**Риск безопасности:**
- Пароли хранятся в `%APPDATA%\NovaVPN\config.json` в открытом виде
- Любой процесс пользователя может прочитать файл
- TODO комментарий указывает на незавершенную реализацию DPAPI

**Рекомендация:**
```go
// Использовать Windows DPAPI для шифрования чувствительных полей
import "golang.org/x/sys/windows"

func (c *Config) encryptPassword() error {
    encrypted, err := windows.CryptProtectData([]byte(c.Password), nil, nil, 0, nil, 0)
    if err != nil {
        return err
    }
    c.EncryptedPassword = base64.StdEncoding.EncodeToString(encrypted)
    c.Password = "" // Очистить plaintext
    return nil
}
```

---

#### Проблема 3: Монолитный VPN клиент (vpnclient/client.go - 633 строки)

**Симптомы:**
- Смешивает 5 обязанностей в одном типе:
  1. Handshake протокол
  2. Шифрование/дешифрование пакетов
  3. UDP чтение/запись (2 горутины)
  4. Чтение из TUN устройства (1 горутина)
  5. Keepalive таймеры

**Проблемы:**
```go
type Client struct {
    // Сетевые компоненты
    conn         *net.UDPConn
    remoteAddr   *net.UDPAddr
    tun          *tunnel.Tunnel
    
    // Криптография
    sendKey      []byte
    recvKey      []byte
    hmacKey      []byte
    
    // Состояние
    state        int32
    sessionID    uint32
    sendSeq      uint64
    recvSeq      uint64
    
    // Статистика
    bytesSent    uint64
    bytesRecv    uint64
    
    // Каналы для горутин
    udpReadChan  chan []byte
    tunReadChan  chan []byte
    stopChan     chan struct{}
}

// 3 горутины работают с общим состоянием:
func (c *Client) udpReadLoop() { ... }      // Горутина 1
func (c *Client) tunReadLoop() { ... }      // Горутина 2
func (c *Client) keepaliveLoop() { ... }    // Горутина 3
```

**Проблемы гонки данных:**
- Атомарные операции используются для статистики, но не для криптографических ключей
- Множественные горутины читают `c.state` без полной синхронизации
- `c.sessionID` может измениться во время переподключения

**Рекомендация:** Разделить на 3 компонента (см. раздел 3.3)

---

### 2.2 ⚠️ ЗНАЧИТЕЛЬНЫЕ проблемы

#### Проблема 4: Прямая зависимость от WinTUN API

**Файл:** `internal/tunnel/wintun.go` (388 строк)

```go
func (t *Tunnel) SetRoutes() error {
    // Прямой вызов netsh.exe через exec.Command
    cmd := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
        t.config.InterfaceName, "static", dnsServer, "primary")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to set DNS: %w", err)
    }
    // ...
}
```

**Проблемы:**
- Нет интерфейса для подмены в тестах
- Зависимость от конкретной версии Windows и формата вывода `netsh`
- Сложно добавить поддержку альтернативных TUN драйверов

**Рекомендация:** Ввести интерфейс `NetworkConfigurator`

---

#### Проблема 5: Polling вместо event-driven архитектуры

**Файл:** `internal/gui/app.go`

```go
func (a *App) startStatusPoller() {
    ticker := time.NewTicker(500 * time.Millisecond)
    go func() {
        for range ticker.C {
            // Каждые 500мс опрашиваем службу
            status, err := a.ipcClient.GetStatus()
            if err == nil {
                a.updateStatusUI(status)
            }
        }
    }()
}
```

**Проблемы:**
- Неэффективно: 2 IPC запроса в секунду даже когда статус не меняется
- Задержка UI: изменения статуса видны с задержкой до 500мс
- Нагрузка на Named Pipe при множестве клиентов

**Рекомендация:** Push-уведомления от службы через callback канал

---

### 2.3 🔍 Мертвый код и неиспользуемые файлы

#### 1. ❌ Неиспользуемый пакет: `internal/autostart/`

**Файл:** `internal/autostart/autostart.go`

```go
package autostart

// Enable добавляет приложение в автозапуск Windows
func Enable(appName, exePath string) error { ... }

// Disable удаляет из автозапуска
func Disable(appName string) error { ... }

// IsEnabled проверяет статус
func IsEnabled(appName string) (bool, error) { ... }
```

**Статус:** 
- ✅ Функциональность описана в README: "Автозапуск — при старте Windows восстанавливает предыдущее соединение"
- ❌ Пакет **нигде не импортируется**
- ❌ В GUI нет чекбокса "Автозапуск"
- ❌ Функциональность не реализована

**Вердикт:** УДАЛИТЬ или завершить реализацию

**Команда для проверки:**
```bash
$ grep -r "internal/autostart" --include="*.go" .
# Результат: (пусто) - нет импортов
```

---

#### 2. ⚠️ Тестовые утилиты в продакшен коде

**Файл:** `cmd/sshcmd/main.go` (98 строк)

```go
func main() {
    host := "212.118.43.43:22"    // Hardcoded IP
    user := "root"                // Hardcoded username
    password := os.Getenv("SSH_PASSWORD")
    
    // SSH соединение и выполнение команд
    // ...
}
```

**Проблемы:**
- Hardcoded credentials в исходном коде
- Нет использования в build pipeline
- Не документирован в README

**Вердикт:** УДАЛИТЬ или переместить в отдельный repo для dev tools

---

**Файл:** `cmd/testdata/main.go` (225 строк)

```go
func main() {
    serverAddr := "212.118.43.43:8443"  // Hardcoded server
    
    // Полный handshake тест с ICMP пакетами
    client := vpnclient.NewClient(&vpnclient.Config{
        ServerAddr: serverAddr,
        Username:   "test",
        Password:   "test",
        // ...
    })
}
```

**Вердикт:** Переместить в `internal/vpnclient/client_test.go` как интеграционный тест

---

#### 3. ✅ Build-time утилиты (оставить)

**Файл:** `cmd/icongen/main.go`

```go
// Генерирует embedded иконки для GUI
func main() {
    generateIcons()
}
```

**Статус:** Используется в Makefile, необходим для сборки

---

## 3. Рекомендации по рефакторингу

### 3.1 Целевая архитектура: Чистая архитектура с слоями

```
┌──────────────────────────────────────────────────────────────────┐
│ СЛОЙ 4: Presentation (UI)                                        │
│ ├─ gui/windows/          Окна и диалоги Walk                     │
│ ├─ gui/viewmodels/       View Models, state management          │
│ └─ gui/systray/          Системный трей                          │
└────────────┬─────────────────────────────────────────────────────┘
             │ (зависит от)
┌────────────▼─────────────────────────────────────────────────────┐
│ СЛОЙ 3: Application Services                                     │
│ ├─ services/vpn/         VPN service orchestrator               │
│ ├─ services/config/      Конфигурация с DPAPI шифрованием       │
│ ├─ services/diagnostics/ Пинг, трейсроут, проверка связи        │
│ └─ services/updates/     Автообновление клиента                 │
└────────────┬─────────────────────────────────────────────────────┘
             │ (зависит от)
┌────────────▼─────────────────────────────────────────────────────┐
│ СЛОЙ 2: Domain / Business Logic                                 │
│ ├─ domain/vpn/           Интерфейсы VPNClient, ConnectionState  │
│ ├─ domain/crypto/        Криптографические интерфейсы           │
│ └─ domain/network/       NetworkConfigurator интерфейс          │
└────────────┬─────────────────────────────────────────────────────┘
             │ (зависит от)
┌────────────▼─────────────────────────────────────────────────────┐
│ СЛОЙ 1: Infrastructure / Implementation                          │
│ ├─ infra/vpnclient/      Реализация VPN протокола               │
│ ├─ infra/crypto/         ChaCha20, ECDH реализации              │
│ ├─ infra/tunnel/         WinTUN driver wrapper                  │
│ ├─ infra/ipc/            Named Pipe транспорт                   │
│ └─ infra/platform/       Windows API (registry, UAC, services)  │
└──────────────────────────────────────────────────────────────────┘
```

**Правила зависимостей:**
1. Верхние слои зависят от нижних (никогда наоборот)
2. Каждый слой зависит только от интерфейсов нижнего слоя
3. Infrastructure слой реализует интерфейсы Domain слоя

---

### 3.2 Приоритет 1: Рефакторинг GUI (gui/app.go)

#### Текущая структура (монолит):
```
gui/
└── app.go (671 строка) - ВСЁ в одном файле
```

#### Целевая структура (разделение обязанностей):
```
gui/
├── app.go                    # Главная точка входа (30 строк)
├── viewmodels/
│   ├── connection_vm.go      # ViewModel для состояния подключения
│   └── settings_vm.go        # ViewModel для настроек
├── windows/
│   ├── main_window.go        # Главное окно
│   ├── settings_dialog.go    # Диалог настроек
│   └── log_window.go         # Окно логов
├── systray/
│   └── tray_icon.go          # Системный трей
└── services/
    ├── vpn_service.go        # Обертка над IPC клиентом
    └── diagnostics.go        # Пинг и диагностика
```

#### Пример рефакторинга:

**ДО (app.go):**
```go
type App struct {
    mainWindow *walk.MainWindow
    ni         *walk.NotifyIcon
    connectBtn *walk.PushButton
    config     *config.Config
    ipcClient  *ipc.Client
    status     VPNStatus
}

func (a *App) connectToVPN() {
    // 50 строк логики подключения
    if err := a.ipcClient.Connect(...); err != nil { ... }
    // Обновление UI
    a.connectBtn.SetEnabled(false)
    a.ni.SetIcon(iconConnected)
}
```

**ПОСЛЕ (разделение на слои):**

```go
// gui/app.go (главная точка входа)
type App struct {
    mainWindow *windows.MainWindow
    trayIcon   *systray.TrayIcon
    vpnService *services.VPNService
}

func (a *App) Run() error {
    // Создание компонентов
    a.vpnService = services.NewVPNService(ipc.NewClient())
    a.mainWindow = windows.NewMainWindow(a.vpnService)
    a.trayIcon = systray.NewTrayIcon(a.vpnService)
    
    // Связывание событий
    a.vpnService.OnStatusChange(a.mainWindow.UpdateStatus)
    a.vpnService.OnStatusChange(a.trayIcon.UpdateIcon)
    
    return a.mainWindow.Run()
}

// gui/services/vpn_service.go (бизнес-логика)
type VPNService struct {
    ipcClient      *ipc.Client
    statusHandlers []func(VPNStatus)
}

func (s *VPNService) Connect(server, username, password string) error {
    if err := s.ipcClient.Connect(...); err != nil {
        return err
    }
    s.notifyStatusChange(StatusConnected)
    return nil
}

func (s *VPNService) OnStatusChange(handler func(VPNStatus)) {
    s.statusHandlers = append(s.statusHandlers, handler)
}

// gui/windows/main_window.go (UI компоненты)
type MainWindow struct {
    *walk.MainWindow
    connectBtn *walk.PushButton
    vpnService *services.VPNService
}

func (w *MainWindow) UpdateStatus(status VPNStatus) {
    w.Synchronize(func() {
        w.connectBtn.SetEnabled(status != StatusConnecting)
        w.connectBtn.SetText(status.String())
    })
}
```

**Преимущества:**
- ✅ Каждый файл < 200 строк
- ✅ Можно тестировать `VPNService` без инициализации GUI
- ✅ Легко добавить новые окна/диалоги
- ✅ UI компоненты не знают о деталях IPC

---

### 3.3 Приоритет 2: Рефакторинг VPN клиента

#### Текущая структура (монолит):
```
vpnclient/
└── client.go (633 строки) - handshake + I/O + crypto + state
```

#### Целевая структура (разделение обязанностей):
```
vpnclient/
├── client.go              # Главный фасад, координация
├── handshake/
│   ├── initiator.go       # Handshake инициация
│   └── responder.go       # Обработка ответов сервера
├── transport/
│   ├── udp_reader.go      # UDP -> VPN пакеты (горутина)
│   ├── tun_reader.go      # TUN -> VPN пакеты (горутина)
│   └── packet_queue.go    # Буферизация и упорядочивание
├── crypto/
│   └── session.go         # Управление ключами сессии
└── state/
    └── connection.go      # Конечный автомат состояний
```

#### Пример рефакторинга:

**ДО (client.go - смешанные обязанности):**
```go
type Client struct {
    conn       *net.UDPConn
    tun        *tunnel.Tunnel
    sendKey    []byte       // Криптография
    recvKey    []byte
    state      int32        // Состояние
    sessionID  uint32
    bytesSent  uint64       // Статистика
    stopChan   chan struct{}
}

func (c *Client) Connect() error {
    // Handshake (100 строк)
    // Запуск горутин (20 строк)
    // Криптография (30 строк)
    // ...
}

func (c *Client) udpReadLoop() {
    // 150 строк чтения, декодирования, маршрутизации пакетов
}
```

**ПОСЛЕ (разделение по файлам):**

```go
// vpnclient/client.go (координация)
type Client struct {
    handshake  *handshake.Initiator
    transport  *transport.Manager
    session    *crypto.Session
    state      *state.Connection
    statistics *Statistics
}

func (c *Client) Connect() error {
    // 1. Выполнить handshake
    keys, err := c.handshake.Perform(c.config)
    if err != nil {
        return err
    }
    
    // 2. Инициализировать криптографическую сессию
    c.session = crypto.NewSession(keys)
    
    // 3. Запустить транспорт
    c.transport.Start(c.session)
    
    // 4. Обновить состояние
    c.state.SetConnected()
    
    return nil
}

// vpnclient/handshake/initiator.go (handshake логика)
type Initiator struct {
    psk string
}

func (h *Initiator) Perform(config *Config) (*SessionKeys, error) {
    // 50 строк - только handshake протокол
    clientKey := crypto.GenerateKeyPair()
    initPacket := protocol.NewHandshakeInit(clientKey.Public, config)
    // ...
    return keys, nil
}

// vpnclient/transport/udp_reader.go (горутина чтения)
type UDPReader struct {
    conn    *net.UDPConn
    session *crypto.Session
    output  chan<- []byte
}

func (r *UDPReader) Start() {
    go r.readLoop()
}

func (r *UDPReader) readLoop() {
    // 50 строк - только UDP чтение и декодирование
    for {
        buf := make([]byte, 2048)
        n, err := r.conn.Read(buf)
        // Декодирование
        plaintext, err := r.session.Decrypt(buf[:n])
        // Отправка в канал
        r.output <- plaintext
    }
}

// vpnclient/state/connection.go (конечный автомат)
type Connection struct {
    current  atomic.Value // ConnectionState
    handlers []StateChangeHandler
}

func (c *Connection) SetConnected() {
    old := c.current.Load().(ConnectionState)
    c.current.Store(StateConnected)
    c.notifyHandlers(old, StateConnected)
}
```

**Преимущества:**
- ✅ Каждый компонент тестируется изолированно
- ✅ Легко добавить новые типы транспорта (TCP, QUIC)
- ✅ Явные границы между модулями
- ✅ Безопасность: ключи изолированы в `crypto.Session`

---

### 3.4 Приоритет 3: Интерфейсы для инфраструктуры

#### Проблема: Прямая зависимость от WinTUN

**ДО:**
```go
// tunnel/wintun.go
type Tunnel struct {
    adapter *wintun.Adapter  // Прямая зависимость от библиотеки
}

func (t *Tunnel) SetRoutes() error {
    cmd := exec.Command("netsh", "interface", "ipv4", "add", "route", ...)
    return cmd.Run()
}
```

**ПОСЛЕ (введение интерфейсов):**

```go
// domain/network/interfaces.go (Domain layer)
package network

type TunnelDevice interface {
    Read(buf []byte) (int, error)
    Write(buf []byte) (int, error)
    Close() error
    MTU() int
}

type NetworkConfigurator interface {
    AddRoute(destination, gateway string) error
    RemoveRoute(destination string) error
    SetDNS(servers []string) error
    RestoreDNS() error
}

// infra/tunnel/wintun_adapter.go (Infrastructure layer)
package tunnel

type WinTUNAdapter struct {
    adapter *wintun.Adapter
}

func (w *WinTUNAdapter) Read(buf []byte) (int, error) {
    return w.adapter.Read(buf)
}

// infra/network/windows_configurator.go
type WindowsConfigurator struct {
    originalDNS []string
}

func (w *WindowsConfigurator) AddRoute(dest, gw string) error {
    // Реализация через netsh или Windows API
    return nil
}

// vpnclient/client.go использует интерфейсы
type Client struct {
    tunnel      network.TunnelDevice      // Интерфейс!
    configurator network.NetworkConfigurator // Интерфейс!
}

// Тесты используют mock реализации
type MockTunnel struct {
    readData []byte
}

func (m *MockTunnel) Read(buf []byte) (int, error) {
    copy(buf, m.readData)
    return len(m.readData), nil
}
```

**Преимущества:**
- ✅ VPN клиент тестируется без реального сетевого устройства
- ✅ Легко добавить поддержку других TUN драйверов (OpenVPN TAP, etc.)
- ✅ Можно создать "dry-run" режим для отладки без изменения маршрутов

---

### 3.5 Приоритет 4: Безопасность - шифрование конфигурации

**ДО (config/config.go):**
```go
type Config struct {
    Server       string `json:"server"`
    Username     string `json:"username"`
    Password     string `json:"password"`      // TODO: DPAPI encryption
    PreSharedKey string `json:"pre_shared_key"`
}

func (c *Config) Save() error {
    data, _ := json.Marshal(c)
    return os.WriteFile(configPath, data, 0600)  // Plaintext!
}
```

**ПОСЛЕ (с DPAPI шифрованием):**
```go
package config

import (
    "golang.org/x/sys/windows"
    "encoding/base64"
)

type Config struct {
    Server             string `json:"server"`
    Username           string `json:"username"`
    EncryptedPassword  string `json:"encrypted_password"`   // Base64(DPAPI encrypted)
    EncryptedPSK       string `json:"encrypted_psk"`
    
    // Транзиентные поля (не сохраняются)
    password string `json:"-"`
    psk      string `json:"-"`
}

func (c *Config) SetPassword(password string) error {
    encrypted, err := encryptDPAPI([]byte(password))
    if err != nil {
        return fmt.Errorf("DPAPI encryption failed: %w", err)
    }
    c.EncryptedPassword = base64.StdEncoding.EncodeToString(encrypted)
    c.password = password  // Хранить в памяти только на время сессии
    return nil
}

func (c *Config) GetPassword() (string, error) {
    if c.password != "" {
        return c.password, nil  // Уже в памяти
    }
    
    encrypted, err := base64.StdEncoding.DecodeString(c.EncryptedPassword)
    if err != nil {
        return "", err
    }
    
    plaintext, err := decryptDPAPI(encrypted)
    if err != nil {
        return "", fmt.Errorf("DPAPI decryption failed: %w", err)
    }
    
    c.password = string(plaintext)
    return c.password, nil
}

func encryptDPAPI(plaintext []byte) ([]byte, error) {
    var dataOut windows.DATA_BLOB
    dataIn := windows.DATA_BLOB{
        Size: uint32(len(plaintext)),
        Data: &plaintext[0],
    }
    
    err := windows.CryptProtectData(&dataIn, nil, nil, 0, nil, 
                                    windows.CRYPTPROTECT_UI_FORBIDDEN, &dataOut)
    if err != nil {
        return nil, err
    }
    
    encrypted := make([]byte, dataOut.Size)
    copy(encrypted, unsafe.Slice(dataOut.Data, dataOut.Size))
    windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))
    
    return encrypted, nil
}

func decryptDPAPI(encrypted []byte) ([]byte, error) {
    var dataOut windows.DATA_BLOB
    dataIn := windows.DATA_BLOB{
        Size: uint32(len(encrypted)),
        Data: &encrypted[0],
    }
    
    err := windows.CryptUnprotectData(&dataIn, nil, nil, 0, nil, 
                                      windows.CRYPTPROTECT_UI_FORBIDDEN, &dataOut)
    if err != nil {
        return nil, err
    }
    
    plaintext := make([]byte, dataOut.Size)
    copy(plaintext, unsafe.Slice(dataOut.Data, dataOut.Size))
    windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))
    
    return plaintext, nil
}
```

**Преимущества:**
- ✅ Пароли защищены DPAPI (расшифровать может только тот же пользователь)
- ✅ Не требуется мастер-пароль от пользователя
- ✅ Защита от чтения другими процессами
- ✅ Совместимо с Windows Credential Manager

---

### 3.6 Приоритет 5: Event-driven архитектура вместо polling

**ДО (polling каждые 500мс):**
```go
// gui/app.go
func (a *App) startStatusPoller() {
    ticker := time.NewTicker(500 * time.Millisecond)
    go func() {
        for range ticker.C {
            status, err := a.ipcClient.GetStatus()
            if err == nil {
                a.updateStatusUI(status)
            }
        }
    }()
}
```

**ПОСЛЕ (event-driven с push уведомлениями):**

```go
// ipc/protocol.go (добавить новый тип сообщения)
type StatusUpdate struct {
    Status       VPNStatus
    BytesSent    uint64
    BytesRecv    uint64
    ConnectedAt  time.Time
}

// ipc/server.go (служба отправляет обновления)
type Server struct {
    clients      map[string]*ClientConnection
    statusChan   chan StatusUpdate
}

func (s *Server) BroadcastStatus(status StatusUpdate) {
    for _, client := range s.clients {
        // Отправить всем подключенным GUI клиентам
        client.SendStatusUpdate(status)
    }
}

// vpnclient/client.go (уведомляет IPC сервер)
func (c *Client) onStateChange(newState ConnectionState) {
    update := StatusUpdate{
        Status:      newState,
        BytesSent:   atomic.LoadUint64(&c.bytesSent),
        BytesRecv:   atomic.LoadUint64(&c.bytesRecv),
        ConnectedAt: c.connectedAt,
    }
    c.ipcServer.BroadcastStatus(update)
}

// ipc/client.go (GUI получает push уведомления)
type Client struct {
    conn           net.Conn
    statusHandlers []func(StatusUpdate)
}

func (c *Client) StartListening() {
    go c.listenLoop()
}

func (c *Client) listenLoop() {
    for {
        var update StatusUpdate
        if err := c.readMessage(&update); err != nil {
            break
        }
        // Вызвать зарегистрированные обработчики
        for _, handler := range c.statusHandlers {
            handler(update)
        }
    }
}

func (c *Client) OnStatusUpdate(handler func(StatusUpdate)) {
    c.statusHandlers = append(c.statusHandlers, handler)
}

// gui/app.go (подписка на события)
func (a *App) Run() error {
    // Подписаться на push уведомления
    a.ipcClient.OnStatusUpdate(func(update StatusUpdate) {
        a.mainWindow.Synchronize(func() {
            a.updateStatusUI(update.Status)
            a.updateTrafficUI(update.BytesSent, update.BytesRecv)
        })
    })
    
    a.ipcClient.StartListening()
    return a.mainWindow.Run()
}
```

**Преимущества:**
- ✅ Мгновенное обновление UI (нет задержки 500мс)
- ✅ Снижение нагрузки на IPC (только при изменении статуса)
- ✅ Масштабируемость: множество GUI клиентов без дополнительной нагрузки

---

## 4. План миграции (пошаговый)

### Фаза 1: Подготовка (1 неделя)

**Шаг 1.1:** Создать интерфейсы для существующих компонентов
```
✓ Создать domain/network/interfaces.go
✓ Создать domain/vpn/interfaces.go
✓ Создать domain/crypto/interfaces.go
```

**Шаг 1.2:** Покрыть существующий код тестами
```
✓ Добавить unit-тесты для crypto/
✓ Добавить unit-тесты для protocol/
✓ Добавить интеграционный тест для handshake
```

**Шаг 1.3:** Удалить мертвый код
```
✓ Удалить internal/autostart/ (не используется)
✓ Переместить cmd/sshcmd в отдельный repo
✓ Переместить cmd/testdata в tests/ как integration_test.go
```

---

### Фаза 2: Рефакторинг Infrastructure (2 недели)

**Шаг 2.1:** Рефакторинг VPN клиента
```
День 1-2: Выделить handshake/ пакет
День 3-4: Выделить transport/ пакет
День 5-6: Выделить crypto/session
День 7: Интеграционные тесты
```

**Шаг 2.2:** Рефакторинг tunnel
```
День 8-9: Создать network.TunnelDevice интерфейс
День 10: Обернуть WinTUN в adapter
День 11: Mock тесты для VPN клиента
```

**Шаг 2.3:** Обновить IPC для push уведомлений
```
День 12-13: Добавить StatusUpdate message
День 14: Реализовать broadcast в server
```

---

### Фаза 3: Рефакторинг Application Layer (1.5 недели)

**Шаг 3.1:** Создать Application Services
```
День 1-2: services/vpn/service.go (обертка над IPC)
День 3: services/config/manager.go (с DPAPI)
День 4: services/diagnostics/pinger.go
```

**Шаг 3.2:** Миграция конфигурации
```
День 5: Реализовать DPAPI шифрование
День 6: Скрипт миграции старых конфигов
День 7: Тестирование на разных версиях Windows
```

---

### Фаза 4: Рефакторинг GUI (2 недели)

**Шаг 4.1:** Разделение на компоненты
```
День 1-2: Создать gui/windows/main_window.go
День 3: Создать gui/systray/tray_icon.go
День 4-5: Создать gui/viewmodels/connection_vm.go
День 6: Миграция логики из app.go
```

**Шаг 4.2:** Интеграция event-driven обновлений
```
День 7-8: Подключить OnStatusUpdate callbacks
День 9: Удалить polling логику
День 10: UI тестирование
```

**Шаг 4.3:** Реализация автозапуска (завершить функциональность)
```
День 11: Добавить чекбокс в settings dialog
День 12: Интегрировать autostart пакет
День 13: Логика восстановления последнего соединения
День 14: Тестирование
```

---

### Фаза 5: Тестирование и документация (1 неделя)

```
День 1-2: End-to-end тестирование
День 3: Обновление README с новой архитектурой
День 4: Code review
День 5: Релиз-кандидат
День 6-7: Beta тестирование
```

---

## 5. Метрики улучшения

### Текущие метрики (baseline)

| Метрика | Значение |
|---------|----------|
| **Размер файлов** | |
| Самый большой файл | 671 строка (gui/app.go) |
| Средний размер файла | ~250 строк |
| **Связанность** | |
| Пакеты с circular dependencies | 0 (хорошо) |
| Пакеты с >5 зависимостями | 2 (gui, vpnclient) |
| **Тестирование** | |
| Покрытие тестами | ~30% (только crypto, protocol) |
| Интеграционные тесты | 1 (cmd/testdata) |
| **Безопасность** | |
| Незашифрованные credentials | 2 поля (password, PSK) |
| TODO по безопасности | 1 (DPAPI encryption) |

### Целевые метрики (после рефакторинга)

| Метрика | Целевое значение | Улучшение |
|---------|------------------|-----------|
| **Размер файлов** | |
| Самый большой файл | <300 строк | ✅ -55% |
| Средний размер файла | ~150 строк | ✅ -40% |
| **Связанность** | |
| Пакеты с >5 зависимостями | 0 | ✅ -100% |
| Слои архитектуры | 4 уровня | ✅ +∞ |
| **Тестирование** | |
| Покрытие тестами | >70% | ✅ +133% |
| Интеграционные тесты | 5+ | ✅ +400% |
| Mock-тесты возможны | Да | ✅ |
| **Безопасность** | |
| Незашифрованные credentials | 0 | ✅ -100% |
| TODO по безопасности | 0 | ✅ -100% |

---

## 6. Риски и митигация

| Риск | Вероятность | Воздействие | Митигация |
|------|-------------|-------------|-----------|
| **Регрессия функциональности** | Средняя | Высокое | Создать suite интеграционных тестов до рефакторинга |
| **Производительность IPC** | Низкая | Среднее | Бенчмарки до/после для push notifications |
| **Совместимость с Windows 7** | Средняя | Низкое | Тестировать DPAPI на всех версиях Windows |
| **Сложность миграции конфигов** | Высокая | Среднее | Скрипт миграции + откат к plaintext при ошибке |
| **Увеличение размера кода** | Высокая | Низкое | Это нормально для улучшения архитектуры |

---

## 7. Альтернативные подходы

### 7.1 Альтернатива: Микро-рефакторинг (постепенный)

**Подход:**
- Не делать полный рефакторинг сразу
- Выделять по одному компоненту за итерацию
- Сохранять обратную совместимость

**Плюсы:**
✅ Меньше рисков
✅ Можно релизить после каждой итерации
✅ Легче откатить изменения

**Минусы:**
❌ Временная сложность (старый + новый код одновременно)
❌ Дольше по времени (6+ месяцев вместо 2)
❌ Требует дисциплины команды

**Рекомендация:** Использовать этот подход, если нет возможности остановить разработку новых фич

---

### 7.2 Альтернатива: Переписать с нуля

**Подход:**
- Создать новый проект с чистой архитектурой
- Портировать функциональность постепенно
- Параллельная поддержка старого клиента

**Плюсы:**
✅ Полная свобода в архитектуре
✅ Нет legacy кода
✅ Можно использовать новые фреймворки

**Минусы:**
❌ Очень долго (6-12 месяцев)
❌ Высокий риск незавершенного проекта
❌ Дублирование усилий

**Рекомендация:** НЕ использовать - текущая кодовая база в хорошем состоянии

---

## 8. Выводы и рекомендации

### 8.1 Главные выводы

1. **Архитектура в целом здоровая** 
   - Хорошее разделение на GUI и Service процессы
   - Разумная структура пакетов
   - Нет circular dependencies

2. **Основные проблемы - монолиты**
   - GUI (671 строка) и VPN клиент (633 строки) требуют разделения
   - Смешивание обязанностей внутри файлов
   - Сложность тестирования

3. **Незавершенная функциональность**
   - Autostart пакет не интегрирован
   - DPAPI шифрование не реализовано
   - Тестовые утилиты в продакшен коде

4. **Отсутствие слоевой архитектуры**
   - GUI напрямую зависит от IPC
   - VPN клиент напрямую зависит от WinTUN
   - Нет доменных интерфейсов

---

### 8.2 Рекомендации по приоритетам

#### 🔴 КРИТИЧНО (сделать в первую очередь)

1. **Реализовать DPAPI шифрование паролей** (Приоритет 4)
   - Время: 2-3 дня
   - Риск безопасности: ВЫСОКИЙ
   - Сложность: НИЗКАЯ

2. **Удалить мертвый код** (см. раздел 2.3)
   - Время: 1 день
   - Уменьшение технического долга
   - Нет рисков

#### 🟡 ВАЖНО (сделать в ближайшие 2 месяца)

3. **Разделить GUI на компоненты** (Приоритет 1)
   - Время: 2 недели
   - Улучшает поддерживаемость
   - Средний риск

4. **Рефакторинг VPN клиента** (Приоритет 2)
   - Время: 2 недели
   - Улучшает тестируемость
   - Средний риск

#### 🟢 ЖЕЛАТЕЛЬНО (долгосрочная цель)

5. **Ввести слоевую архитектуру** (Приоритет 3)
   - Время: 3-4 недели
   - Улучшает масштабируемость
   - Низкий риск

6. **Event-driven IPC** (Приоритет 5)
   - Время: 1.5 недели
   - Улучшает UX
   - Низкий риск

---

### 8.3 Следующие шаги

**Немедленно (эта неделя):**
1. ✅ Провести code review с командой
2. ⏳ Получить одобрение на план рефакторинга
3. ⏳ Создать ветку `refactor/clean-architecture`
4. ⏳ Начать с Фазы 1: Подготовка

**Этот месяц:**
1. ⏳ Завершить Фазу 1 (подготовка)
2. ⏳ Завершить Фазу 2 (infrastructure)
3. ⏳ Реализовать DPAPI шифрование

**Следующий месяц:**
1. ⏳ Завершить Фазу 3 (application services)
2. ⏳ Завершить Фазу 4 (GUI рефакторинг)
3. ⏳ Завершить Фазу 5 (тестирование)

---

## Приложение A: Список файлов для удаления/перемещения

### Удалить полностью:

```bash
# Неиспользуемый пакет
rm -rf internal/autostart/

# Тестовая утилита с hardcoded credentials
rm -rf cmd/sshcmd/
```

### Переместить:

```bash
# Интеграционный тест -> test suite
mv cmd/testdata/main.go internal/vpnclient/integration_test.go

# Исправить импорты и преобразовать в тест
```

---

## Приложение B: Дерево целевой структуры проекта

```
vpn-client-windows/
├── cmd/
│   ├── novavpn/              # GUI приложение
│   │   └── main.go
│   ├── novavpn-service/      # Системная служба
│   │   └── main.go
│   └── icongen/              # Build утилита
│       └── main.go
├── internal/
│   ├── domain/               # СЛОЙ 2: Domain интерфейсы
│   │   ├── vpn/
│   │   │   └── interfaces.go
│   │   ├── network/
│   │   │   └── interfaces.go
│   │   └── crypto/
│   │       └── interfaces.go
│   ├── services/             # СЛОЙ 3: Application Services
│   │   ├── vpn/
│   │   │   └── service.go
│   │   ├── config/
│   │   │   ├── manager.go
│   │   │   └── dpapi.go
│   │   └── diagnostics/
│   │       └── pinger.go
│   ├── gui/                  # СЛОЙ 4: Presentation
│   │   ├── app.go
│   │   ├── windows/
│   │   │   ├── main_window.go
│   │   │   └── settings_dialog.go
│   │   ├── viewmodels/
│   │   │   └── connection_vm.go
│   │   └── systray/
│   │       └── tray_icon.go
│   └── infra/                # СЛОЙ 1: Infrastructure
│       ├── vpnclient/
│       │   ├── client.go
│       │   ├── handshake/
│       │   ├── transport/
│       │   ├── crypto/
│       │   └── state/
│       ├── tunnel/
│       │   └── wintun_adapter.go
│       ├── network/
│       │   └── windows_configurator.go
│       ├── crypto/
│       │   └── chacha20.go
│       ├── protocol/
│       │   └── protocol.go
│       ├── ipc/
│       │   ├── client.go
│       │   ├── server.go
│       │   └── protocol.go
│       └── platform/
│           ├── service/
│           ├── registry/
│           └── elevation/
├── tests/
│   ├── integration/
│   │   └── handshake_test.go
│   └── e2e/
│       └── vpn_connection_test.go
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## Приложение C: Checklist для ревью кода

При code review использовать этот checklist:

### Архитектура

- [ ] Компонент принадлежит правильному слою?
- [ ] Зависимости направлены только вниз (верхние → нижние слои)?
- [ ] Используются интерфейсы для инфраструктурных зависимостей?
- [ ] Нет circular dependencies?

### Код

- [ ] Файл < 300 строк?
- [ ] Функция < 50 строк?
- [ ] Один тип = одна обязанность?
- [ ] Публичные функции документированы?

### Безопасность

- [ ] Нет plaintext credentials?
- [ ] Используется DPAPI для sensitive data?
- [ ] Криптографические ключи очищаются через `ZeroKey()`?
- [ ] Нет hardcoded паролей/токенов?

### Тестирование

- [ ] Unit-тесты покрывают публичные функции?
- [ ] Используются mock объекты для внешних зависимостей?
- [ ] Интеграционные тесты для критичных сценариев?

### Performance

- [ ] Нет горутин без graceful shutdown?
- [ ] Каналы имеют буферы где необходимо?
- [ ] Используются sync.Pool для частых аллокаций?
- [ ] Atomic операции для shared state?

---

**Конец отчета**

---

**Автор:** GitHub Copilot Agent  
**Контакт:** <repository maintainer>  
**Дата следующего ревью:** После завершения Фазы 1 (через 1 неделю)
