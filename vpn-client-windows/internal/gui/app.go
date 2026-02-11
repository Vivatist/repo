// Package gui — графический интерфейс клиента NovaVPN (Walk + системный трей).
// GUI работает без прав администратора. Все привилегированные операции
// (TUN, маршруты) выполняются через Windows-сервис NovaVPN по IPC.
package gui

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/novavpn/vpn-client-windows/internal/config"
	"github.com/novavpn/vpn-client-windows/internal/elevation"
	"github.com/novavpn/vpn-client-windows/internal/ipc"
)

// App — главное GUI-приложение.
type App struct {
	cfg       *config.Config
	ipcClient *ipc.Client

	mainWindow         *walk.MainWindow
	notifyIcon         *walk.NotifyIcon
	serverEdit         *walk.LineEdit
	pskEdit            *walk.LineEdit
	emailEdit          *walk.LineEdit
	passwordEdit       *walk.LineEdit
	connectBtn         *walk.PushButton
	statusLabel        *walk.Label
	statsLabel         *walk.Label
	serviceStatusLabel *walk.Label

	// Иконки
	iconDisconnected *walk.Icon
	iconConnecting   *walk.Icon
	iconConnected    *walk.Icon

	// Поллинг статуса через IPC
	stopPoll  chan struct{}
	lastState int // предыдущее состояние для отслеживания изменений
}

// NewApp создаёт приложение.
func NewApp() *App {
	return &App{
		cfg:       config.Load(),
		ipcClient: ipc.NewClient(),
		stopPoll:  make(chan struct{}),
		lastState: -1,
	}
}

// Run запускает GUI.
func (a *App) Run(autoConnect bool) error {
	// Создаём иконки-щиты
	a.iconDisconnected, a.iconConnecting, a.iconConnected = makeShieldIcons()

	// Создаём главное окно
	if err := a.createMainWindow(); err != nil {
		return err
	}

	// Устанавливаем иконку приложения (logo.svg)
	if icon := loadAppIcon(); icon != nil {
		a.mainWindow.SetIcon(icon)
	}

	// Создаём иконку в трее
	if err := a.createTrayIcon(); err != nil {
		return err
	}

	// Загружаем настройки в форму
	a.loadSettingsToForm()

	// Запускаем поллинг статуса от сервиса
	go a.pollStatusLoop()

	// Автоподключение
	if autoConnect && a.cfg.WasConnected && a.cfg.ServerAddr != "" {
		log.Println("[GUI] Автоподключение...")
		go a.connect()
	}

	// Если автостарт — сразу в трей
	if autoConnect {
		a.mainWindow.SetVisible(false)
	}

	a.mainWindow.Run()
	return nil
}

// createMainWindow создаёт главное окно.
func (a *App) createMainWindow() error {
	err := MainWindow{
		AssignTo: &a.mainWindow,
		Title:    "NovaVPN",
		MinSize:  Size{400, 420},
		MaxSize:  Size{400, 420},
		Size:     Size{400, 420},
		Layout:   VBox{MarginsZero: false, Margins: Margins{10, 10, 10, 10}},
		Children: []Widget{
			// Заголовок
			Label{Text: "NovaVPN Client", Font: Font{Bold: true, PointSize: 14}},
			VSpacer{Size: 5},

			// Статус
			Label{
				AssignTo:  &a.statusLabel,
				Text:      "● Отключён",
				Font:      Font{PointSize: 10},
				TextColor: walk.RGB(180, 0, 0),
			},
			Label{
				AssignTo: &a.statsLabel,
				Text:     "",
				Font:     Font{PointSize: 8},
			},
			VSpacer{Size: 5},

			// Настройки
			GroupBox{
				Title:  "Настройки подключения",
				Layout: Grid{Columns: 2, Spacing: 5},
				Children: []Widget{
					Label{Text: "Сервер:"},
					LineEdit{AssignTo: &a.serverEdit, CueBanner: "212.118.43.43:51820"},

					Label{Text: "PSK:"},
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 2},
						Children: []Widget{
							LineEdit{AssignTo: &a.pskEdit},
							PushButton{
								Text:    "📋",
								MaxSize: Size{Width: 30},
								OnClicked: func() {
									if txt := a.pskEdit.Text(); txt != "" {
										walk.Clipboard().SetText(txt)
									}
								},
							},
						},
					},

					Label{Text: "Email:"},
					LineEdit{AssignTo: &a.emailEdit, CueBanner: "user@example.com"},

					Label{Text: "Пароль:"},
					LineEdit{AssignTo: &a.passwordEdit, PasswordMode: true},
				},
			},
			VSpacer{Size: 5},

			// Кнопка подключения
			PushButton{
				AssignTo:  &a.connectBtn,
				Text:      "Подключиться",
				MinSize:   Size{0, 40},
				Font:      Font{PointSize: 11, Bold: true},
				OnClicked: a.onConnectClicked,
			},

			// Индикатор статуса сервиса
			Label{
				AssignTo:  &a.serviceStatusLabel,
				Text:      "",
				Font:      Font{PointSize: 8},
				TextColor: walk.RGB(128, 128, 128),
			},
		},
	}.Create()
	if err != nil {
		return err
	}

	// Подписка на событие закрытия окна (сворачиваем в трей вместо закрытия)
	a.mainWindow.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		*canceled = true
		a.mainWindow.SetVisible(false)
	})

	return nil
}

// createTrayIcon создаёт иконку в системном трее.
func (a *App) createTrayIcon() error {
	var err error
	a.notifyIcon, err = walk.NewNotifyIcon(a.mainWindow)
	if err != nil {
		return err
	}

	a.notifyIcon.SetToolTip("NovaVPN — Отключён")
	a.notifyIcon.SetVisible(true)

	if a.iconDisconnected != nil {
		a.notifyIcon.SetIcon(a.iconDisconnected)
	}

	// Двойной клик — показать окно
	a.notifyIcon.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			a.showWindow()
		}
	})

	// Контекстное меню (ContextMenu() уже создано при инициализации NotifyIcon)
	menu := a.notifyIcon.ContextMenu()

	connectAction := walk.NewAction()
	connectAction.SetText("Подключить")
	connectAction.Triggered().Attach(func() {
		go a.connect()
	})
	menu.Actions().Add(connectAction)

	disconnectAction := walk.NewAction()
	disconnectAction.SetText("Отключить")
	disconnectAction.Triggered().Attach(func() {
		go a.disconnect()
	})
	menu.Actions().Add(disconnectAction)

	separator := walk.NewSeparatorAction()
	menu.Actions().Add(separator)

	showAction := walk.NewAction()
	showAction.SetText("Настройки")
	showAction.Triggered().Attach(func() {
		a.showWindow()
	})
	menu.Actions().Add(showAction)

	separator2 := walk.NewSeparatorAction()
	menu.Actions().Add(separator2)

	exitAction := walk.NewAction()
	exitAction.SetText("Выход")
	exitAction.Triggered().Attach(func() {
		a.onExit()
	})
	menu.Actions().Add(exitAction)
	return nil
}

// showWindow показывает главное окно.
func (a *App) showWindow() {
	a.mainWindow.SetVisible(true)
	a.mainWindow.Activate()
}

// loadSettingsToForm заполняет форму сохранёнными настройками.
func (a *App) loadSettingsToForm() {
	a.serverEdit.SetText(a.cfg.ServerAddr)
	a.pskEdit.SetText(a.cfg.PSK)
	a.emailEdit.SetText(a.cfg.Email)
	a.passwordEdit.SetText(a.cfg.Password)
}

// saveSettings сохраняет текущие настройки из формы.
func (a *App) saveSettings() {
	a.cfg.ServerAddr = a.serverEdit.Text()
	a.cfg.PSK = a.pskEdit.Text()
	a.cfg.Email = a.emailEdit.Text()
	a.cfg.Password = a.passwordEdit.Text()
	if err := a.cfg.Save(); err != nil {
		log.Printf("[GUI] Ошибка сохранения настроек: %v", err)
	}
}

// onConnectClicked — обработчик кнопки подключения.
func (a *App) onConnectClicked() {
	if a.lastState == ipc.StateConnected {
		go a.disconnect()
	} else if a.lastState == ipc.StateConnecting || a.lastState == ipc.StateDisconnecting {
		// Игнорируем нажатие во время переходных состояний
		return
	} else {
		// StateDisconnected, -1 (начальное), -2 (сервис недоступен) — всё ведёт к connect()
		// connect() сам проверит доступность сервиса и предложит установку
		go a.connect()
	}
}

// connect подключается к VPN через сервис.
func (a *App) connect() {
	a.saveSettings()

	if a.cfg.ServerAddr == "" || a.cfg.PSK == "" || a.cfg.Email == "" || a.cfg.Password == "" {
		a.mainWindow.Synchronize(func() {
			walk.MsgBox(a.mainWindow, "NovaVPN", "Заполните все поля", walk.MsgBoxIconWarning)
		})
		return
	}

	// Проверяем, доступен ли сервис
	if !a.ipcClient.IsServiceRunning() {
		a.mainWindow.Synchronize(func() {
			result := walk.MsgBox(a.mainWindow, "NovaVPN",
				"Сервис NovaVPN не запущен.\n\nУстановить и запустить сервис?\n(Потребуется подтверждение UAC)",
				walk.MsgBoxOKCancel|walk.MsgBoxIconQuestion)
			if result == walk.DlgCmdOK {
				go a.installAndStartService()
			}
		})
		return
	}

	// Показываем "Подключение..." сразу
	a.mainWindow.Synchronize(func() {
		a.statusLabel.SetText("● Подключение...")
		a.statusLabel.SetTextColor(walk.RGB(200, 150, 0))
		a.connectBtn.SetText("Подключение...")
		a.connectBtn.SetEnabled(false)
		a.setFieldsEnabled(false)
	})

	params := ipc.ConnectParams{
		ServerAddr: a.cfg.ServerAddr,
		PSK:        a.cfg.PSK,
		Email:      a.cfg.Email,
		Password:   a.cfg.Password,
	}

	if err := a.ipcClient.Connect(params); err != nil {
		a.mainWindow.Synchronize(func() {
			walk.MsgBox(a.mainWindow, "Ошибка подключения", err.Error(), walk.MsgBoxIconError)
			a.updateUIForState(ipc.StateDisconnected, "")
		})
		return
	}

	// Сохраняем состояние подключения
	a.cfg.WasConnected = true
	a.cfg.Save()
}

// disconnect отключается от VPN через сервис.
func (a *App) disconnect() {
	a.ipcClient.Disconnect()
	a.cfg.WasConnected = false
	a.cfg.Save()
}

// onExit — выход из приложения.
func (a *App) onExit() {
	// Останавливаем поллинг
	close(a.stopPoll)

	// Если подключён — отключаем через сервис
	if a.lastState == ipc.StateConnected {
		a.cfg.WasConnected = true
		a.cfg.Save()
		a.ipcClient.Disconnect()
	}

	a.notifyIcon.Dispose()
	a.mainWindow.Dispose()
	walk.App().Exit(0)
}

// pollStatusLoop — цикл опроса статуса VPN через IPC.
// Обновляет GUI на основе ответов от сервиса.
func (a *App) pollStatusLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopPoll:
			return
		case <-ticker.C:
			status, err := a.ipcClient.GetStatus()
			if err != nil {
				// Сервис недоступен
				if a.lastState != -2 {
					a.lastState = -2
					a.mainWindow.Synchronize(func() {
						a.statusLabel.SetText("● Сервис недоступен")
						a.statusLabel.SetTextColor(walk.RGB(128, 128, 128))
						a.connectBtn.SetText("Подключиться")
						a.connectBtn.SetEnabled(true)
						a.setFieldsEnabled(true)
						a.statsLabel.SetText("")
						a.notifyIcon.SetToolTip("NovaVPN — Сервис недоступен")
						a.serviceStatusLabel.SetText("Сервис NovaVPN не запущен")
						a.serviceStatusLabel.SetTextColor(walk.RGB(180, 0, 0))
						if a.iconDisconnected != nil {
							a.notifyIcon.SetIcon(a.iconDisconnected)
						}
					})
				}
				continue
			}

			// Обновляем UI если состояние изменилось
			if status.State != a.lastState {
				a.lastState = status.State
				a.mainWindow.Synchronize(func() {
					a.updateUIForState(status.State, status.AssignedIP)
					a.serviceStatusLabel.SetText("Сервис NovaVPN запущен")
					a.serviceStatusLabel.SetTextColor(walk.RGB(0, 128, 0))
				})
			}

			// Обновляем статистику если подключены
			if status.State == ipc.StateConnected {
				a.mainWindow.Synchronize(func() {
					a.statsLabel.SetText(fmt.Sprintf("↑ %s   ↓ %s",
						formatBytes(status.BytesSent), formatBytes(status.BytesRecv)))
				})
			}
		}
	}
}

// updateUIForState обновляет все элементы GUI для заданного состояния.
func (a *App) updateUIForState(state int, assignedIP string) {
	switch state {
	case ipc.StateDisconnected:
		a.statusLabel.SetText("● Отключён")
		a.statusLabel.SetTextColor(walk.RGB(180, 0, 0))
		a.connectBtn.SetText("Подключиться")
		a.connectBtn.SetEnabled(true)
		a.setFieldsEnabled(true)
		a.notifyIcon.SetToolTip("NovaVPN — Отключён")
		if a.iconDisconnected != nil {
			a.notifyIcon.SetIcon(a.iconDisconnected)
		}
		a.statsLabel.SetText("")

	case ipc.StateConnecting:
		a.statusLabel.SetText("● Подключение...")
		a.statusLabel.SetTextColor(walk.RGB(200, 150, 0))
		a.connectBtn.SetText("Подключение...")
		a.connectBtn.SetEnabled(false)
		a.setFieldsEnabled(false)
		a.notifyIcon.SetToolTip("NovaVPN — Подключение...")
		if a.iconConnecting != nil {
			a.notifyIcon.SetIcon(a.iconConnecting)
		}

	case ipc.StateConnected:
		text := "● Подключён"
		if assignedIP != "" {
			text += " (VPN IP: " + assignedIP + ")"
		}
		a.statusLabel.SetText(text)
		a.statusLabel.SetTextColor(walk.RGB(0, 150, 0))
		a.connectBtn.SetText("Отключиться")
		a.connectBtn.SetEnabled(true)
		a.setFieldsEnabled(false)
		tooltip := "NovaVPN — Подключён"
		if assignedIP != "" {
			tooltip += "\nVPN IP: " + assignedIP
		}
		a.notifyIcon.SetToolTip(tooltip)
		if a.iconConnected != nil {
			a.notifyIcon.SetIcon(a.iconConnected)
		}

	case ipc.StateDisconnecting:
		a.statusLabel.SetText("● Отключение...")
		a.statusLabel.SetTextColor(walk.RGB(200, 150, 0))
		a.connectBtn.SetEnabled(false)
	}
}

// setFieldsEnabled включает/отключает поля формы.
func (a *App) setFieldsEnabled(enabled bool) {
	a.serverEdit.SetEnabled(enabled)
	a.pskEdit.SetEnabled(enabled)
	a.emailEdit.SetEnabled(enabled)
	a.passwordEdit.SetEnabled(enabled)
}

// installAndStartService устанавливает и запускает сервис NovaVPN с UAC elevation.
func (a *App) installAndStartService() {
	exe, err := os.Executable()
	if err != nil {
		a.mainWindow.Synchronize(func() {
			walk.MsgBox(a.mainWindow, "Ошибка", "Не удалось определить путь: "+err.Error(), walk.MsgBoxIconError)
		})
		return
	}

	serviceExe := filepath.Join(filepath.Dir(exe), "novavpn-service.exe")

	// Проверяем наличие файла сервиса
	if _, err := os.Stat(serviceExe); os.IsNotExist(err) {
		a.mainWindow.Synchronize(func() {
			walk.MsgBox(a.mainWindow, "Ошибка",
				"Файл novavpn-service.exe не найден.\nУбедитесь, что он находится рядом с NovaVPN.exe",
				walk.MsgBoxIconError)
		})
		return
	}

	log.Println("[GUI] Запуск установки сервиса с UAC...")

	// Запускаем установку с UAC (одна команда: install + start)
	if err := elevation.RunElevated(serviceExe, "install"); err != nil {
		a.mainWindow.Synchronize(func() {
			walk.MsgBox(a.mainWindow, "Ошибка",
				"Не удалось установить сервис.\nВозможно, вы отменили запрос UAC.",
				walk.MsgBoxIconError)
		})
		return
	}

	// Ждём пока сервис станет доступен
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		if a.ipcClient.IsServiceRunning() {
			log.Println("[GUI] Сервис установлен и запущен")
			a.mainWindow.Synchronize(func() {
				walk.MsgBox(a.mainWindow, "NovaVPN",
					"Сервис NovaVPN установлен и запущен!\nТеперь вы можете подключиться.",
					walk.MsgBoxIconInformation)
			})
			return
		}
	}

	a.mainWindow.Synchronize(func() {
		walk.MsgBox(a.mainWindow, "Ошибка",
			"Сервис установлен, но не удалось дождаться его запуска.\nПопробуйте запустить вручную.",
			walk.MsgBoxIconWarning)
	})
}

// formatBytes форматирует байты в человекочитаемый формат.
func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f ГБ", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f МБ", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f КБ", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d Б", b)
	}
}
