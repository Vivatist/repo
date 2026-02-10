// Package gui — графический интерфейс клиента NovaVPN (Walk + системный трей).
package gui

import (
	"fmt"
	"log"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"github.com/novavpn/vpn-client-windows/internal/autostart"
	"github.com/novavpn/vpn-client-windows/internal/config"
	"github.com/novavpn/vpn-client-windows/internal/vpnclient"
)

// App — главное GUI-приложение.
type App struct {
	cfg    *config.Config
	client *vpnclient.Client

	mainWindow   *walk.MainWindow
	notifyIcon   *walk.NotifyIcon
	serverEdit   *walk.LineEdit
	pskEdit      *walk.LineEdit
	emailEdit    *walk.LineEdit
	passwordEdit *walk.LineEdit
	connectBtn   *walk.PushButton
	statusLabel  *walk.Label
	statsLabel   *walk.Label
	autoStartCB  *walk.CheckBox

	// Иконки
	iconDisconnected *walk.Icon
	iconConnecting   *walk.Icon
	iconConnected    *walk.Icon

	statsTimer *time.Ticker
	stopStats  chan struct{}
}

// NewApp создаёт приложение.
func NewApp() *App {
	app := &App{
		cfg:       config.Load(),
		stopStats: make(chan struct{}),
	}
	app.client = vpnclient.NewClient(app.onStateChanged)
	return app
}

// Run запускает GUI.
func (a *App) Run(autoConnect bool) error {
	// Создаём иконки-щиты
	a.iconDisconnected, a.iconConnecting, a.iconConnected = makeShieldIcons()

	// Создаём главное окно
	if err := a.createMainWindow(); err != nil {
		return err
	}

	// Создаём иконку в трее
	if err := a.createTrayIcon(); err != nil {
		return err
	}

	// Загружаем настройки в форму
	a.loadSettingsToForm()

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
		MinSize:  Size{400, 380},
		MaxSize:  Size{400, 380},
		Size:     Size{400, 380},
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

			// Автозапуск
			CheckBox{
				AssignTo: &a.autoStartCB,
				Text:     "Запускать при старте Windows",
				OnCheckedChanged: func() {
					a.cfg.AutoStart = a.autoStartCB.Checked()
					if a.cfg.AutoStart {
						autostart.Enable()
					} else {
						autostart.Disable()
					}
					a.saveSettings()
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
	a.autoStartCB.SetChecked(a.cfg.AutoStart)
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
	if a.client.GetState() == vpnclient.StateConnected {
		go a.disconnect()
	} else if a.client.GetState() == vpnclient.StateDisconnected {
		go a.connect()
	}
}

// connect подключается к VPN.
func (a *App) connect() {
	a.saveSettings()

	if a.cfg.ServerAddr == "" || a.cfg.PSK == "" || a.cfg.Email == "" || a.cfg.Password == "" {
		a.mainWindow.Synchronize(func() {
			walk.MsgBox(a.mainWindow, "NovaVPN", "Заполните все поля", walk.MsgBoxIconWarning)
		})
		return
	}

	params := vpnclient.ConnectParams{
		ServerAddr: a.cfg.ServerAddr,
		PSK:        a.cfg.PSK,
		Email:      a.cfg.Email,
		Password:   a.cfg.Password,
	}

	if err := a.client.Connect(params); err != nil {
		a.mainWindow.Synchronize(func() {
			walk.MsgBox(a.mainWindow, "Ошибка подключения", err.Error(), walk.MsgBoxIconError)
		})
		return
	}

	// Сохраняем состояние подключения
	a.cfg.WasConnected = true
	a.cfg.Save()
}

// disconnect отключается от VPN.
func (a *App) disconnect() {
	a.client.Disconnect()
	a.cfg.WasConnected = false
	a.cfg.Save()
}

// onExit — выход из приложения.
func (a *App) onExit() {
	// Если подключён — сохраняем состояние
	if a.client.GetState() == vpnclient.StateConnected {
		a.cfg.WasConnected = true
		a.cfg.Save()
		a.client.Disconnect()
	}

	a.notifyIcon.Dispose()
	a.mainWindow.Dispose()
	walk.App().Exit(0)
}

// onStateChanged — колбэк при смене состояния VPN.
func (a *App) onStateChanged(state vpnclient.ConnectionState, info string) {
	a.mainWindow.Synchronize(func() {
		switch state {
		case vpnclient.StateDisconnected:
			a.statusLabel.SetText("● Отключён")
			a.statusLabel.SetTextColor(walk.RGB(180, 0, 0))
			a.connectBtn.SetText("Подключиться")
			a.connectBtn.SetEnabled(true)
			a.setFieldsEnabled(true)
			a.notifyIcon.SetToolTip("NovaVPN — Отключён")
			if a.iconDisconnected != nil {
				a.notifyIcon.SetIcon(a.iconDisconnected)
			}
			a.stopStatsUpdate()
			a.statsLabel.SetText("")

		case vpnclient.StateConnecting:
			a.statusLabel.SetText("● Подключение...")
			a.statusLabel.SetTextColor(walk.RGB(200, 150, 0))
			a.connectBtn.SetText("Подключение...")
			a.connectBtn.SetEnabled(false)
			a.setFieldsEnabled(false)
			a.notifyIcon.SetToolTip("NovaVPN — Подключение...")
			if a.iconConnecting != nil {
				a.notifyIcon.SetIcon(a.iconConnecting)
			}

		case vpnclient.StateConnected:
			text := "● Подключён"
			if info != "" {
				text += " (" + info + ")"
			}
			a.statusLabel.SetText(text)
			a.statusLabel.SetTextColor(walk.RGB(0, 150, 0))
			a.connectBtn.SetText("Отключиться")
			a.connectBtn.SetEnabled(true)
			a.setFieldsEnabled(false)
			tooltip := "NovaVPN — Подключён"
			if info != "" {
				tooltip += "\n" + info
			}
			a.notifyIcon.SetToolTip(tooltip)
			if a.iconConnected != nil {
				a.notifyIcon.SetIcon(a.iconConnected)
			}
			a.notifyIcon.ShowInfo("NovaVPN", "VPN подключён")
			a.startStatsUpdate()

		case vpnclient.StateDisconnecting:
			a.statusLabel.SetText("● Отключение...")
			a.statusLabel.SetTextColor(walk.RGB(200, 150, 0))
			a.connectBtn.SetEnabled(false)
		}
	})
}

// setFieldsEnabled включает/отключает поля формы.
func (a *App) setFieldsEnabled(enabled bool) {
	a.serverEdit.SetEnabled(enabled)
	a.pskEdit.SetEnabled(enabled)
	a.emailEdit.SetEnabled(enabled)
	a.passwordEdit.SetEnabled(enabled)
}

// startStatsUpdate запускает обновление статистики.
func (a *App) startStatsUpdate() {
	a.statsTimer = time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-a.stopStats:
				return
			case <-a.statsTimer.C:
				sent := a.client.BytesSent.Load()
				recv := a.client.BytesRecv.Load()
				a.mainWindow.Synchronize(func() {
					a.statsLabel.SetText(fmt.Sprintf("↑ %s   ↓ %s",
						formatBytes(sent), formatBytes(recv)))
				})
			}
		}
	}()
}

// stopStatsUpdate останавливает обновление статистики.
func (a *App) stopStatsUpdate() {
	if a.statsTimer != nil {
		a.statsTimer.Stop()
		select {
		case a.stopStats <- struct{}{}:
		default:
		}
	}
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
