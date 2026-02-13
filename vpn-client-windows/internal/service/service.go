//go:build windows

// Package service управляет Windows-сервисом NovaVPN.
//
// Предоставляет установку/удаление/запуск/остановку сервиса через
// Windows Service Control Manager, а также запуск в режиме сервиса.
package service

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/novavpn/vpn-client-windows/internal/application/vpnservice"
	domainvpn "github.com/novavpn/vpn-client-windows/internal/domain/vpn"
	infraipc "github.com/novavpn/vpn-client-windows/internal/infrastructure/ipc"
)

const serviceName = "NovaVPN"

// novaVPNService реализует интерфейс svc.Handler.
type novaVPNService struct{}

// Windows power event constants (PBT_*)
const (
	pbtAPMSuspend         = 0x04 // система переходит в спящий режим
	pbtAPMResumeAutomatic = 0x12 // система возобновлена автоматически
	pbtAPMResumeSuspend   = 0x07 // система возобновлена пользователем
)

// Execute — основной цикл Windows-сервиса.
func (s *novaVPNService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent

	changes <- svc.Status{State: svc.StartPending}

	// Создаём VPN service
	vpnSvc, err := vpnservice.NewService()
	if err != nil {
		log.Printf("[SERVICE] Ошибка создания VPN service: %v", err)
		changes <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	// Создаём IPC-сервер
	ipcServer := infraipc.NewNamedPipeServer()
	ipcServer.SetHandler(func(req map[string]interface{}) map[string]interface{} {
		return handleIPCRequest(vpnSvc, req)
	})

	// Запускаем IPC-сервер
	go func() {
		if err := ipcServer.Start(); err != nil {
			log.Printf("[SERVICE] Ошибка IPC-сервера: %v", err)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Println("[SERVICE] Сервис запущен")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				log.Println("[SERVICE] Останавливаем сервис...")

				// Отключаем VPN если подключён
				if vpnSvc.GetState() == domainvpn.StateConnected {
					vpnSvc.Disconnect()
				}

				// Останавливаем IPC
				ipcServer.Stop()

				return false, 0
			case svc.PowerEvent:
				switch c.EventType {
				case pbtAPMSuspend:
					log.Println("[SERVICE] Система переходит в спящий режим")
				case pbtAPMResumeAutomatic, pbtAPMResumeSuspend:
					log.Println("[SERVICE] Система возобновлена из спящего режима")
					// Если VPN был подключён, принудительно переподключаем:
					// после sleep UDP-сокет мёртв, но клиент может этого не знать
					if vpnSvc.GetState() == domainvpn.StateConnected {
						log.Println("[SERVICE] Переподключение VPN после resume...")
						go func() {
							params := vpnSvc.GetConnectParams()
							if err := vpnSvc.Disconnect(); err != nil {
								log.Printf("[SERVICE] Ошибка отключения после resume: %v", err)
							}
							// Небольшая пауза для восстановления сети
							time.Sleep(2 * time.Second)
							if err := vpnSvc.Connect(params); err != nil {
								log.Printf("[SERVICE] Ошибка переподключения после resume: %v", err)
							}
						}()
					}
				}
			}
		}
	}
}

// handleIPCRequest обрабатывает IPC-запросы от GUI.
func handleIPCRequest(vpnSvc *vpnservice.Service, req map[string]interface{}) map[string]interface{} {
	reqType, _ := req["type"].(string)

	switch reqType {
	case "connect":
		payload, _ := req["payload"].(map[string]interface{})
		if payload == nil {
			return map[string]interface{}{"type": "error", "error": "missing payload"}
		}

		params := domainvpn.ConnectParams{
			ServerAddr: fmt.Sprintf("%v", payload["server_addr"]),
			Email:      fmt.Sprintf("%v", payload["email"]),
			Password:   fmt.Sprintf("%v", payload["password"]),
			PSK:        fmt.Sprintf("%v", payload["psk"]),
		}

		if err := vpnSvc.Connect(params); err != nil {
			return map[string]interface{}{"type": "error", "error": err.Error()}
		}
		return map[string]interface{}{"type": "ok"}

	case "disconnect":
		if err := vpnSvc.Disconnect(); err != nil {
			return map[string]interface{}{"type": "error", "error": err.Error()}
		}
		return map[string]interface{}{"type": "ok"}

	case "get_status":
		state := vpnSvc.GetState()
		stats := vpnSvc.GetStatistics()
		info := vpnSvc.GetInfo()

		payload := map[string]interface{}{
			"state":        int(state),
			"state_text":   state.String(),
			"bytes_sent":   stats.BytesSent,
			"bytes_recv":   stats.BytesRecv,
			"packets_sent": stats.PacketsSent,
			"packets_recv": stats.PacketsRecv,
		}

		if info.AssignedIP != nil {
			payload["assigned_ip"] = info.AssignedIP.String()
		}

		return map[string]interface{}{"type": "status", "payload": payload}

	default:
		return map[string]interface{}{"type": "error", "error": "unknown request type"}
	}
}

// IsRunningAsService проверяет, запущен ли процесс как Windows-сервис.
func IsRunningAsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

// RunService запускает процесс в режиме Windows-сервиса.
func RunService() error {
	// Настраиваем логирование в файл
	logDir := filepath.Join(os.Getenv("ProgramData"), "NovaVPN")
	os.MkdirAll(logDir, 0755)
	logFile, err := os.OpenFile(
		filepath.Join(logDir, "service.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	log.Println("[SERVICE] Запуск Windows-сервиса NovaVPN...")
	return svc.Run(serviceName, &novaVPNService{})
}

// Install устанавливает Windows-сервис.
func Install(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	// Проверяем, не установлен ли уже
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("сервис %s уже установлен", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: "NovaVPN VPN Service",
		Description: "NovaVPN — VPN-клиент с собственным протоколом",
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	log.Printf("[SERVICE] Сервис %s установлен: %s", serviceName, exePath)
	return nil
}

// Uninstall удаляет Windows-сервис.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	// Останавливаем если запущен
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	log.Printf("[SERVICE] Сервис %s удалён", serviceName)
	return nil
}

// Start запускает Windows-сервис.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	return nil
}

// Stop останавливает Windows-сервис.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("stop service: %w", err)
	}

	return nil
}

// IsInstalled проверяет, установлен ли сервис.
func IsInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// IsRunning проверяет, запущен ли сервис.
func IsRunning() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false
	}

	return status.State == svc.Running
}
