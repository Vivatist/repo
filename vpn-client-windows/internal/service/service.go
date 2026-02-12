//go:build windows

// Package service реализует Windows-сервис NovaVPN.
// Сервис работает с SYSTEM-привилегиями, управляет TUN-адаптером,
// маршрутами и VPN-подключением. GUI общается с сервисом через IPC (Named Pipe).
package service

import (
	"log"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows/svc"

	"github.com/novavpn/vpn-client-windows/internal/ipc"
	"github.com/novavpn/vpn-client-windows/internal/vpnclient"
)

// ServiceName — имя Windows-сервиса.
const ServiceName = "NovaVPN"

// ServiceDisplayName — отображаемое имя сервиса.
const ServiceDisplayName = "NovaVPN VPN Service"

// ServiceDescription — описание сервиса.
const ServiceDescription = "Управляет VPN-подключениями NovaVPN. Обеспечивает работу TUN-адаптера и маршрутизации."

// novaVPNService — реализация интерфейса svc.Handler.
type novaVPNService struct {
	client      *vpnclient.Client
	ipcServer   *ipc.Server
	mu          sync.Mutex
	pskMu       sync.Mutex // отдельный мьютекс для PSK (избегаем deadlock)
	receivedPSK string     // PSK полученный при bootstrap-подключении
}

// Execute — основной цикл Windows-сервиса.
func (s *novaVPNService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Настраиваем логирование в ProgramData
	setupServiceLogging()

	log.Println("[SERVICE] NovaVPN Service запускается...")

	// Создаём VPN-клиент
	s.client = vpnclient.NewClient(func(state vpnclient.ConnectionState, info string) {
		log.Printf("[SERVICE] Состояние VPN: %s (%s)", state, info)
	}, func(pskHex string) {
		s.pskMu.Lock()
		s.receivedPSK = pskHex
		s.pskMu.Unlock()
		log.Printf("[SERVICE] Получен PSK от сервера (bootstrap)")
	})

	// Запускаем IPC-сервер
	s.ipcServer = ipc.NewServer(s.handleConnect, s.handleDisconnect, s.handleStatus)
	if err := s.ipcServer.Start(); err != nil {
		log.Printf("[SERVICE] Ошибка запуска IPC: %v", err)
		changes <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Println("[SERVICE] NovaVPN Service запущен и ожидает команд")

	// Ожидаем команд от SCM
	for {
		c := <-r
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			log.Println("[SERVICE] Получена команда остановки...")

			// Отключаем VPN
			s.client.Disconnect()

			// Останавливаем IPC
			s.ipcServer.Stop()

			log.Println("[SERVICE] NovaVPN Service остановлен")
			return false, 0

		case svc.Interrogate:
			changes <- c.CurrentStatus
		}
	}
}

// handleConnect — обработчик IPC-команды подключения.
func (s *novaVPNService) handleConnect(params ipc.ConnectParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Printf("[SERVICE] Команда Connect: сервер=%s, email=%s", params.ServerAddr, params.Email)

	return s.client.Connect(vpnclient.ConnectParams{
		ServerAddr: params.ServerAddr,
		PSK:        params.PSK,
		Email:      params.Email,
		Password:   params.Password,
	})
}

// handleDisconnect — обработчик IPC-команды отключения.
func (s *novaVPNService) handleDisconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Println("[SERVICE] Команда Disconnect")
	s.client.Disconnect()
}

// handleStatus — обработчик IPC-запроса статуса.
func (s *novaVPNService) handleStatus() ipc.StatusInfo {
	s.pskMu.Lock()
	psk := s.receivedPSK
	s.pskMu.Unlock()

	state := s.client.GetState()
	status := ipc.StatusInfo{
		State:       int(state),
		StateText:   state.String(),
		ReceivedPSK: psk,
		BytesSent:   s.client.BytesSent.Load(),
		BytesRecv:   s.client.BytesRecv.Load(),
		PacketsSent: s.client.PacketsSent.Load(),
		PacketsRecv: s.client.PacketsRecv.Load(),
	}
	if ip := s.client.GetAssignedIP(); ip != nil {
		status.AssignedIP = ip.String()
	}
	return status
}

// RunService запускает NovaVPN как Windows-сервис (вызывается SCM).
func RunService() error {
	return svc.Run(ServiceName, &novaVPNService{})
}

// IsRunningAsService определяет, запущен ли процесс как Windows-сервис.
func IsRunningAsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

// setupServiceLogging настраивает логирование сервиса.
func setupServiceLogging() {
	logDir := filepath.Join(os.Getenv("ProgramData"), "NovaVPN")
	os.MkdirAll(logDir, 0755)

	f, err := os.OpenFile(
		filepath.Join(logDir, "service.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return
	}

	log.SetOutput(f)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}
