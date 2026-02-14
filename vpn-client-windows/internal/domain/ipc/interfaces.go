//go:build windows

// Package ipc определяет интерфейсы для межпроцессного взаимодействия.
package ipc

import "github.com/novavpn/vpn-client-windows/internal/domain/vpn"

// ConnectRequest — запрос на подключение к VPN.
type ConnectRequest struct {
	ServerAddr string
	Email      string
	Password   string
	PSK        string
}

// StatusResponse — ответ со статусом подключения.
type StatusResponse struct {
	State       vpn.ConnectionState
	Info        string
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
	AssignedIP  string
	DNS         []string
}

// Client — интерфейс IPC-клиента (GUI -> Service).
type Client interface {
	// Connect отправляет запрос на подключение к VPN-серверу.
	Connect(req ConnectRequest) error

	// Disconnect отправляет запрос на отключение от VPN-сервера.
	Disconnect() error

	// GetStatus запрашивает текущий статус подключения.
	GetStatus() (*StatusResponse, error)

	// StopService отправляет запрос на остановку Windows-сервиса.
	// Сервис выполнит graceful shutdown: отключит VPN, остановит IPC, завершит процесс.
	StopService() error

	// Close закрывает соединение.
	Close() error
}

// Server — интерфейс IPC-сервера (Service).
type Server interface {
	// Start запускает IPC-сервер.
	Start() error

	// Stop останавливает IPC-сервер.
	Stop()

	// SetVPNClient устанавливает VPN-клиент для обработки запросов.
	SetVPNClient(client vpn.Client)
}
