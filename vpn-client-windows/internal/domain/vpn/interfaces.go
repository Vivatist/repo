//go:build windows

// Package vpn определяет доменные интерфейсы для VPN-клиента.
package vpn

import (
	"net"
	"time"
)

// ConnectionState — состояние VPN-подключения.
type ConnectionState int32

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateConnected
	StateDisconnecting
)

func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "Отключён"
	case StateConnecting:
		return "Подключение..."
	case StateConnected:
		return "Подключён"
	case StateDisconnecting:
		return "Отключение..."
	default:
		return "Неизвестно"
	}
}

// ConnectParams — параметры подключения к VPN-серверу.
type ConnectParams struct {
	ServerAddr string // host:port
	PSK        string // hex-encoded PSK (пустой = bootstrap-режим)
	Email      string
	Password   string
}

// ConnectionInfo — информация о текущем подключении.
type ConnectionInfo struct {
	State       ConnectionState
	ServerAddr  string
	AssignedIP  net.IP
	DNS         []net.IP
	MTU         uint16
	SubnetMask  uint8
	ConnectedAt time.Time
}

// Statistics — статистика передачи данных.
type Statistics struct {
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
}

// ConnectionHealth — уровень здоровья VPN-соединения.
// Определяется пассивным мониторингом: сколько прошло с момента последнего
// полученного пакета от сервера (data или keepalive).
type ConnectionHealth int32

const (
	// HealthGood — связь стабильна (< 20 сек без пакетов от сервера).
	HealthGood ConnectionHealth = iota

	// HealthDegraded — возможна потеря пакетов (20-30 сек).
	HealthDegraded

	// HealthLost — связь потеряна (> 30 сек или keepalive probe timeout 15 сек).
	// Инициируется reconnect.
	HealthLost
)

func (h ConnectionHealth) String() string {
	switch h {
	case HealthGood:
		return "Стабильно"
	case HealthDegraded:
		return "Нестабильно"
	case HealthLost:
		return "Потеряно"
	default:
		return "Неизвестно"
	}
}

// StatusCallback — колбэк для уведомлений об изменении состояния.
type StatusCallback func(state ConnectionState, info string)

// HealthCallback — колбэк для уведомлений об изменении здоровья соединения.
// Вызывается только при смене уровня (не при каждой проверке).
// Может быть nil — тогда мониторинг работает, но без оповещений.
type HealthCallback func(health ConnectionHealth)

// PSKCallback — колбэк для сохранения полученного PSK.
type PSKCallback func(pskHex string)

// Client — интерфейс VPN-клиента.
type Client interface {
	// Connect подключается к VPN-серверу с заданными параметрами.
	Connect(params ConnectParams) error

	// Disconnect отключается от VPN-сервера.
	Disconnect() error

	// GetState возвращает текущее состояние подключения.
	GetState() ConnectionState

	// GetInfo возвращает информацию о текущем подключении.
	GetInfo() ConnectionInfo

	// GetStatistics возвращает статистику передачи данных.
	GetStatistics() Statistics
}
