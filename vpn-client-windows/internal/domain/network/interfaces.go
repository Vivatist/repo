//go:build windows

// Package network определяет интерфейсы для работы с сетевыми устройствами.
package network

import "net"

// TunnelDevice — интерфейс TUN-устройства для чтения/записи пакетов.
type TunnelDevice interface {
	// Read читает пакет из устройства.
	Read(buf []byte) (n int, err error)

	// Write записывает пакет в устройство.
	Write(packet []byte) (n int, err error)

	// Close закрывает устройство.
	Close() error

	// MTU возвращает MTU устройства.
	MTU() int

	// Name возвращает имя интерфейса.
	Name() string
}

// NetworkConfigurator — интерфейс для настройки сетевых параметров.
type NetworkConfigurator interface {
	// ConfigureInterface настраивает IP-адрес и маску подсети на интерфейсе.
	ConfigureInterface(ifaceName string, ip net.IP, subnetMask uint8) error

	// SetDNS устанавливает DNS-серверы для интерфейса.
	SetDNS(ifaceName string, dns []net.IP) error

	// RestoreDNS восстанавливает оригинальные DNS-серверы.
	RestoreDNS(ifaceName string) error

	// AddRoute добавляет маршрут в таблицу маршрутизации.
	AddRoute(destination string, gateway net.IP, metric int) error

	// RemoveRoute удаляет маршрут из таблицы маршрутизации.
	RemoveRoute(destination string) error

	// GetPhysicalInterfaceIP возвращает IP физического сетевого интерфейса.
	GetPhysicalInterfaceIP() (net.IP, error)
}
