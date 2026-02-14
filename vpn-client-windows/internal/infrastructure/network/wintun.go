//go:build windows

// Package network реализует адаптер WinTUN для сетевого туннелирования.
package network

import (
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"github.com/novavpn/vpn-client-windows/internal/domain/network"
)

const ringCapacity = 0x800000 // 8 МБ кольцевой буфер

// WinTUNDevice реализует интерфейс TunnelDevice с использованием WinTUN.
type WinTUNDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	name     string
	mtu      int
	readWait windows.Handle
	closed   atomic.Bool
}

// NewWinTUNDevice создаёт новый TUN-адаптер через WinTUN.
func NewWinTUNDevice(name string, mtu int) (network.TunnelDevice, error) {
	adapter, err := wintun.CreateAdapter(name, "NovaVPN", nil)
	if err != nil {
		return nil, fmt.Errorf("CreateAdapter: %w", err)
	}

	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("StartSession: %w", err)
	}

	device := &WinTUNDevice{
		adapter:  adapter,
		session:  session,
		name:     name,
		mtu:      mtu,
		readWait: session.ReadWaitEvent(),
	}

	log.Printf("[TUN] Адаптер '%s' создан (MTU: %d)", name, mtu)
	return device, nil
}

// Read читает пакет из TUN-адаптера.
// Использует таймаут в WaitForSingleObject для корректного выхода при Close().
func (d *WinTUNDevice) Read(buf []byte) (int, error) {
	for {
		if d.closed.Load() {
			return 0, fmt.Errorf("device closed")
		}
		packet, err := d.session.ReceivePacket()
		if err != nil {
			if d.closed.Load() {
				return 0, fmt.Errorf("device closed")
			}
			// Таймаут 1000мс — снижает CPU wakeup в idle (10 раз реже проверка closed).
			// При Close() устройство сигнализирует через readWait, поэтому
			// увеличенный таймаут не замедляет корректное завершение.
			windows.WaitForSingleObject(d.readWait, 1000)
			continue
		}

		n := copy(buf, packet)
		d.session.ReleaseReceivePacket(packet)
		return n, nil
	}
}

// Write записывает пакет в TUN-адаптер.
func (d *WinTUNDevice) Write(packet []byte) (int, error) {
	buf, err := d.session.AllocateSendPacket(len(packet))
	if err != nil {
		return 0, fmt.Errorf("AllocateSendPacket: %w", err)
	}

	copy(buf, packet)
	d.session.SendPacket(buf)
	return len(packet), nil
}

// Close закрывает TUN-адаптер. Идемпотентный — безопасен для повторных вызовов.
func (d *WinTUNDevice) Close() error {
	if d.closed.Swap(true) {
		return nil // уже закрыт
	}
	log.Printf("[TUN] Закрываем адаптер '%s'", d.name)
	d.session.End()
	if d.adapter != nil {
		d.adapter.Close()
	}
	return nil
}

// MTU возвращает MTU устройства.
func (d *WinTUNDevice) MTU() int {
	return d.mtu
}

// Name возвращает имя интерфейса.
func (d *WinTUNDevice) Name() string {
	return d.name
}

// GetInterfaceIndex возвращает IF index TUN-адаптера.
func (d *WinTUNDevice) GetInterfaceIndex() (uint32, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range ifaces {
		if iface.Name == d.name {
			return uint32(iface.Index), nil
		}
	}
	return 0, fmt.Errorf("интерфейс %q не найден", d.name)
}
