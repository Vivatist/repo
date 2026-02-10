// Package tun реализует работу с TUN-интерфейсом на Linux.
//
// TUN-интерфейс используется для создания виртуального сетевого устройства,
// через которое проходит VPN-трафик. Пакеты, поступающие в TUN, читаются
// сервером, шифруются и отправляются клиенту через UDP.
package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// tunDevice — путь к устройству TUN
	tunDevice = "/dev/net/tun"

	// ifnamsiz — максимальная длина имени интерфейса
	ifnamsiz = 16

	// IFF_TUN — флаг TUN-устройства
	iffTUN = 0x0001

	// IFF_NO_PI — не добавлять заголовок packet information
	iffNO_PI = 0x1000
)

// ifreq — структура для ioctl запросов к сетевому интерфейсу.
type ifreq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte // padding
}

// TUNDevice представляет TUN-интерфейс.
type TUNDevice struct {
	file *os.File
	name string
	mtu  int
}

// NewTUN создаёт новый TUN-интерфейс.
func NewTUN(name string, mtu int) (*TUNDevice, error) {
	// Открываем /dev/net/tun
	fd, err := unix.Open(tunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть %s: %w", tunDevice, err)
	}

	// Настраиваем TUN-интерфейс через ioctl
	var req ifreq
	req.Flags = iffTUN | iffNO_PI

	// Копируем имя интерфейса
	if len(name) >= ifnamsiz {
		unix.Close(fd)
		return nil, fmt.Errorf("имя интерфейса слишком длинное: %s", name)
	}
	copy(req.Name[:], name)

	// TUNSETIFF ioctl
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF ошибка: %v", errno)
	}

	// Получаем фактическое имя интерфейса
	actualName := string(req.Name[:])
	if idx := strings.IndexByte(actualName, 0); idx != -1 {
		actualName = actualName[:idx]
	}

	file := os.NewFile(uintptr(fd), tunDevice)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("не удалось создать файл из fd")
	}

	tun := &TUNDevice{
		file: file,
		name: actualName,
		mtu:  mtu,
	}

	return tun, nil
}

// Configure настраивает IP-адрес и другие параметры TUN-интерфейса.
func (t *TUNDevice) Configure(ipAddr string, subnetMask int) error {
	// Устанавливаем IP-адрес
	cidr := fmt.Sprintf("%s/%d", ipAddr, subnetMask)
	if err := runCmd("ip", "addr", "add", cidr, "dev", t.name); err != nil {
		return fmt.Errorf("ошибка установки IP-адреса: %w", err)
	}

	// Устанавливаем MTU
	if err := runCmd("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", t.mtu)); err != nil {
		return fmt.Errorf("ошибка установки MTU: %w", err)
	}

	// Поднимаем интерфейс
	if err := runCmd("ip", "link", "set", "dev", t.name, "up"); err != nil {
		return fmt.Errorf("ошибка поднятия интерфейса: %w", err)
	}

	return nil
}

// Read читает IP-пакет из TUN-интерфейса.
func (t *TUNDevice) Read(buf []byte) (int, error) {
	return t.file.Read(buf)
}

// Write записывает IP-пакет в TUN-интерфейс.
func (t *TUNDevice) Write(buf []byte) (int, error) {
	return t.file.Write(buf)
}

// Close закрывает TUN-интерфейс.
func (t *TUNDevice) Close() error {
	// Опускаем интерфейс
	_ = runCmd("ip", "link", "set", "dev", t.name, "down")
	_ = runCmd("ip", "link", "delete", t.name)
	return t.file.Close()
}

// Name возвращает имя TUN-интерфейса.
func (t *TUNDevice) Name() string {
	return t.name
}

// MTU возвращает MTU интерфейса.
func (t *TUNDevice) MTU() int {
	return t.mtu
}

// File возвращает файловый дескриптор.
func (t *TUNDevice) File() *os.File {
	return t.file
}

// SetupRouting настраивает маршрутизацию для VPN-клиентов.
func SetupRouting(vpnSubnet string, tunName string, extInterface string, enableNAT bool) error {
	// Включаем IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("ошибка включения IP forwarding: %w", err)
	}

	if enableNAT {
		// Настраиваем NAT (masquerade)
		if err := runCmd("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", vpnSubnet, "-o", extInterface, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("ошибка настройки NAT: %w", err)
		}

		// Разрешаем forwarding для VPN-подсети
		if err := runCmd("iptables", "-A", "FORWARD",
			"-i", tunName, "-o", extInterface, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("ошибка настройки FORWARD (out): %w", err)
		}

		if err := runCmd("iptables", "-A", "FORWARD",
			"-i", extInterface, "-o", tunName,
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("ошибка настройки FORWARD (in): %w", err)
		}
	}

	return nil
}

// CleanupRouting удаляет правила маршрутизации.
func CleanupRouting(vpnSubnet string, tunName string, extInterface string, enableNAT bool) {
	if enableNAT {
		_ = runCmd("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-s", vpnSubnet, "-o", extInterface, "-j", "MASQUERADE")
		_ = runCmd("iptables", "-D", "FORWARD",
			"-i", tunName, "-o", extInterface, "-j", "ACCEPT")
		_ = runCmd("iptables", "-D", "FORWARD",
			"-i", extInterface, "-o", tunName,
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}
}

// ExtractDstIP извлекает IP-адрес назначения из IPv4-пакета.
func ExtractDstIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	// Версия IP в первых 4 битах
	version := packet[0] >> 4
	if version != 4 {
		return nil
	}
	// Destination IP: байты 16-19 (IPv4)
	return net.IPv4(packet[16], packet[17], packet[18], packet[19])
}

// ExtractSrcIP извлекает IP-адрес источника из IPv4-пакета.
func ExtractSrcIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	if version != 4 {
		return nil
	}
	// Source IP: байты 12-15 (IPv4)
	return net.IPv4(packet[12], packet[13], packet[14], packet[15])
}

// runCmd выполняет системную команду.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
