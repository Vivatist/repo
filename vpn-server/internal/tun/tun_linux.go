// Package tun реализует работу с TUN-интерфейсом на Linux.
//
// TUN-интерфейс используется для создания виртуального сетевого устройства,
// через которое проходит VPN-трафик. Пакеты, поступающие в TUN, читаются
// сервером, шифруются и отправляются клиенту через UDP.
package tun

import (
	"fmt"
	"log"
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

	// IFF_VNET_HDR — включить virtio_net_hdr перед каждым пакетом (GRO/GSO)
	iffVNET_HDR = 0x4000

	// ioctl команды для GRO/GSO
	// TUNSETVNETHDRSZ = _IOW('T', 216, int) — устанавливает размер virtio заголовка
	tunSetVNetHdrSz = 0x400454D8
	// TUNSETOFFLOAD = _IOW('T', 208, unsigned int) — включает offload features
	tunSetOffload = 0x400454D0

	// TUN offload features (TUNSETOFFLOAD)
	tunFCsum = 0x01 // Checksum offload
	tunFTSO4 = 0x02 // TCP Segmentation Offload (IPv4)
	tunFTSO6 = 0x04 // TCP Segmentation Offload (IPv6)
	tunFUSO4 = 0x20 // UDP Segmentation Offload (IPv4, Linux 6.2+)
	tunFUSO6 = 0x40 // UDP Segmentation Offload (IPv6, Linux 6.2+)
)

// ifreq — структура для ioctl запросов к сетевому интерфейсу.
type ifreq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte // padding
}

// TUNDevice представляет TUN-интерфейс.
type TUNDevice struct {
	file       *os.File
	name       string
	mtu        int
	groEnabled bool   // GRO/GSO активен (IFF_VNET_HDR + offload)
	usoEnabled bool   // UDP Segmentation Offload (Linux 6.2+)
	writeBuf   []byte // Пре-аллоцированный буфер для записи с virtio header (zero-alloc)
}

// NewTUN создаёт новый TUN-интерфейс.
// enableGRO: если true, пытается включить GRO/GSO через IFF_VNET_HDR + TUNSETOFFLOAD.
// При неудаче автоматически отключает GRO и работает в обычном режиме.
func NewTUN(name string, mtu int, enableGRO bool) (*TUNDevice, error) {
	// Открываем /dev/net/tun
	fd, err := unix.Open(tunDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть %s: %w", tunDevice, err)
	}

	// Настраиваем TUN-интерфейс через ioctl
	var req ifreq
	req.Flags = iffTUN | iffNO_PI
	if enableGRO {
		req.Flags |= iffVNET_HDR
	}

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
		if enableGRO {
			// TUNSETIFF с IFF_VNET_HDR не удался — пробуем без GRO
			log.Printf("[TUN] IFF_VNET_HDR не поддерживается, GRO/GSO отключён")
			req.Flags = iffTUN | iffNO_PI
			_, _, errno = unix.Syscall(
				unix.SYS_IOCTL,
				uintptr(fd),
				uintptr(unix.TUNSETIFF),
				uintptr(unsafe.Pointer(&req)),
			)
			if errno != 0 {
				unix.Close(fd)
				return nil, fmt.Errorf("ioctl TUNSETIFF ошибка: %v", errno)
			}
			enableGRO = false
		} else {
			unix.Close(fd)
			return nil, fmt.Errorf("ioctl TUNSETIFF ошибка: %v", errno)
		}
	}

	// Настраиваем GRO/GSO
	usoEnabled := false
	if enableGRO {
		enableGRO, usoEnabled = setupGRO(fd)
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
		file:       file,
		name:       actualName,
		mtu:        mtu,
		groEnabled: enableGRO,
		usoEnabled: usoEnabled,
	}

	// Пре-аллоцируем буфер для записи с virtio header (zero-alloc Write)
	if enableGRO {
		tun.writeBuf = make([]byte, VirtioNetHdrLen+mtu+100)
		// Первые VirtioNetHdrLen байт = 0 (GSO_NONE) — Go нулевая инициализация
	}

	return tun, nil
}

// setupGRO настраивает GRO/GSO через ioctl на открытом fd TUN-устройства.
// Возвращает: (groEnabled, usoEnabled).
func setupGRO(fd int) (bool, bool) {
	// 1. Устанавливаем размер virtio заголовка
	sz := int32(VirtioNetHdrLen)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		tunSetVNetHdrSz,
		uintptr(unsafe.Pointer(&sz)),
	)
	if errno != 0 {
		log.Printf("[TUN] TUNSETVNETHDRSZ не удался: %v — GRO/GSO отключён", errno)
		return false, false
	}

	// 2. Включаем базовые offload features (TSO4 + TSO6)
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		tunSetOffload,
		uintptr(tunFCsum|tunFTSO4|tunFTSO6),
	)
	if errno != 0 {
		log.Printf("[TUN] TUNSETOFFLOAD (TSO) не удался: %v — GRO/GSO отключён", errno)
		return false, false
	}

	log.Println("[TUN] GRO/GSO активирован (IFF_VNET_HDR + TSO4/TSO6)")

	// 3. Пробуем USO (UDP Segmentation Offload, Linux 6.2+)
	usoEnabled := false
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		tunSetOffload,
		uintptr(tunFCsum|tunFTSO4|tunFTSO6|tunFUSO4|tunFUSO6),
	)
	if errno == 0 {
		usoEnabled = true
		log.Println("[TUN] USO активирован (UDP Segmentation Offload, Linux 6.2+)")
	} else {
		log.Println("[TUN] USO не поддерживается (Linux < 6.2) — только TCP GRO")
	}

	return true, usoEnabled
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

// Read читает пакет из TUN-интерфейса.
// При GRO: возвращает данные с virtio_net_hdr (10 байт) — используй ParseGROHeader.
// Без GRO: возвращает чистый IP-пакет.
func (t *TUNDevice) Read(buf []byte) (int, error) {
	return t.file.Read(buf)
}

// Write записывает IP-пакет в TUN-интерфейс.
// При GRO: автоматически добавляет virtio header (GSO_NONE) — zero-alloc.
// Без GRO: прямая запись.
func (t *TUNDevice) Write(buf []byte) (int, error) {
	if !t.groEnabled {
		return t.file.Write(buf)
	}

	// Пишем: virtio_hdr(10 нулей, GSO_NONE) + IP-пакет
	total := VirtioNetHdrLen + len(buf)
	if total > len(t.writeBuf) {
		// Не должно происходить при нормальных MTU, но обработаем
		t.writeBuf = make([]byte, total+1024)
	}
	// writeBuf[:VirtioNetHdrLen] всегда нули (GSO_NONE) — Go zero-init
	copy(t.writeBuf[VirtioNetHdrLen:], buf)
	n, err := t.file.Write(t.writeBuf[:total])
	if err != nil {
		return 0, err
	}
	if n < VirtioNetHdrLen {
		return 0, fmt.Errorf("short write в TUN: %d байт", n)
	}
	return n - VirtioNetHdrLen, nil
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

// GROEnabled возвращает true, если GRO/GSO активен.
func (t *TUNDevice) GROEnabled() bool {
	return t.groEnabled
}

// USOEnabled возвращает true, если UDP Segmentation Offload активен (Linux 6.2+).
func (t *TUNDevice) USOEnabled() bool {
	return t.usoEnabled
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

// ExtractDstIPKey извлекает IP-адрес назначения как [4]byte ключ (zero-alloc).
// Используется на hot path вместо ExtractDstIP, чтобы избежать аллокации net.IP.
func ExtractDstIPKey(packet []byte) ([4]byte, bool) {
	var key [4]byte
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return key, false
	}
	copy(key[:], packet[16:20])
	return key, true
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
