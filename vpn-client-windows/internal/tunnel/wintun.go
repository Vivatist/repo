// Package tunnel реализует WinTUN-адаптер для Windows.
package tunnel

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	ringCapacity = 0x800000 // 8 МБ кольцевой буфер
)

// WinTUN — обёртка над WinTUN-адаптером.
type WinTUN struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	name     string
	mtu      int
	readWait windows.Handle
	serverIP net.IP // для cleanup маршрутов
}

// NewWinTUN создаёт новый TUN-адаптер через WinTUN.
func NewWinTUN(name string, mtu int) (*WinTUN, error) {
	// Создаём адаптер
	adapter, err := wintun.CreateAdapter(name, "NovaVPN", nil)
	if err != nil {
		return nil, fmt.Errorf("CreateAdapter: %w", err)
	}

	// Стартуем сессию
	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("StartSession: %w", err)
	}

	t := &WinTUN{
		adapter:  adapter,
		session:  session,
		name:     name,
		mtu:      mtu,
		readWait: session.ReadWaitEvent(),
	}

	log.Printf("[TUN] Адаптер '%s' создан (MTU: %d)", name, mtu)
	return t, nil
}

// Read читает пакет из TUN-адаптера.
func (t *WinTUN) Read(buf []byte) (int, error) {
	for {
		packet, err := t.session.ReceivePacket()
		if err != nil {
			// Ждём данных
			windows.WaitForSingleObject(t.readWait, windows.INFINITE)
			continue
		}

		n := copy(buf, packet)
		t.session.ReleaseReceivePacket(packet)
		return n, nil
	}
}

// Write записывает пакет в TUN-адаптер.
func (t *WinTUN) Write(packet []byte) (int, error) {
	buf, err := t.session.AllocateSendPacket(len(packet))
	if err != nil {
		return 0, fmt.Errorf("AllocateSendPacket: %w", err)
	}

	copy(buf, packet)
	t.session.SendPacket(buf)
	return len(packet), nil
}

// Close закрывает TUN-адаптер и очищает маршруты.
func (t *WinTUN) Close() error {
	log.Printf("[TUN] Закрываем адаптер '%s'", t.name)

	// Восстанавливаем DNS
	t.restoreDNS()

	// Удаляем маршруты
	t.cleanupRoutes()

	t.session.End()
	if t.adapter != nil {
		t.adapter.Close()
	}
	return nil
}

// GetInterfaceIndex возвращает IF index TUN-адаптера через Go net.Interfaces (без PowerShell).
func (t *WinTUN) GetInterfaceIndex() (uint32, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range ifaces {
		if iface.Name == t.name {
			return uint32(iface.Index), nil
		}
	}
	return 0, fmt.Errorf("интерфейс %q не найден", t.name)
}

// ConfigureNetwork настраивает IP, DNS и маршруты одним bat-скриптом (оптимизация скорости).
func (t *WinTUN) ConfigureNetwork(vpnIP net.IP, subnetMask uint8, dns1, dns2, serverIP net.IP) error {
	ifName := t.name
	t.serverIP = serverIP

	// IF index TUN-адаптера (Go native, ~0ms)
	tunIF, err := t.GetInterfaceIndex()
	if err != nil {
		log.Printf("[TUN] Не удалось получить IF index TUN: %v", err)
	} else {
		log.Printf("[TUN] IF index TUN: %d", tunIF)
	}

	// Физический шлюз (Go native, ~0ms)
	physGW, physIF := getPhysicalGateway()
	log.Printf("[TUN] Физ. шлюз: %s, IF index: %d", physGW, physIF)

	// Формируем единый bat-скрипт: все netsh + route в одном процессе
	maskStr := subnetMaskToString(subnetMask)
	vpnGW := make(net.IP, 4)
	copy(vpnGW, vpnIP.To4())
	vpnGW[3] = 1

	var script strings.Builder
	script.WriteString("@echo off\n")
	// IP
	script.WriteString(fmt.Sprintf("netsh interface ip set address \"%s\" static %s %s\n", ifName, vpnIP.String(), maskStr))
	// DNS
	if dns1 != nil {
		script.WriteString(fmt.Sprintf("netsh interface ip set dns \"%s\" static %s\n", ifName, dns1.String()))
	}
	if dns2 != nil {
		script.WriteString(fmt.Sprintf("netsh interface ip add dns \"%s\" %s index=2\n", ifName, dns2.String()))
	}
	// Метрика + MTU
	script.WriteString(fmt.Sprintf("netsh interface ip set interface \"%s\" metric=5\n", ifName))
	script.WriteString(fmt.Sprintf("netsh interface ipv4 set subinterface \"%s\" mtu=%d store=active\n", ifName, t.mtu))
	// Маршрут к серверу
	if physGW != "" && serverIP != nil {
		if physIF > 0 {
			script.WriteString(fmt.Sprintf("route add %s mask 255.255.255.255 %s metric 1 IF %d\n",
				serverIP.String(), physGW, physIF))
		} else {
			script.WriteString(fmt.Sprintf("route add %s mask 255.255.255.255 %s metric 1\n",
				serverIP.String(), physGW))
		}
	}
	// VPN маршруты
	if tunIF > 0 {
		script.WriteString(fmt.Sprintf("route add 0.0.0.0 mask 128.0.0.0 %s metric 3 IF %d\n", vpnGW.String(), tunIF))
		script.WriteString(fmt.Sprintf("route add 128.0.0.0 mask 128.0.0.0 %s metric 3 IF %d\n", vpnGW.String(), tunIF))
	} else {
		script.WriteString(fmt.Sprintf("route add 0.0.0.0 mask 128.0.0.0 %s metric 3\n", vpnGW.String()))
		script.WriteString(fmt.Sprintf("route add 128.0.0.0 mask 128.0.0.0 %s metric 3\n", vpnGW.String()))
	}

	// Пишем bat-файл во временную директорию и запускаем одним вызовом
	tmpFile := filepath.Join(os.TempDir(), "novavpn-setup.bat")
	if err := os.WriteFile(tmpFile, []byte(script.String()), 0644); err != nil {
		return fmt.Errorf("ошибка создания bat: %w", err)
	}
	defer os.Remove(tmpFile)

	log.Printf("[TUN] Настройка сети (IP: %s/%d, DNS: %s/%s)...", vpnIP, subnetMask, dns1, dns2)

	cmd := exec.Command("cmd", "/C", tmpFile)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[TUN] Вывод bat: %s", string(output))
		return fmt.Errorf("ошибка настройки сети: %w", err)
	}

	log.Printf("[TUN] Маршруты настроены (full tunnel): server->%s IF %d, VPN gw=%s IF %d",
		physGW, physIF, vpnGW, tunIF)
	return nil
}

// restoreDNS сбрасывает DNS на автоматический.
func (t *WinTUN) restoreDNS() {
	// Не нужно — адаптер удаляется, DNS восстанавливается автоматически.
}

// cleanupRoutes удаляет маршруты.
func (t *WinTUN) cleanupRoutes() {
	runCmd("route delete 0.0.0.0 mask 128.0.0.0")
	runCmd("route delete 128.0.0.0 mask 128.0.0.0")
	if t.serverIP != nil {
		runCmd(fmt.Sprintf("route delete %s mask 255.255.255.255", t.serverIP.String()))
	}
	log.Println("[TUN] Маршруты очищены")
}

// runCmd выполняет shell-команду.
func runCmd(cmdStr string) error {
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return nil
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

// getPhysicalGateway возвращает шлюз и IF index физического адаптера.
// Использует route print (мгновенно, без PowerShell).
func getPhysicalGateway() (gateway string, ifIndex int) {
	// Собираем имена виртуальных интерфейсов для фильтрации по ifIndex
	virtualIFs := getVirtualInterfaceIndices()

	// Парсим route print — ищем default route 0.0.0.0 с минимальной метрикой
	cmd := exec.Command("route", "print", "0.0.0.0")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		log.Printf("[TUN] route print error: %v", err)
		return "", 0
	}

	bestGW := ""
	bestIF := 0
	bestMetric := 999999

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Формат: Network    Netmask    Gateway    Interface    Metric
		// 0.0.0.0    0.0.0.0    192.168.55.2    192.168.55.112    25
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		gw := fields[2]
		ifIP := fields[3]
		var metric int
		fmt.Sscanf(fields[4], "%d", &metric)

		if gw == "On-link" || net.ParseIP(gw) == nil {
			continue
		}

		// Определяем ifIndex по IP интерфейса
		idx := getIfIndexByIP(ifIP)
		if idx > 0 && virtualIFs[idx] {
			continue // пропускаем Tailscale, VirtualBox и т.д.
		}

		if metric < bestMetric {
			bestMetric = metric
			bestGW = gw
			bestIF = idx
		}
	}

	if bestGW != "" {
		return bestGW, bestIF
	}
	return "", 0
}

// getVirtualInterfaceIndices возвращает set ifIndex виртуальных адаптеров.
func getVirtualInterfaceIndices() map[int]bool {
	result := make(map[int]bool)
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "tailscale") || strings.Contains(name, "wintun") ||
			strings.Contains(name, "novavpn") || strings.Contains(name, "tap") ||
			strings.Contains(name, "tun") || strings.Contains(name, "virtualbox") ||
			strings.Contains(name, "loopback") {
			result[iface.Index] = true
		}
	}
	return result
}

// getIfIndexByIP возвращает ifIndex по IP-адресу интерфейса.
func getIfIndexByIP(ipStr string) int {
	target := net.ParseIP(ipStr)
	if target == nil {
		return 0
	}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok && ipnet.IP.Equal(target) {
				return iface.Index
			}
		}
	}
	return 0
}

// GetPhysicalLocalIP возвращает IP-адрес физического адаптера для привязки UDP-сокета.
// Go-native реализация (без PowerShell — мгновенно).
func GetPhysicalLocalIP() (net.IP, error) {
	// Определяем ifIndex физ. шлюза → ищем IP этого интерфейса
	_, physIF := getPhysicalGateway()
	if physIF > 0 {
		iface, err := net.InterfaceByIndex(physIF)
		if err == nil {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if ok && ipnet.IP.To4() != nil {
					log.Printf("[TUN] Физический IP для UDP: %s (iface: %s, IF %d)", ipnet.IP, iface.Name, physIF)
					return ipnet.IP, nil
				}
			}
		}
	}
	// Fallback
	return getPhysicalIPViaGo()
}

// getPhysicalIPViaGo определяет физический IP через Go net.Interfaces (fallback).
func getPhysicalIPViaGo() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "tailscale") || strings.Contains(name, "wintun") ||
			strings.Contains(name, "tun") || strings.Contains(name, "tap") ||
			strings.Contains(name, "nova") || strings.Contains(name, "virtualbox") ||
			strings.Contains(name, "loopback") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				log.Printf("[TUN] Физический IP (Go fallback): %s (iface: %s)", ip4, iface.Name)
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("не найден физический IP")
}

// subnetMaskToString конвертирует CIDR маску в строку.
func subnetMaskToString(bits uint8) string {
	mask := net.CIDRMask(int(bits), 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

// Скрытое окно для netsh/route
func init() {
	// Подавляем консольные окна при запуске netsh/route
	_ = unsafe.Sizeof(0)
}
