//go:build windows

// Package network реализует настройку сетевых параметров Windows.
package network

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/novavpn/vpn-client-windows/internal/domain/network"
)

// WindowsConfigurator реализует NetworkConfigurator для Windows.
type WindowsConfigurator struct {
	serverIP net.IP // для cleanup маршрутов
}

// NewWindowsConfigurator создаёт новый конфигуратор сети для Windows.
func NewWindowsConfigurator() network.NetworkConfigurator {
	return &WindowsConfigurator{}
}

// ConfigureInterface настраивает IP-адрес и маску подсети на интерфейсе.
func (c *WindowsConfigurator) ConfigureInterface(ifaceName string, ip net.IP, subnetMask uint8) error {
	maskStr := subnetMaskToString(subnetMask)
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		ifaceName, "static", ip.String(), maskStr)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[NET] netsh output: %s", string(output))
		return fmt.Errorf("set IP address: %w", err)
	}

	log.Printf("[NET] IP настроен: %s/%d на %s", ip, subnetMask, ifaceName)
	return nil
}

// SetDNS устанавливает DNS-серверы для интерфейса.
func (c *WindowsConfigurator) SetDNS(ifaceName string, dns []net.IP) error {
	if len(dns) == 0 {
		return nil
	}

	// Первый DNS
	cmd := exec.Command("netsh", "interface", "ip", "set", "dns",
		ifaceName, "static", dns[0].String())
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[NET] netsh output: %s", string(output))
		return fmt.Errorf("set primary DNS: %w", err)
	}

	// Дополнительные DNS
	for i := 1; i < len(dns); i++ {
		cmd = exec.Command("netsh", "interface", "ip", "add", "dns",
			ifaceName, dns[i].String(), fmt.Sprintf("index=%d", i+1))
		cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[NET] netsh output: %s", string(output))
			return fmt.Errorf("add DNS %d: %w", i, err)
		}
	}

	log.Printf("[NET] DNS настроен: %v на %s", dns, ifaceName)
	return nil
}

// RestoreDNS восстанавливает автоматическое получение DNS.
func (c *WindowsConfigurator) RestoreDNS(ifaceName string) error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "dns",
		ifaceName, "dhcp")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[NET] netsh output: %s", string(output))
		return fmt.Errorf("restore DNS: %w", err)
	}

	log.Printf("[NET] DNS восстановлен на %s", ifaceName)
	return nil
}

// AddRoute добавляет маршрут в таблицу маршрутизации.
// destination может содержать маску: "10.0.0.0 mask 255.0.0.0" — она разбивается на отдельные аргументы.
func (c *WindowsConfigurator) AddRoute(destination string, gateway net.IP, metric int) error {
	// Разбиваем destination на отдельные аргументы ("0.0.0.0 mask 128.0.0.0" → ["0.0.0.0", "mask", "128.0.0.0"])
	args := append([]string{"add"}, strings.Fields(destination)...)
	if gateway != nil {
		args = append(args, gateway.String())
	}
	if metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", metric))
	}

	cmd := exec.Command("route", args...)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Игнорируем ошибку если маршрут уже существует
		if !strings.Contains(string(output), "already exists") {
			log.Printf("[NET] route output: %s", string(output))
			return fmt.Errorf("add route: %w", err)
		}
	}

	log.Printf("[NET] Маршрут добавлен: %s -> %s (metric %d)", destination, gateway, metric)
	return nil
}

// RemoveRoute удаляет маршрут из таблицы маршрутизации.
// destination может содержать маску: "0.0.0.0 mask 128.0.0.0" — она разбивается на отдельные аргументы.
func (c *WindowsConfigurator) RemoveRoute(destination string) error {
	// Разбиваем destination на отдельные аргументы, чтобы каждый передавался отдельно.
	// Без этого Go на Windows оборачивает строку с пробелами в кавычки,
	// и route.exe не может распарсить "0.0.0.0 mask 128.0.0.0" как один аргумент.
	args := append([]string{"delete"}, strings.Fields(destination)...)
	cmd := exec.Command("route", args...)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := string(output)
		// Игнорируем ошибку если маршрут не существует
		if !strings.Contains(outStr, "not found") && !strings.Contains(outStr, "not exist") {
			log.Printf("[NET] route delete output: %s", outStr)
			return fmt.Errorf("delete route %s: %w", destination, err)
		}
	}

	log.Printf("[NET] Маршрут удалён: %s", destination)
	return nil
}

// GetPhysicalInterfaceIP возвращает IP физического сетевого интерфейса.
func (c *WindowsConfigurator) GetPhysicalInterfaceIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("get interfaces: %w", err)
	}

	// Фильтруем виртуальные интерфейсы
	for _, iface := range ifaces {
		// Пропускаем loopback и виртуальные адаптеры
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.Contains(strings.ToLower(iface.Name), "virtual") ||
			strings.Contains(strings.ToLower(iface.Name), "vmware") ||
			strings.Contains(strings.ToLower(iface.Name), "virtualbox") ||
			strings.Contains(strings.ToLower(iface.Name), "hyper-v") ||
			strings.Contains(strings.ToLower(iface.Name), "tailscale") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no physical interface found")
}

// SetupVPNRoutes настраивает full tunnel маршруты для VPN.
func (c *WindowsConfigurator) SetupVPNRoutes(ifaceName string, vpnIP, serverIP net.IP) error {
	// Сохраняем IP сервера для cleanup
	c.serverIP = serverIP

	// Получаем физический шлюз
	physGW, physIF, err := c.getPhysicalGateway()
	if err != nil {
		log.Printf("[NET] Не удалось найти физический шлюз: %v", err)
	}

	// Получаем IF index TUN
	tunIF, err := c.getInterfaceIndex(ifaceName)
	if err != nil {
		log.Printf("[NET] Не удалось получить IF index TUN: %v", err)
		tunIF = 0
	}

	// VPN gateway (первый IP в подсети)
	vpnGW := make(net.IP, 4)
	copy(vpnGW, vpnIP.To4())
	vpnGW[3] = 1

	var script strings.Builder
	script.WriteString("@echo off\n")

	// Маршрут к серверу через физический шлюз
	if physGW != nil && serverIP != nil {
		if physIF > 0 {
			script.WriteString(fmt.Sprintf("route add %s mask 255.255.255.255 %s metric 1 IF %d\n",
				serverIP.String(), physGW.String(), physIF))
		} else {
			script.WriteString(fmt.Sprintf("route add %s mask 255.255.255.255 %s metric 1\n",
				serverIP.String(), physGW.String()))
		}
	}

	// Full tunnel: две половинки 0.0.0.0/1 и 128.0.0.0/1
	if tunIF > 0 {
		script.WriteString(fmt.Sprintf("route add 0.0.0.0 mask 128.0.0.0 %s metric 3 IF %d\n", vpnGW.String(), tunIF))
		script.WriteString(fmt.Sprintf("route add 128.0.0.0 mask 128.0.0.0 %s metric 3 IF %d\n", vpnGW.String(), tunIF))
	} else {
		script.WriteString(fmt.Sprintf("route add 0.0.0.0 mask 128.0.0.0 %s metric 3\n", vpnGW.String()))
		script.WriteString(fmt.Sprintf("route add 128.0.0.0 mask 128.0.0.0 %s metric 3\n", vpnGW.String()))
	}

	// Пишем bat-файл и запускаем
	tmpFile := filepath.Join(os.TempDir(), "novavpn-routes.bat")
	if err := os.WriteFile(tmpFile, []byte(script.String()), 0644); err != nil {
		return fmt.Errorf("create bat file: %w", err)
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command("cmd", "/C", tmpFile)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[NET] route bat output: %s", string(output))
		return fmt.Errorf("setup routes: %w", err)
	}

	log.Printf("[NET] VPN маршруты настроены: gw=%s IF %d", vpnGW, tunIF)
	return nil
}

// CleanupVPNRoutes удаляет VPN маршруты.
func (c *WindowsConfigurator) CleanupVPNRoutes() error {
	var lastErr error

	if err := c.RemoveRoute("0.0.0.0 mask 128.0.0.0"); err != nil {
		log.Printf("[NET] Не удалось удалить маршрут 0.0.0.0/1: %v", err)
		lastErr = err
	}
	if err := c.RemoveRoute("128.0.0.0 mask 128.0.0.0"); err != nil {
		log.Printf("[NET] Не удалось удалить маршрут 128.0.0.0/1: %v", err)
		lastErr = err
	}
	if c.serverIP != nil {
		if err := c.RemoveRoute(fmt.Sprintf("%s mask 255.255.255.255", c.serverIP.String())); err != nil {
			log.Printf("[NET] Не удалось удалить маршрут сервера: %v", err)
			lastErr = err
		}
	}

	// Сбрасываем DNS-кеш — после смены маршрутов старые DNS-записи могут быть невалидны
	flushCmd := exec.Command("ipconfig", "/flushdns")
	flushCmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	flushCmd.Run()

	log.Println("[NET] VPN маршруты очищены")
	return lastErr
}

// getPhysicalGateway возвращает физический шлюз и IF index.
func (c *WindowsConfigurator) getPhysicalGateway() (net.IP, int, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return nil, 0, fmt.Errorf("route print: %w", err)
	}

	bestGW := ""
	bestIF := 0
	bestMetric := 999999

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "0.0.0.0") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		gw := fields[2]
		metric := 100
		ifIndex := 0

		// Парсим метрику и IF
		for i := 3; i < len(fields); i++ {
			fmt.Sscanf(fields[i], "%d", &metric)
			if i+1 < len(fields) {
				fmt.Sscanf(fields[i+1], "%d", &ifIndex)
			}
		}

		if metric < bestMetric {
			bestMetric = metric
			bestGW = gw
			bestIF = ifIndex
		}
	}

	if bestGW == "" {
		return nil, 0, fmt.Errorf("no default gateway found")
	}

	return net.ParseIP(bestGW), bestIF, nil
}

// getInterfaceIndex возвращает IF index интерфейса по имени.
func (c *WindowsConfigurator) getInterfaceIndex(name string) (uint32, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return uint32(iface.Index), nil
		}
	}
	return 0, fmt.Errorf("interface %q not found", name)
}

// subnetMaskToString преобразует CIDR-длину в маску подсети.
func subnetMaskToString(bits uint8) string {
	mask := net.CIDRMask(int(bits), 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
