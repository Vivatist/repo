package server

import (
	"fmt"
	"net"
	"sync"
)

// IPPool — пул IP-адресов для VPN-клиентов.
type IPPool struct {
	mu        sync.Mutex
	network   *net.IPNet
	serverIP  net.IP
	allocated map[string]bool
	available []net.IP
}

// NewIPPool создаёт новый пул IP-адресов.
func NewIPPool(cidr string, serverIP string) (*IPPool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("невалидная подсеть: %w", err)
	}

	srvIP := net.ParseIP(serverIP)
	if srvIP == nil {
		return nil, fmt.Errorf("невалидный IP сервера: %s", serverIP)
	}

	pool := &IPPool{
		network:   network,
		serverIP:  srvIP.To4(),
		allocated: make(map[string]bool),
		available: make([]net.IP, 0),
	}

	// Генерируем все доступные IP в подсети
	pool.generateAvailable()

	return pool, nil
}

// generateAvailable генерирует все доступные IP-адреса в подсети.
func (p *IPPool) generateAvailable() {
	ip := make(net.IP, len(p.network.IP))
	copy(ip, p.network.IP)

	for ip := nextIP(ip); p.network.Contains(ip); ip = nextIP(ip) {
		// Пропускаем broadcast и адрес сервера
		if isBroadcast(ip, p.network) {
			continue
		}
		if ip.Equal(p.serverIP) {
			continue
		}

		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		p.available = append(p.available, ipCopy)
	}
}

// Allocate выделяет IP-адрес из пула.
func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.available) == 0 {
		return nil, fmt.Errorf("пул IP-адресов исчерпан")
	}

	ip := p.available[0]
	p.available = p.available[1:]
	p.allocated[ip.String()] = true

	return ip, nil
}

// AllocateSpecific выделяет конкретный IP-адрес.
func (p *IPPool) AllocateSpecific(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()
	if p.allocated[ipStr] {
		return fmt.Errorf("IP %s уже занят", ipStr)
	}

	// Удаляем из доступных
	for i, availIP := range p.available {
		if availIP.Equal(ip) {
			p.available = append(p.available[:i], p.available[i+1:]...)
			p.allocated[ipStr] = true
			return nil
		}
	}

	return fmt.Errorf("IP %s не найден в пуле", ipStr)
}

// Release возвращает IP-адрес в пул.
func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()
	if !p.allocated[ipStr] {
		return
	}

	delete(p.allocated, ipStr)
	p.available = append(p.available, ip)
}

// AvailableCount возвращает количество доступных IP.
func (p *IPPool) AvailableCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.available)
}

// nextIP увеличивает IP-адрес на 1.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	return next
}

// isBroadcast проверяет, является ли IP broadcast-адресом подсети.
func isBroadcast(ip net.IP, network *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	for i := range ip4 {
		if ip4[i] != (network.IP[i] | ^network.Mask[i]) {
			return false
		}
	}
	return true
}
