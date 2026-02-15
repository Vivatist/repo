//go:build windows

// Package netmon — независимый модуль мониторинга VPN-соединения.
//
// Объединяет три механизма обнаружения мёртвого соединения:
//  1. Health probe — active probe (keepalive без ответа за 15 сек) + passive пороги (20/30 сек)
//  2. Network watch — обнаружение смены/пропажи физической сети (Windows)
//
// Модуль не знает о VPN-протоколе. Единственный контракт: вызывающий код
// дёргает RecordActivity() при получении данных, RecordKeepaliveSent() при отправке,
// а модуль вызывает OnLost() когда соединение мёртво.
package netmon

import (
	"crypto/rand"
	"log"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// HealthLevel — уровень здоровья соединения.
type HealthLevel int32

const (
	HealthGood     HealthLevel = iota // < degradedThreshold без пакетов
	HealthDegraded                    // degradedThreshold..lostThreshold без пакетов
	HealthLost                        // > lostThreshold или probe timeout
)

func (h HealthLevel) String() string {
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

// Config — настройки монитора.
type Config struct {
	// Пороги здоровья соединения.
	DegradedAfter time.Duration // Порог для HealthDegraded (по умолч. 20 сек)
	LostAfter     time.Duration // Порог для HealthLost (по умолч. 30 сек)
	ProbeTimeout  time.Duration // Active probe: нет ответа после keepalive (по умолч. 15 сек)

	// Интервалы проверок.
	HealthCheckMin time.Duration // Мин. интервал проверки здоровья (по умолч. 3 сек)
	HealthCheckMax time.Duration // Макс. интервал проверки здоровья (по умолч. 7 сек)
	NetCheckEvery  time.Duration // Интервал проверки физ. сети (по умолч. 2 сек)

	// Колбэки. Вызываются из горутин монитора.
	OnHealthChange func(HealthLevel) // Смена уровня здоровья (может быть nil)
	OnLost         func()            // Соединение мёртво — нужен reconnect (обязательный)
}

// DefaultConfig возвращает конфигурацию по умолчанию.
func DefaultConfig(onLost func()) Config {
	return Config{
		DegradedAfter:  20 * time.Second,
		LostAfter:      30 * time.Second,
		ProbeTimeout:   15 * time.Second,
		HealthCheckMin: 3 * time.Second,
		HealthCheckMax: 7 * time.Second,
		NetCheckEvery:  2 * time.Second,
		OnLost:         onLost,
	}
}

// Monitor — единый монитор здоровья VPN-соединения.
// Один объект, два механизма: health probe + network watch.
// Полностью lock-free на hot path.
type Monitor struct {
	cfg Config

	// Health probe state (atomic, lock-free)
	lastActivity      atomic.Int64 // UnixNano последнего полученного пакета
	lastKeepaliveSent atomic.Int64 // UnixNano последнего отправленного keepalive
	currentHealth     atomic.Int32 // текущий HealthLevel

	// Network watch state
	prevIPs    []string    // предыдущий набор физических IP
	hadNetwork bool        // была ли сеть на предыдущей проверке

	// Остановка
	stopCh chan struct{}
}

// New создаёт новый монитор.
func New(cfg Config) *Monitor {
	m := &Monitor{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
	m.currentHealth.Store(int32(HealthGood))
	m.lastActivity.Store(time.Now().UnixNano())
	m.prevIPs = getPhysicalIPs()
	m.hadNetwork = len(m.prevIPs) > 0
	return m
}

// RecordActivity фиксирует получение пакета от сервера.
// Hot path: 1 atomic store (~1 нс), zero-alloc.
func (m *Monitor) RecordActivity() {
	m.lastActivity.Store(time.Now().UnixNano())
}

// RecordKeepaliveSent фиксирует отправку keepalive для active probe.
// Не сбрасывает таймер если предыдущий probe ещё ждёт ответа —
// иначе timeout (15 сек) никогда не сработает при keepalive каждые 10-20 сек.
func (m *Monitor) RecordKeepaliveSent() {
	lastAct := m.lastActivity.Load()
	kaSent := m.lastKeepaliveSent.Load()
	if kaSent <= lastAct {
		m.lastKeepaliveSent.Store(time.Now().UnixNano())
	}
}

// Health возвращает текущий уровень здоровья (lock-free).
func (m *Monitor) Health() HealthLevel {
	return HealthLevel(m.currentHealth.Load())
}

// Start запускает обе горутины мониторинга.
func (m *Monitor) Start() {
	go m.healthLoop()
	go m.networkLoop()
}

// Stop останавливает мониторинг.
func (m *Monitor) Stop() {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
}

// --- Health probe goroutine ---

func (m *Monitor) healthLoop() {
	timer := time.NewTimer(m.randomHealthInterval())
	defer timer.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-timer.C:
			m.checkHealth()
			timer.Reset(m.randomHealthInterval())
		}
	}
}

func (m *Monitor) checkHealth() {
	lastNano := m.lastActivity.Load()
	if lastNano == 0 {
		return
	}

	elapsed := time.Since(time.Unix(0, lastNano))

	// Active Probe: keepalive отправлен, ответ не получен за ProbeTimeout
	probeExpired := false
	kaSentNano := m.lastKeepaliveSent.Load()
	if kaSentNano > 0 && lastNano < kaSentNano {
		if time.Since(time.Unix(0, kaSentNano)) >= m.cfg.ProbeTimeout {
			probeExpired = true
		}
	}

	var newHealth HealthLevel
	switch {
	case probeExpired:
		newHealth = HealthLost
	case elapsed >= m.cfg.LostAfter:
		newHealth = HealthLost
	case elapsed >= m.cfg.DegradedAfter:
		newHealth = HealthDegraded
	default:
		newHealth = HealthGood
	}

	oldHealth := HealthLevel(m.currentHealth.Swap(int32(newHealth)))
	if oldHealth == newHealth {
		return
	}

	if probeExpired {
		log.Printf("[HEALTH] %s → %s (active probe expired: keepalive без ответа %v)",
			oldHealth, newHealth, time.Since(time.Unix(0, kaSentNano)).Round(time.Second))
	} else {
		log.Printf("[HEALTH] %s → %s (без пакетов: %v)",
			oldHealth, newHealth, elapsed.Round(time.Second))
	}

	if m.cfg.OnHealthChange != nil {
		m.cfg.OnHealthChange(newHealth)
	}
	if newHealth == HealthLost && m.cfg.OnLost != nil {
		m.cfg.OnLost()
	}
}

func (m *Monitor) randomHealthInterval() time.Duration {
	minMs := int(m.cfg.HealthCheckMin / time.Millisecond)
	maxMs := int(m.cfg.HealthCheckMax / time.Millisecond)
	spread := maxMs - minMs
	if spread <= 0 {
		return m.cfg.HealthCheckMin
	}
	var buf [1]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return m.cfg.HealthCheckMin + (m.cfg.HealthCheckMax-m.cfg.HealthCheckMin)/2
	}
	return time.Duration(minMs+int(buf[0])%spread) * time.Millisecond
}

// --- Network watch goroutine ---

func (m *Monitor) networkLoop() {
	ticker := time.NewTicker(m.cfg.NetCheckEvery)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkNetwork()
		}
	}
}

func (m *Monitor) checkNetwork() {
	currentIPs := getPhysicalIPs()
	hasNetwork := len(currentIPs) > 0

	switch {
	case m.hadNetwork && !hasNetwork:
		log.Println("[NET] Физическая сеть потеряна")
		m.hadNetwork = false
		m.prevIPs = currentIPs
		if m.cfg.OnLost != nil {
			m.cfg.OnLost()
		}

	case m.hadNetwork && hasNetwork && !ipsEqual(m.prevIPs, currentIPs):
		log.Printf("[NET] Смена сети: %v → %v", m.prevIPs, currentIPs)
		m.prevIPs = currentIPs
		if m.cfg.OnLost != nil {
			m.cfg.OnLost()
		}

	case !m.hadNetwork && hasNetwork:
		log.Println("[NET] Физическая сеть восстановлена")
		m.hadNetwork = true
		m.prevIPs = currentIPs

	default:
		m.prevIPs = currentIPs
	}
}

// ResetNetwork обновляет базовый набор IP (вызывать после reconnect).
func (m *Monitor) ResetNetwork() {
	m.prevIPs = getPhysicalIPs()
	m.hadNetwork = len(m.prevIPs) > 0
}

// HasPhysicalNetwork проверяет наличие физической сети.
func HasPhysicalNetwork() bool {
	return len(getPhysicalIPs()) > 0
}

// --- Утилиты (не экспортируются) ---

// getPhysicalIPs возвращает отсортированный список IPv4-адресов физических интерфейсов.
func getPhysicalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		if strings.Contains(name, "wintun") || strings.Contains(name, "novavpn") ||
			strings.Contains(name, "virtual") || strings.Contains(name, "vmware") ||
			strings.Contains(name, "virtualbox") || strings.Contains(name, "hyper-v") ||
			strings.Contains(name, "loopback") || strings.Contains(name, "tailscale") ||
			strings.Contains(name, "vethernet") || strings.Contains(name, "docker") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					ips = append(ips, ip4.String())
				}
			}
		}
	}
	sort.Strings(ips)
	return ips
}

func ipsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
