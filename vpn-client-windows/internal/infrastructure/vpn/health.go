//go:build windows

// connectionMonitor — пассивный мониторинг здоровья VPN-соединения.
//
// Принцип: отслеживает время последнего полученного пакета от сервера
// (data или keepalive). Не генерирует сетевой трафик — полностью пассивный.
//
// Три уровня:
//   - HealthGood:     < 35 сек (макс серверный keepalive = 32 сек + запас)
//   - HealthDegraded: 35-60 сек (возможна потеря пакетов)
//   - HealthLost:     > 60 сек (≈ 2 пропущенных keepalive-цикла)
//
// Ресурсы: 0 сетевых пакетов, 1 atomic store на приём, 1 проверка каждые 3-7 сек.
package vpn

import (
	"crypto/rand"
	"log"
	"sync/atomic"
	"time"

	domainvpn "github.com/novavpn/vpn-client-windows/internal/domain/vpn"
)

// Пороговые значения здоровья соединения.
const (
	// healthDegradedThreshold — порог для статуса "Нестабильно".
	// Макс серверный keepalive = 32 сек (25 ± 7), берём 35 с запасом.
	healthDegradedThreshold = 35 * time.Second

	// healthLostThreshold — порог для статуса "Потеряно".
	// ≈ 2 пропущенных keepalive-цикла сервера. При достижении — reconnect.
	healthLostThreshold = 60 * time.Second
)

// connectionMonitor — lock-free пассивный монитор здоровья соединения.
// Не генерирует сетевой трафик, не выделяет память на hot path.
type connectionMonitor struct {
	// Время последней активности (UnixNano, atomic).
	lastActivity atomic.Int64

	// Текущий статус здоровья (atomic, хранит int32 от ConnectionHealth).
	currentHealth atomic.Int32

	// Колбэки (устанавливаются при создании, не меняются — safe for concurrent read).
	onHealthChange domainvpn.HealthCallback
	onLost         func() // вызывается при HealthLost для инициации reconnect

	// Канал остановки мониторинга.
	stopCh chan struct{}
}

// newConnectionMonitor создаёт новый монитор здоровья.
//
// onHealthChange — вызывается ТОЛЬКО при смене уровня здоровья (может быть nil).
// onLost — вызывается при переходе в HealthLost для инициации reconnect (может быть nil).
func newConnectionMonitor(onHealthChange domainvpn.HealthCallback, onLost func()) *connectionMonitor {
	m := &connectionMonitor{
		onHealthChange: onHealthChange,
		onLost:         onLost,
		stopCh:         make(chan struct{}),
	}
	m.currentHealth.Store(int32(domainvpn.HealthGood))
	m.lastActivity.Store(time.Now().UnixNano())
	return m
}

// RecordActivity фиксирует получение пакета от сервера.
// Вызывается на hot path — zero-alloc, 1 atomic store (~1 нс).
func (m *connectionMonitor) RecordActivity() {
	m.lastActivity.Store(time.Now().UnixNano())
}

// Start запускает фоновый цикл проверки здоровья.
// Интервал проверки рандомизирован (3-7 сек) — полностью локальная операция.
func (m *connectionMonitor) Start() {
	go m.monitorLoop()
}

// Stop останавливает мониторинг.
func (m *connectionMonitor) Stop() {
	select {
	case <-m.stopCh:
		// уже остановлен
	default:
		close(m.stopCh)
	}
}

// Reset сбрасывает монитор в начальное состояние (при reconnect).
func (m *connectionMonitor) Reset() {
	m.lastActivity.Store(time.Now().UnixNano())
	m.currentHealth.Store(int32(domainvpn.HealthGood))
}

// Health возвращает текущий уровень здоровья (lock-free).
func (m *connectionMonitor) Health() domainvpn.ConnectionHealth {
	return domainvpn.ConnectionHealth(m.currentHealth.Load())
}

// monitorLoop — фоновый цикл проверки здоровья.
// Интервал рандомизирован для единообразия с остальными таймерами.
// Используем time.Timer вместо time.After для корректной очистки ресурсов.
func (m *connectionMonitor) monitorLoop() {
	timer := time.NewTimer(randomCheckInterval())
	defer timer.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-timer.C:
			m.check()
			timer.Reset(randomCheckInterval())
		}
	}
}

// check определяет текущий уровень здоровья по времени последнего пакета.
// Вызывает колбэк только при смене уровня.
func (m *connectionMonitor) check() {
	lastNano := m.lastActivity.Load()
	if lastNano == 0 {
		return
	}

	elapsed := time.Since(time.Unix(0, lastNano))

	var newHealth domainvpn.ConnectionHealth
	switch {
	case elapsed >= healthLostThreshold:
		newHealth = domainvpn.HealthLost
	case elapsed >= healthDegradedThreshold:
		newHealth = domainvpn.HealthDegraded
	default:
		newHealth = domainvpn.HealthGood
	}

	// Swap: обновляем только если изменилось
	oldHealth := domainvpn.ConnectionHealth(m.currentHealth.Swap(int32(newHealth)))
	if oldHealth == newHealth {
		return
	}

	log.Printf("[HEALTH] Здоровье соединения: %s → %s (без пакетов: %v)",
		oldHealth, newHealth, elapsed.Round(time.Second))

	// Уведомляем о смене здоровья
	if m.onHealthChange != nil {
		m.onHealthChange(newHealth)
	}

	// При потере связи — инициируем reconnect
	if newHealth == domainvpn.HealthLost && m.onLost != nil {
		m.onLost()
	}
}

// randomCheckInterval возвращает случайный интервал проверки 3-7 секунд.
// Использует crypto/rand для непредсказуемости (без big.Int аллокаций).
func randomCheckInterval() time.Duration {
	var buf [1]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 5 * time.Second // fallback
	}
	return time.Duration(3+int(buf[0]%5)) * time.Second // 3-7 сек
}

// randomKeepaliveInterval возвращает случайный интервал keepalive 10-20 секунд.
// Криптографически стойкий рандом для защиты от DPI-детектирования
// регулярных паттернов трафика (без big.Int аллокаций).
func randomKeepaliveInterval() time.Duration {
	var buf [1]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 15 * time.Second // fallback
	}
	return time.Duration(10+int(buf[0]%11)) * time.Second // 10-20 сек
}
