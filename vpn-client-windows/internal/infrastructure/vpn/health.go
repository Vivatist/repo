//go:build windows

// Package vpn реализует VPN-клиент с использованием доменных интерфейсов.
package vpn

import (
	"crypto/rand"
	"math/big"
	"sync/atomic"
	"time"

	domainvpn "github.com/novavpn/vpn-client-windows/internal/domain/vpn"
)

// connectionMonitor отслеживает здоровье VPN-соединения в реальном времени.
//
// Принцип работы:
//   - Фиксирует время получения ЛЮБОГО пакета от сервера (data, keepalive)
//     через атомарный timestamp (lock-free, zero-alloc).
//   - Периодически проверяет разницу между текущим временем и последним
//     полученным пакетом. Интервал проверки рандомизирован для защиты от DPI.
//   - Три уровня здоровья:
//     HealthGood     — пакет получен в пределах degradedAfter
//     HealthDegraded — пакет не получен дольше degradedAfter, но в пределах lostAfter
//     HealthLost     — пакет не получен дольше lostAfter → инициирует reconnect
//   - Уведомляет UI только при СМЕНЕ статуса (без спама).
//
// Ресурсоэффективность:
//   - Никаких сетевых запросов (ping/probe). Анализ основан на уже
//     существующем потоке пакетов (data + keepalive от сервера).
//   - Один тикер с рандомизированным интервалом (5±2 сек) — ~0% CPU.
//   - Lock-free: atomic.Int64 для timestamp, atomic.Int32 для статуса.
//   - Не создаёт паттернов в сетевом трафике — работает полностью локально.
type connectionMonitor struct {
	// lastServerActivity — unix timestamp последнего пакета от сервера (atomic, lock-free)
	lastServerActivity atomic.Int64

	// currentHealth — текущий статус здоровья (atomic)
	currentHealth atomic.Int32

	// degradedAfter — через сколько секунд без активности считаем соединение нестабильным.
	// По умолчанию: 35 секунд (чуть больше максимального серверного keepalive 32 сек).
	degradedAfter time.Duration

	// lostAfter — через сколько секунд без активности считаем соединение потерянным.
	// По умолчанию: 60 секунд (~2 пропущенных keepalive цикла сервера).
	lostAfter time.Duration

	// onHealth — колбэк при смене статуса здоровья
	onHealth domainvpn.HealthCallback

	// onLost — колбэк для инициации переподключения при потере связи
	onLost func()
}

// newConnectionMonitor создаёт монитор здоровья соединения.
func newConnectionMonitor(onHealth domainvpn.HealthCallback, onLost func()) *connectionMonitor {
	m := &connectionMonitor{
		degradedAfter: 35 * time.Second,
		lostAfter:     60 * time.Second,
		onHealth:      onHealth,
		onLost:        onLost,
	}
	m.currentHealth.Store(int32(domainvpn.HealthUnknown))
	return m
}

// RecordActivity фиксирует получение пакета от сервера.
// Вызывается из udpReadLoop при получении ЛЮБОГО пакета (data, keepalive).
// Lock-free, zero-alloc — безопасно вызывать в hot path.
func (m *connectionMonitor) RecordActivity() {
	m.lastServerActivity.Store(time.Now().Unix())
}

// GetHealth возвращает текущий статус здоровья соединения.
func (m *connectionMonitor) GetHealth() domainvpn.ConnectionHealth {
	return domainvpn.ConnectionHealth(m.currentHealth.Load())
}

// monitorLoop — цикл проверки здоровья соединения.
// Запускается как горутина, завершается при закрытии stopCh.
// Интервал рандомизирован (5±2 сек) для защиты от fingerprinting.
func (m *connectionMonitor) monitorLoop(stopCh <-chan struct{}) {
	for {
		// Рандомизированный интервал: 3-7 секунд
		interval := m.randomCheckInterval()

		select {
		case <-stopCh:
			return
		case <-time.After(interval):
		}

		m.check()
	}
}

// check выполняет одну проверку здоровья соединения.
func (m *connectionMonitor) check() {
	lastActivity := m.lastServerActivity.Load()
	if lastActivity == 0 {
		return // ещё не было активности
	}

	elapsed := time.Since(time.Unix(lastActivity, 0))

	var newHealth domainvpn.ConnectionHealth
	switch {
	case elapsed >= m.lostAfter:
		newHealth = domainvpn.HealthLost
	case elapsed >= m.degradedAfter:
		newHealth = domainvpn.HealthDegraded
	default:
		newHealth = domainvpn.HealthGood
	}

	oldHealth := domainvpn.ConnectionHealth(m.currentHealth.Swap(int32(newHealth)))

	// Уведомляем только при СМЕНЕ статуса
	if newHealth != oldHealth {
		if m.onHealth != nil {
			m.onHealth(newHealth)
		}

		// При потере связи инициируем reconnect
		if newHealth == domainvpn.HealthLost && m.onLost != nil {
			m.onLost()
		}
	}
}

// reset сбрасывает монитор (при новом подключении).
func (m *connectionMonitor) reset() {
	m.lastServerActivity.Store(time.Now().Unix())
	m.currentHealth.Store(int32(domainvpn.HealthGood))
}

// randomCheckInterval генерирует рандомизированный интервал проверки 3-7 секунд.
// Рандомизация предотвращает создание детектируемых паттернов активности.
func (m *connectionMonitor) randomCheckInterval() time.Duration {
	// 3 + (0..4) = 3-7 секунд
	n, _ := rand.Int(rand.Reader, big.NewInt(5))
	return time.Duration(3+n.Int64()) * time.Second
}

// randomKeepaliveInterval генерирует рандомизированный интервал keepalive 10-20 секунд.
// Аналогично серверной стороне — предотвращает DPI fingerprinting по фиксированному интервалу.
func randomKeepaliveInterval() time.Duration {
	// 10 + (0..10) = 10-20 секунд
	n, _ := rand.Int(rand.Reader, big.NewInt(11))
	return time.Duration(10+n.Int64()) * time.Second
}
