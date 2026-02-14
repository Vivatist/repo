package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/novavpn/vpn-server/internal/protocol"
)

// ═══════════════════════════════════════════════════════
//  Stress-режим: ступенчатый нагрузочный тест
//
//  Постепенно увеличивает число клиентов (step by step),
//  на каждой ступени каждый клиент генерирует реалистичный
//  трафик (keepalive + burst data). Тест останавливается
//  при достижении порога деградации.
//
//  Метрики:
//  - Keepalive sent/recv → для расчёта потерь и RTT
//  - Data sent → для нагрузки (one-way, без ответа)
// ═══════════════════════════════════════════════════════

// StressConfig — конфигурация stress-теста.
type StressConfig struct {
	ServerAddr       string
	PSKHex           string
	Email            string
	Password         string
	HandshakeTimeout time.Duration
	PacketSize       int

	// Stress-параметры
	StartClients  int           // Начальное число клиентов (напр. 10)
	StepSize      int           // Шаг увеличения (напр. 25)
	MaxClients    int           // Потолок (напр. 200)
	StepDuration  time.Duration // Время каждой ступени (напр. 15s)
	BurstInterval time.Duration // Интервал между burst'ами data (напр. 300ms)
	BurstSize     int           // Пакетов в burst'е (напр. 5)
}

// StressReport — итоговый отчёт stress-теста.
type StressReport struct {
	Timestamp        time.Time    `json:"timestamp"`
	ServerAddr       string       `json:"server_addr"`
	Steps            []StepResult `json:"steps"`
	MaxStableClients int          `json:"max_stable_clients"`
	MaxTestedClients int          `json:"max_tested_clients"`
	StopReason       string       `json:"stop_reason"`
	TotalDuration    string       `json:"total_duration"`
}

// StepResult — результат одной ступени.
type StepResult struct {
	TargetClients    int           `json:"target_clients"`
	ConnectedClients int           `json:"connected_clients"`
	HandshakeErrors  int           `json:"handshake_errors"`
	HandshakeAvg     time.Duration `json:"handshake_avg_ns"`
	HandshakeAvgStr  string        `json:"handshake_avg"`
	HandshakeMax     time.Duration `json:"handshake_max_ns"`
	HandshakeMaxStr  string        `json:"handshake_max"`

	// RTT и потери — по keepalive (единственный request-response пакет)
	RTT           LatencyStats `json:"rtt"`
	KeepaliveSent uint64       `json:"keepalive_sent"`
	KeepaliveRecv uint64       `json:"keepalive_recv"`
	KeepaliveLoss float64      `json:"keepalive_loss_percent"`

	// Data — one-way нагрузка (без ответа, для stress-эффекта)
	DataSent       uint64  `json:"data_sent_packets"`
	ThroughputPPS  float64 `json:"throughput_pps"`
	ThroughputMbps float64 `json:"throughput_mbps"`

	Status  string `json:"status"` // "OK", "DEGRADED", "FAILED"
	Comment string `json:"comment,omitempty"`
}

// stressClient — клиент, живущий между ступенями.
type stressClient struct {
	client  *benchClient
	stopCh  chan struct{}
	metrics stressClientMetrics
}

// stressClientMetrics — потокобезопасные метрики клиента.
//
// Keepalive — request-response: для подсчёта потерь и RTT.
// Data — one-way: сервер расшифровывает → TUN → ядро. Ответа нет.
type stressClientMetrics struct {
	keepaliveSent atomic.Uint64
	keepaliveRecv atomic.Uint64
	dataSent      atomic.Uint64
	sendErrors    atomic.Uint64

	// RTT вычисляется через FIFO очередь времён отправки keepalive.
	// Receiver goroutine снимает верхний элемент при получении keepalive-ответа.
	rttMu      sync.Mutex
	rttSamples []time.Duration
	sendTimes  []time.Time // FIFO: время отправки keepalive
}

// Пороги деградации
const (
	// Handshake: >20% неудач = FAILED
	stressHandshakeFailThreshold = 0.20
	// Потери keepalive: >10% = DEGRADED, >30% = FAILED
	stressLossDegraded = 10.0
	stressLossFailed   = 30.0
	// RTT p95: >50мс = DEGRADED, >200мс = FAILED
	stressRTTP95Degraded = 50 * time.Millisecond
	stressRTTP95Failed   = 200 * time.Millisecond
)

func runStressBenchmark(cfg *StressConfig) *StressReport {
	report := &StressReport{
		Timestamp:  time.Now(),
		ServerAddr: cfg.ServerAddr,
	}
	totalStart := time.Now()

	// Живые клиенты (переживают ступени)
	var aliveClients []*stressClient
	var aliveClientsMu sync.Mutex

	log.Println()
	log.Println("═══════════════════════════════════════════════════════════")
	log.Println("  STRESS TEST — ступенчатое наращивание нагрузки")
	log.Println("═══════════════════════════════════════════════════════════")
	log.Printf("  Сервер:       %s", cfg.ServerAddr)
	log.Printf("  Старт:        %d клиентов", cfg.StartClients)
	log.Printf("  Шаг:          +%d клиентов", cfg.StepSize)
	log.Printf("  Потолок:      %d клиентов", cfg.MaxClients)
	log.Printf("  Длит. ступени: %s", cfg.StepDuration)
	log.Printf("  Burst:        %d пакетов каждые %s", cfg.BurstSize, cfg.BurstInterval)
	log.Println("═══════════════════════════════════════════════════════════")

	maxStable := 0
	var stopReason string

	// Формируем список ступеней заранее
	var steps []int
	for n := cfg.StartClients; n <= cfg.MaxClients; n += cfg.StepSize {
		steps = append(steps, n)
	}
	// Если последняя ступень не дотягивает до потолка — добавляем финальную
	if len(steps) > 0 && steps[len(steps)-1] < cfg.MaxClients {
		steps = append(steps, cfg.MaxClients)
	}

	for _, targetClients := range steps {
		log.Println()
		log.Printf("─── СТУПЕНЬ: %d клиентов ──────────────────────────────", targetClients)

		// Сколько новых клиентов нужно поднять?
		aliveClientsMu.Lock()
		newCount := targetClients - len(aliveClients)
		aliveClientsMu.Unlock()

		if newCount <= 0 {
			newCount = 0
		}

		// Фаза 1: Подключение новых клиентов
		var newClients []*stressClient
		var hsTimes []time.Duration
		hsErrors := 0

		if newCount > 0 {
			log.Printf("[CONNECT] Подключение %d новых клиентов...", newCount)
			var connectWG sync.WaitGroup
			var connectMu sync.Mutex

			for i := 0; i < newCount; i++ {
				connectWG.Add(1)
				go func() {
					defer connectWG.Done()
					benchCfg := &BenchConfig{
						ServerAddr:       cfg.ServerAddr,
						PSKHex:           cfg.PSKHex,
						Email:            cfg.Email,
						Password:         cfg.Password,
						HandshakeTimeout: cfg.HandshakeTimeout,
						PacketSize:       cfg.PacketSize,
					}
					start := time.Now()
					client, err := newBenchClient(benchCfg)
					hsTime := time.Since(start)

					connectMu.Lock()
					defer connectMu.Unlock()

					if err != nil {
						hsErrors++
						hsTimes = append(hsTimes, hsTime)
						return
					}

					hsTimes = append(hsTimes, hsTime)
					sc := &stressClient{
						client: client,
						stopCh: make(chan struct{}),
					}
					newClients = append(newClients, sc)
				}()

				// Задержка между подключениями (не DDoS)
				time.Sleep(30 * time.Millisecond)
			}
			connectWG.Wait()

			log.Printf("[CONNECT] Подключено %d/%d (ошибок: %d)", len(newClients), newCount, hsErrors)

			// Запускаем загрузку для новых клиентов
			for _, sc := range newClients {
				go sc.runStressTraffic(cfg)
			}

			aliveClientsMu.Lock()
			aliveClients = append(aliveClients, newClients...)
			aliveClientsMu.Unlock()
		}

		// Сброс метрик всех живых клиентов перед измерением
		aliveClientsMu.Lock()
		for _, sc := range aliveClients {
			sc.resetMetrics()
		}
		connectedTotal := len(aliveClients)
		aliveClientsMu.Unlock()

		// Фаза 2: Сбор метрик (ждём stepDuration)
		log.Printf("[MEASURE] Сбор метрик %s (активных клиентов: %d)...", cfg.StepDuration, connectedTotal)
		time.Sleep(cfg.StepDuration)

		// Фаза 3: Сбор результатов
		step := StepResult{
			TargetClients:    targetClients,
			ConnectedClients: connectedTotal,
			HandshakeErrors:  hsErrors,
		}

		// Handshake stats
		if len(hsTimes) > 0 {
			sort.Slice(hsTimes, func(i, j int) bool { return hsTimes[i] < hsTimes[j] })
			var total time.Duration
			for _, t := range hsTimes {
				total += t
			}
			step.HandshakeAvg = total / time.Duration(len(hsTimes))
			step.HandshakeMax = hsTimes[len(hsTimes)-1]
		}
		step.HandshakeAvgStr = step.HandshakeAvg.Round(time.Microsecond).String()
		step.HandshakeMaxStr = step.HandshakeMax.Round(time.Microsecond).String()

		// Агрегируем метрики всех клиентов
		var allRTT []time.Duration
		var totalKASent, totalKARecv, totalDataSent uint64

		aliveClientsMu.Lock()
		for _, sc := range aliveClients {
			totalKASent += sc.metrics.keepaliveSent.Load()
			totalKARecv += sc.metrics.keepaliveRecv.Load()
			totalDataSent += sc.metrics.dataSent.Load()

			sc.metrics.rttMu.Lock()
			allRTT = append(allRTT, sc.metrics.rttSamples...)
			sc.metrics.rttMu.Unlock()
		}
		aliveClientsMu.Unlock()

		step.KeepaliveSent = totalKASent
		step.KeepaliveRecv = totalKARecv
		if totalKASent > 0 && totalKASent > totalKARecv {
			step.KeepaliveLoss = float64(totalKASent-totalKARecv) / float64(totalKASent) * 100
		}
		step.DataSent = totalDataSent

		step.RTT = computeLatencyStats(allRTT)

		seconds := cfg.StepDuration.Seconds()
		if seconds > 0 {
			step.ThroughputPPS = float64(totalDataSent) / seconds
			step.ThroughputMbps = float64(totalDataSent) * float64(cfg.PacketSize) * 8 / seconds / 1_000_000
		}

		// Оценка статуса ступени
		step.Status, step.Comment = evaluateStepStatus(step, targetClients)

		// Лог результатов ступени
		logStepResult(step)

		report.Steps = append(report.Steps, step)
		report.MaxTestedClients = targetClients

		if step.Status == "OK" || step.Status == "DEGRADED" {
			if step.ConnectedClients > maxStable {
				maxStable = step.ConnectedClients
			}
		}

		// Решение о продолжении
		if step.Status == "FAILED" {
			stopReason = fmt.Sprintf("Деградация на %d клиентах: %s", targetClients, step.Comment)
			log.Printf("[STOP] %s", stopReason)
			break
		}
	}

	if stopReason == "" {
		stopReason = fmt.Sprintf("Достигнут потолок %d клиентов", cfg.MaxClients)
	}

	// Отключаем всех клиентов
	log.Println()
	log.Printf("[CLEANUP] Отключение %d клиентов...", len(aliveClients))
	aliveClientsMu.Lock()
	for _, sc := range aliveClients {
		close(sc.stopCh)
		sc.client.disconnect()
	}
	aliveClientsMu.Unlock()

	report.MaxStableClients = maxStable
	report.StopReason = stopReason
	report.TotalDuration = time.Since(totalStart).Round(time.Second).String()

	return report
}

// resetMetrics обнуляет метрики клиента перед новой ступенью.
func (sc *stressClient) resetMetrics() {
	sc.metrics.keepaliveSent.Store(0)
	sc.metrics.keepaliveRecv.Store(0)
	sc.metrics.dataSent.Store(0)
	sc.metrics.sendErrors.Store(0)
	sc.metrics.rttMu.Lock()
	sc.metrics.rttSamples = sc.metrics.rttSamples[:0]
	sc.metrics.sendTimes = sc.metrics.sendTimes[:0]
	sc.metrics.rttMu.Unlock()
}

// runStressTraffic — реалистичный паттерн трафика одного клиента.
//
// Архитектура:
//   - Receiver goroutine: единственный читатель сокета.
//     Считает keepalive-ответы, вычисляет RTT через FIFO sendTimes.
//   - Main goroutine: отправляет keepalive (каждую 1с) и data burst'ы.
//     Keepalive → keepaliveSent + sendTimes FIFO.
//     Data → dataSent (one-way, ответа нет).
func (sc *stressClient) runStressTraffic(cfg *StressConfig) {
	bc := sc.client

	// Receiver goroutine: единственный читатель сокета.
	// Парсит keepalive-ответы, вычисляет RTT через FIFO.
	go func() {
		buf := make([]byte, 2048)
		for {
			bc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := bc.conn.Read(buf)
			if err != nil {
				select {
				case <-sc.stopCh:
					return
				default:
					continue
				}
			}

			if n < protocol.MinPacketSize {
				continue
			}

			// Парсим пакет: QUIC(5) + SID(4) + Type(1)
			raw := buf[:n]
			if n < protocol.QUICHeaderSize+protocol.SessionIDSize+protocol.PacketTypeSize {
				continue
			}
			// Деобфускация заголовка (SID + Type)
			protocol.ObfuscateHeader(raw[protocol.QUICHeaderSize:], sc.client.headerMask, false)
			pktType := protocol.PacketType(raw[protocol.QUICHeaderSize+protocol.SessionIDSize])

			if pktType == protocol.PacketKeepalive {
				recvTime := time.Now()
				sc.metrics.keepaliveRecv.Add(1)

				// FIFO: берём время отправки первого ожидающего keepalive
				sc.metrics.rttMu.Lock()
				if len(sc.metrics.sendTimes) > 0 {
					rtt := recvTime.Sub(sc.metrics.sendTimes[0])
					if rtt >= 0 {
						sc.metrics.rttSamples = append(sc.metrics.rttSamples, rtt)
					}
					sc.metrics.sendTimes = sc.metrics.sendTimes[1:]
				}
				sc.metrics.rttMu.Unlock()
			}

			select {
			case <-sc.stopCh:
				return
			default:
			}
		}
	}()

	// Keepalive каждую 1 секунду (15 семплов за 15-секундную ступень)
	keepaliveTicker := time.NewTicker(1 * time.Second)
	defer keepaliveTicker.Stop()

	// Data burst
	burstTicker := time.NewTicker(cfg.BurstInterval)
	defer burstTicker.Stop()

	// Фейковый IPv4 пакет для data burst
	plaintext := makeStressPayload(bc, cfg.PacketSize)

	for {
		select {
		case <-sc.stopCh:
			return

		case <-keepaliveTicker.C:
			// Отправляем keepalive
			kaBuf, err := bc.buildKeepalive()
			if err != nil {
				continue
			}
			sendTime := time.Now()
			bc.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			if _, err := bc.conn.Write(kaBuf); err != nil {
				sc.metrics.sendErrors.Add(1)
				continue
			}
			sc.metrics.keepaliveSent.Add(1)

			// Записываем время отправки в FIFO для RTT
			sc.metrics.rttMu.Lock()
			sc.metrics.sendTimes = append(sc.metrics.sendTimes, sendTime)
			// Очищаем старые pending (>5 сек)
			now := time.Now()
			for len(sc.metrics.sendTimes) > 0 && now.Sub(sc.metrics.sendTimes[0]) > 5*time.Second {
				sc.metrics.sendTimes = sc.metrics.sendTimes[1:]
			}
			sc.metrics.rttMu.Unlock()

		case <-burstTicker.C:
			// Data burst: шлём BurstSize пакетов залпом (one-way)
			for b := 0; b < cfg.BurstSize; b++ {
				pkt, err := bc.buildDataPacket(plaintext)
				if err != nil {
					sc.metrics.sendErrors.Add(1)
					continue
				}
				bc.conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				if _, err := bc.conn.Write(pkt); err != nil {
					sc.metrics.sendErrors.Add(1)
					continue
				}
				sc.metrics.dataSent.Add(1)
			}

			// Добавляем jitter к burst interval (±30%)
			jitter := time.Duration(rand.Int63n(int64(cfg.BurstInterval) * 6 / 10))
			jitter -= time.Duration(int64(cfg.BurstInterval) * 3 / 10)
			burstTicker.Reset(cfg.BurstInterval + jitter)
		}
	}
}

// makeStressPayload — создаёт фейковый IPv4 пакет с dst=10.8.0.1 для TUN.
func makeStressPayload(bc *benchClient, pktSize int) []byte {
	plaintext := make([]byte, pktSize)
	if pktSize >= 20 {
		plaintext[0] = 0x45 // IPv4, IHL=5
		plaintext[1] = 0x00
		plaintext[2] = byte(pktSize >> 8)
		plaintext[3] = byte(pktSize)
		plaintext[8] = 64   // TTL
		plaintext[9] = 0x11 // UDP
		if bc.assignedIP != nil {
			ip4 := bc.assignedIP.To4()
			if ip4 != nil {
				copy(plaintext[12:16], ip4)
			}
		}
		// Dst: 10.8.0.1 (server VPN IP)
		plaintext[16] = 10
		plaintext[17] = 8
		plaintext[18] = 0
		plaintext[19] = 1
	}
	return plaintext
}

// evaluateStepStatus — оценивает результат ступени.
func evaluateStepStatus(step StepResult, targetClients int) (status string, comment string) {
	var issues []string

	// Handshake failures
	hsTotal := step.ConnectedClients + step.HandshakeErrors
	if hsTotal > 0 {
		hsFailRate := float64(step.HandshakeErrors) / float64(hsTotal)
		if hsFailRate > stressHandshakeFailThreshold {
			issues = append(issues, fmt.Sprintf("handshake failures %.0f%%", hsFailRate*100))
			return "FAILED", strings.Join(issues, ", ")
		}
	}

	// Подключилось меньше половины
	if step.ConnectedClients < targetClients/2 {
		issues = append(issues, fmt.Sprintf("подключилось %d/%d", step.ConnectedClients, targetClients))
		return "FAILED", strings.Join(issues, ", ")
	}

	// RTT p95: пропускаем если нет данных
	if step.RTT.Count > 0 {
		if step.RTT.P95 > stressRTTP95Failed {
			issues = append(issues, fmt.Sprintf("RTT p95 = %s", step.RTT.P95Str))
			return "FAILED", strings.Join(issues, ", ")
		}
		if step.RTT.P95 > stressRTTP95Degraded {
			issues = append(issues, fmt.Sprintf("RTT p95 = %s", step.RTT.P95Str))
		}
	}

	// Потери keepalive (основной показатель деградации сервера)
	if step.KeepaliveSent > 0 {
		if step.KeepaliveLoss > stressLossFailed {
			issues = append(issues, fmt.Sprintf("потери keepalive %.1f%%", step.KeepaliveLoss))
			return "FAILED", strings.Join(issues, ", ")
		}
		if step.KeepaliveLoss > stressLossDegraded {
			issues = append(issues, fmt.Sprintf("потери keepalive %.1f%%", step.KeepaliveLoss))
		}
	}

	if len(issues) > 0 {
		return "DEGRADED", strings.Join(issues, ", ")
	}
	return "OK", ""
}

// logStepResult — выводит результат ступени в лог.
func logStepResult(step StepResult) {
	statusColor := "OK"
	switch step.Status {
	case "OK":
		statusColor = "✅ OK"
	case "DEGRADED":
		statusColor = "⚠️  DEGRADED"
	case "FAILED":
		statusColor = "❌ FAILED"
	}

	log.Printf("  Результат: %s", statusColor)
	log.Printf("    Подключения:  %d/%d (ошибок: %d)", step.ConnectedClients, step.TargetClients, step.HandshakeErrors)
	log.Printf("    Handshake:    avg %s, max %s", step.HandshakeAvgStr, step.HandshakeMaxStr)
	if step.RTT.Count > 0 {
		log.Printf("    RTT:          p50 %s, p95 %s, p99 %s (%d семплов)", step.RTT.P50Str, step.RTT.P95Str, step.RTT.P99Str, step.RTT.Count)
	} else {
		log.Printf("    RTT:          нет данных")
	}
	log.Printf("    Keepalive:    отправлено %d, получено %d (потери %.1f%%)", step.KeepaliveSent, step.KeepaliveRecv, step.KeepaliveLoss)
	log.Printf("    Data (→):     %d пакетов, %.0f pps, %.1f Мбит/с", step.DataSent, step.ThroughputPPS, step.ThroughputMbps)
	if step.Comment != "" {
		log.Printf("    Причина:      %s", step.Comment)
	}
}

// printStressReport — финальный отчёт stress-теста.
func printStressReport(r *StressReport) {
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         STRESS TEST — ИТОГОВЫЙ ОТЧЁТ                                 ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Сервер:                  %-59s║\n", r.ServerAddr)
	fmt.Printf("║  Макс. стабильных:        %-59s║\n", fmt.Sprintf("%d клиентов", r.MaxStableClients))
	fmt.Printf("║  Макс. протестировано:     %-59s║\n", fmt.Sprintf("%d клиентов", r.MaxTestedClients))
	fmt.Printf("║  Общее время:             %-59s║\n", r.TotalDuration)
	fmt.Printf("║  Причина остановки:       %-59s║\n", truncStr(r.StopReason, 59))
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                                       ║")

	// Таблица ступеней
	fmt.Println("║  Клиенты  Подкл  Handshake    RTT p50    RTT p95   KA потери  Data pps   Статус  ║")
	fmt.Println("║  ───────  ─────  ─────────  ─────────  ─────────  ─────────  ─────────  ──────  ║")

	for _, step := range r.Steps {
		statusIcon := "✅"
		switch step.Status {
		case "DEGRADED":
			statusIcon = "⚠️"
		case "FAILED":
			statusIcon = "❌"
		}

		rttP50 := "—"
		rttP95 := "—"
		if step.RTT.Count > 0 {
			rttP50 = step.RTT.P50Str
			rttP95 = step.RTT.P95Str
		}

		kaLoss := "—"
		if step.KeepaliveSent > 0 {
			kaLoss = fmt.Sprintf("%.1f%%", step.KeepaliveLoss)
		}

		fmt.Printf("║  %4d     %4d   %9s  %9s  %9s  %9s  %7.0f    %s    ║\n",
			step.TargetClients,
			step.ConnectedClients,
			step.HandshakeAvgStr,
			rttP50,
			rttP95,
			kaLoss,
			step.ThroughputPPS,
			statusIcon,
		)
	}

	fmt.Println("║                                                                                       ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════════════════════╣")

	// Вердикт
	verdict := fmt.Sprintf("Сервер стабильно держит %d одновременных клиентов", r.MaxStableClients)
	if r.MaxStableClients >= r.MaxTestedClients {
		verdict += " (потолок не достигнут, можно больше)"
	}
	fmt.Printf("║  ВЕРДИКТ: %-73s║\n", verdict)
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════════════════╝")
}

func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func saveStressJSONReport(r *StressReport, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
