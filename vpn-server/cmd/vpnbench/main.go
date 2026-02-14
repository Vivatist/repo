// vpnbench — нагрузочный тест NovaVPN сервера.
//
// Создаёт N одновременных VPN-клиентов, каждый выполняет handshake,
// затем обменивается data-пакетами (ping-pong). Собирает метрики:
//   - Время handshake (мин/сред/макс/p95/p99)
//   - RTT data-пакетов (мин/сред/макс/p95/p99)
//   - Throughput (пакетов/сек, байт/сек)
//   - Потери пакетов (%)
//   - Ошибки подключения
//
// Использование:
//
//	vpnbench -server 212.118.41.227:443 -psk <hex> -email test@novavpn.app -password secret -clients 10 -duration 30s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	// Параметры командной строки
	serverAddr := flag.String("server", "", "Адрес VPN-сервера (host:port)")
	pskHex := flag.String("psk", "", "Pre-Shared Key (hex, 64 символа)")
	email := flag.String("email", "", "Email для аутентификации")
	password := flag.String("password", "", "Пароль для аутентификации")
	numClients := flag.Int("clients", 1, "Количество одновременных клиентов")
	duration := flag.Duration("duration", 30*time.Second, "Длительность теста")
	pktSize := flag.Int("pktsize", 1000, "Размер data-пакета (plaintext, байт)")
	interval := flag.Duration("interval", 100*time.Millisecond, "Интервал между ping-пакетами на клиента")
	timeout := flag.Duration("timeout", 30*time.Second, "Таймаут handshake")
	mode := flag.String("mode", "rtt", "Режим: rtt | throughput | stress")
	jsonOutput := flag.String("json", "", "Путь для JSON-отчёта (пусто = только консоль)")

	// Stress-специфичные параметры
	stressStart := flag.Int("stress-start", 10, "Stress: начальное число клиентов")
	stressStep := flag.Int("stress-step", 25, "Stress: шаг увеличения клиентов")
	stressMax := flag.Int("stress-max", 200, "Stress: потолок клиентов")
	stressStepDur := flag.Duration("stress-step-duration", 15*time.Second, "Stress: длительность каждой ступени")
	stressBurstInterval := flag.Duration("stress-burst-interval", 300*time.Millisecond, "Stress: интервал между burst'ами")
	stressBurstSize := flag.Int("stress-burst-size", 5, "Stress: пакетов в burst'е")
	flag.Parse()

	if *serverAddr == "" || *email == "" || *password == "" {
		fmt.Println("Использование: vpnbench -server HOST:PORT -psk PSK -email EMAIL -password PASS [опции]")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *mode != "rtt" && *mode != "throughput" && *mode != "stress" {
		fmt.Println("[ОШИБКА] -mode должен быть 'rtt', 'throughput' или 'stress'")
		os.Exit(1)
	}

	// Stress режим — отдельный путь
	if *mode == "stress" {
		stressCfg := &StressConfig{
			ServerAddr:       *serverAddr,
			PSKHex:           *pskHex,
			Email:            *email,
			Password:         *password,
			HandshakeTimeout: *timeout,
			PacketSize:       *pktSize,
			StartClients:     *stressStart,
			StepSize:         *stressStep,
			MaxClients:       *stressMax,
			StepDuration:     *stressStepDur,
			BurstInterval:    *stressBurstInterval,
			BurstSize:        *stressBurstSize,
		}

		stressReport := runStressBenchmark(stressCfg)
		printStressReport(stressReport)

		if *jsonOutput != "" {
			if err := saveStressJSONReport(stressReport, *jsonOutput); err != nil {
				log.Printf("[ОШИБКА] Не удалось сохранить JSON: %v", err)
			} else {
				log.Printf("[OK] JSON-отчёт сохранён: %s", *jsonOutput)
			}
		}
		return
	}

	cfg := &BenchConfig{
		ServerAddr:       *serverAddr,
		PSKHex:           *pskHex,
		Email:            *email,
		Password:         *password,
		NumClients:       *numClients,
		Duration:         *duration,
		PacketSize:       *pktSize,
		PingInterval:     *interval,
		HandshakeTimeout: *timeout,
		Mode:             *mode,
	}

	log.Println("═══════════════════════════════════════════")
	log.Println("  NovaVPN Benchmark Tool")
	log.Println("═══════════════════════════════════════════")
	log.Printf("  Сервер:    %s", cfg.ServerAddr)
	log.Printf("  Режим:     %s", cfg.Mode)
	log.Printf("  Клиенты:   %d", cfg.NumClients)
	log.Printf("  Время:     %s", cfg.Duration)
	log.Printf("  Размер:    %d байт", cfg.PacketSize)
	if cfg.Mode == "rtt" {
		log.Printf("  Интервал:  %s", cfg.PingInterval)
	}
	log.Println("═══════════════════════════════════════════")

	report := runBenchmark(cfg)

	printReport(report)

	if *jsonOutput != "" {
		if err := saveJSONReport(report, *jsonOutput); err != nil {
			log.Printf("[ОШИБКА] Не удалось сохранить JSON: %v", err)
		} else {
			log.Printf("[OK] JSON-отчёт сохранён: %s", *jsonOutput)
		}
	}
}

// BenchConfig — конфигурация нагрузочного теста.
type BenchConfig struct {
	ServerAddr       string
	PSKHex           string
	Email            string
	Password         string
	NumClients       int
	Duration         time.Duration
	PacketSize       int
	PingInterval     time.Duration
	HandshakeTimeout time.Duration
	Mode             string // "rtt" или "throughput"
}

// BenchReport — итоговый отчёт нагрузочного теста.
type BenchReport struct {
	Timestamp   time.Time     `json:"timestamp"`
	ServerAddr  string        `json:"server_addr"`
	Mode        string        `json:"mode"`
	NumClients  int           `json:"num_clients"`
	Duration    time.Duration `json:"duration_ns"`
	DurationStr string        `json:"duration"`
	PacketSize  int           `json:"packet_size_bytes"`

	// Handshake метрики
	Handshake LatencyStats `json:"handshake"`

	// RTT метрики (data-пакеты)
	RTT LatencyStats `json:"rtt"`

	// Throughput
	TotalPacketsSent uint64  `json:"total_packets_sent"`
	TotalPacketsRecv uint64  `json:"total_packets_recv"`
	PacketLossRate   float64 `json:"packet_loss_percent"`
	PacketsPerSec    float64 `json:"packets_per_sec"`
	MbitsPerSec      float64 `json:"mbits_per_sec"`

	// Ошибки
	HandshakeErrors int      `json:"handshake_errors"`
	SendErrors      uint64   `json:"send_errors"`
	RecvTimeouts    uint64   `json:"recv_timeouts"`
	ErrorMessages   []string `json:"error_messages,omitempty"`
}

// LatencyStats — статистика задержек.
type LatencyStats struct {
	Count  int           `json:"count"`
	Min    time.Duration `json:"min_ns"`
	Avg    time.Duration `json:"avg_ns"`
	Max    time.Duration `json:"max_ns"`
	P50    time.Duration `json:"p50_ns"`
	P95    time.Duration `json:"p95_ns"`
	P99    time.Duration `json:"p99_ns"`
	MinStr string        `json:"min"`
	AvgStr string        `json:"avg"`
	MaxStr string        `json:"max"`
	P50Str string        `json:"p50"`
	P95Str string        `json:"p95"`
	P99Str string        `json:"p99"`
}

// clientResult — результаты одного клиента.
type clientResult struct {
	handshakeTime time.Duration
	handshakeErr  error
	rttSamples    []time.Duration
	packetsSent   uint64
	packetsRecv   uint64
	sendErrors    uint64
	recvTimeouts  uint64
}

func runBenchmark(cfg *BenchConfig) *BenchReport {
	results := make([]clientResult, cfg.NumClients)
	var wg sync.WaitGroup

	// Счётчик успешных handshake (для прогресса)
	var connectedCount atomic.Int32

	log.Printf("[BENCH] Подключение %d клиентов...", cfg.NumClients)

	// Фаза 1: Параллельный handshake всех клиентов
	for i := 0; i < cfg.NumClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			start := time.Now()
			client, err := newBenchClient(cfg)
			hsTime := time.Since(start)
			if err != nil {
				results[idx].handshakeErr = err
				results[idx].handshakeTime = hsTime
				return
			}
			results[idx].handshakeTime = hsTime

			connectedCount.Add(1)
			log.Printf("[CLIENT-%d] Подключён (сессия #%d, IP: %s, handshake: %s)",
				idx, client.sessionID, client.assignedIP, hsTime.Round(time.Millisecond))

			// Фаза 2: Обмен данными
			var dataResult clientResult
			if cfg.Mode == "throughput" {
				dataResult = client.runThroughputTest(cfg.Duration, cfg.PacketSize, idx)
			} else {
				dataResult = client.runDataExchange(cfg.Duration, cfg.PacketSize, cfg.PingInterval, idx)
			}
			results[idx].rttSamples = dataResult.rttSamples
			results[idx].packetsSent = dataResult.packetsSent
			results[idx].packetsRecv = dataResult.packetsRecv
			results[idx].sendErrors = dataResult.sendErrors
			results[idx].recvTimeouts = dataResult.recvTimeouts

			// Отключаемся
			client.disconnect()
		}(i)

		// Небольшая задержка между подключениями чтобы не DDoS'ить
		if i < cfg.NumClients-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}

	wg.Wait()
	log.Printf("[BENCH] Все клиенты завершили работу (%d/%d подключились)",
		connectedCount.Load(), cfg.NumClients)

	return buildReport(cfg, results)
}

func buildReport(cfg *BenchConfig, results []clientResult) *BenchReport {
	report := &BenchReport{
		Timestamp:   time.Now(),
		ServerAddr:  cfg.ServerAddr,
		Mode:        cfg.Mode,
		NumClients:  cfg.NumClients,
		Duration:    cfg.Duration,
		DurationStr: cfg.Duration.String(),
		PacketSize:  cfg.PacketSize,
	}

	// Собираем handshake метрики
	var hsTimes []time.Duration
	for i, r := range results {
		if r.handshakeErr != nil {
			report.HandshakeErrors++
			report.ErrorMessages = append(report.ErrorMessages,
				fmt.Sprintf("client-%d: %v", i, r.handshakeErr))
		} else {
			hsTimes = append(hsTimes, r.handshakeTime)
		}
	}
	report.Handshake = computeLatencyStats(hsTimes)

	// Собираем RTT метрики
	var allRTT []time.Duration
	for _, r := range results {
		allRTT = append(allRTT, r.rttSamples...)
		report.TotalPacketsSent += r.packetsSent
		report.TotalPacketsRecv += r.packetsRecv
		report.SendErrors += r.sendErrors
		report.RecvTimeouts += r.recvTimeouts
	}
	report.RTT = computeLatencyStats(allRTT)

	// Потери (только для RTT режима — throughput однонаправленный, потери не измеряются)
	if cfg.Mode != "throughput" {
		if report.TotalPacketsSent > 0 && report.TotalPacketsSent > report.TotalPacketsRecv {
			report.PacketLossRate = float64(report.TotalPacketsSent-report.TotalPacketsRecv) / float64(report.TotalPacketsSent) * 100
		}
	}

	// Throughput
	seconds := cfg.Duration.Seconds()
	if seconds > 0 {
		if cfg.Mode == "throughput" {
			// В режиме throughput считаем по отправленным (data — однонаправленный)
			report.PacketsPerSec = float64(report.TotalPacketsSent) / seconds
			report.MbitsPerSec = float64(report.TotalPacketsSent) * float64(cfg.PacketSize) * 8 / seconds / 1_000_000
		} else {
			report.PacketsPerSec = float64(report.TotalPacketsRecv) / seconds
			report.MbitsPerSec = float64(report.TotalPacketsRecv) * float64(cfg.PacketSize) * 8 / seconds / 1_000_000
		}
	}

	return report
}

func computeLatencyStats(samples []time.Duration) LatencyStats {
	if len(samples) == 0 {
		return LatencyStats{}
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

	var total time.Duration
	for _, s := range samples {
		total += s
	}

	stats := LatencyStats{
		Count: len(samples),
		Min:   samples[0],
		Avg:   total / time.Duration(len(samples)),
		Max:   samples[len(samples)-1],
		P50:   percentile(samples, 50),
		P95:   percentile(samples, 95),
		P99:   percentile(samples, 99),
	}

	stats.MinStr = stats.Min.Round(time.Microsecond).String()
	stats.AvgStr = stats.Avg.Round(time.Microsecond).String()
	stats.MaxStr = stats.Max.Round(time.Microsecond).String()
	stats.P50Str = stats.P50.Round(time.Microsecond).String()
	stats.P95Str = stats.P95.Round(time.Microsecond).String()
	stats.P99Str = stats.P99.Round(time.Microsecond).String()

	return stats
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := len(sorted) * p / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func printReport(r *BenchReport) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  РЕЗУЛЬТАТЫ НАГРУЗОЧНОГО ТЕСТА")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  Время:           %s\n", r.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Сервер:          %s\n", r.ServerAddr)
	fmt.Printf("  Режим:           %s\n", r.Mode)
	fmt.Printf("  Клиенты:         %d (ошибок подключения: %d)\n", r.NumClients, r.HandshakeErrors)
	fmt.Printf("  Длительность:    %s\n", r.DurationStr)
	fmt.Printf("  Размер пакета:   %d байт\n", r.PacketSize)
	fmt.Println()

	fmt.Println("  ── Handshake ──────────────────────────────────────────")
	if r.Handshake.Count > 0 {
		fmt.Printf("    Кол-во:     %d\n", r.Handshake.Count)
		fmt.Printf("    Min:        %s\n", r.Handshake.MinStr)
		fmt.Printf("    Avg:        %s\n", r.Handshake.AvgStr)
		fmt.Printf("    P50:        %s\n", r.Handshake.P50Str)
		fmt.Printf("    P95:        %s\n", r.Handshake.P95Str)
		fmt.Printf("    P99:        %s\n", r.Handshake.P99Str)
		fmt.Printf("    Max:        %s\n", r.Handshake.MaxStr)
	} else {
		fmt.Println("    Нет данных (все handshake неуспешны)")
	}
	fmt.Println()

	fmt.Println("  ── RTT (data round-trip) ─────────────────────────────")
	if r.RTT.Count > 0 {
		fmt.Printf("    Кол-во:     %d\n", r.RTT.Count)
		fmt.Printf("    Min:        %s\n", r.RTT.MinStr)
		fmt.Printf("    Avg:        %s\n", r.RTT.AvgStr)
		fmt.Printf("    P50:        %s\n", r.RTT.P50Str)
		fmt.Printf("    P95:        %s\n", r.RTT.P95Str)
		fmt.Printf("    P99:        %s\n", r.RTT.P99Str)
		fmt.Printf("    Max:        %s\n", r.RTT.MaxStr)
	} else {
		fmt.Println("    Нет данных")
	}
	fmt.Println()

	fmt.Println("  ── Throughput ─────────────────────────────────────────")
	fmt.Printf("    Отправлено: %d пакетов\n", r.TotalPacketsSent)
	if r.Mode == "throughput" {
		fmt.Printf("    (однонаправленный тест — потери не измеряются)\n")
	} else {
		fmt.Printf("    Получено:   %d пакетов\n", r.TotalPacketsRecv)
		fmt.Printf("    Потери:     %.2f%%\n", r.PacketLossRate)
	}
	fmt.Printf("    Скорость:   %.1f пакетов/сек\n", r.PacketsPerSec)
	fmt.Printf("    Скорость:   %.2f Мбит/с\n", r.MbitsPerSec)
	fmt.Println()

	fmt.Println("  ── Ошибки ────────────────────────────────────────────")
	fmt.Printf("    Handshake:  %d\n", r.HandshakeErrors)
	fmt.Printf("    Отправка:   %d\n", r.SendErrors)
	fmt.Printf("    Таймауты:   %d\n", r.RecvTimeouts)
	if len(r.ErrorMessages) > 0 {
		for _, msg := range r.ErrorMessages {
			fmt.Printf("    · %s\n", msg)
		}
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
}

func saveJSONReport(r *BenchReport, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
