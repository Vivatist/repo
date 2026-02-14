package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/novavpn/vpn-server/config"
	"github.com/novavpn/vpn-server/internal/auth"
	"github.com/novavpn/vpn-server/internal/protocol"
	"github.com/novavpn/vpn-server/internal/tun"
)

// VPNServer представляет VPN-сервер.
type VPNServer struct {
	cfg *config.ServerConfig
	psk [protocol.KeySize]byte

	// UDP-соединение
	udpConn *net.UDPConn

	// TUN-интерфейс
	tunDev *tun.TUNDevice

	// Менеджер сессий
	sessions *SessionManager

	// Batch sender для пакетной отправки UDP через sendmmsg (Linux)
	batch *batchSender

	// Batch receiver для пакетного приёма UDP через recvmmsg (Linux)
	batchRecv *batchReceiver

	// Семафор для ограничения параллельных handshake (Argon2id — CPU-intensive).
	// Argon2id(time=1, memory=4MB) × N горутин. При 64 параллельных: 64 × 4МБ = 256МБ.
	handshakeSem chan struct{}

	// Контекст для graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Хранилище пользователей (email + пароль)
	userStore *auth.UserStore
}

// NewVPNServer создаёт новый VPN-сервер.
func NewVPNServer(cfg *config.ServerConfig) (*VPNServer, error) {
	// Декодируем PSK
	psk, err := protocol.DecodePSK(cfg.PreSharedKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования PSK: %w", err)
	}

	// Создаём менеджер сессий
	sessionTimeout := time.Duration(cfg.SessionTimeout) * time.Second
	sessions, err := NewSessionManager(cfg.VPNSubnet, cfg.ServerVPNIP, cfg.MaxClients, sessionTimeout)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания менеджера сессий: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Создаём хранилище пользователей
	userStore := auth.NewUserStore(cfg.UsersFile)

	srv := &VPNServer{
		cfg:          cfg,
		psk:          psk,
		sessions:     sessions,
		ctx:          ctx,
		cancel:       cancel,
		userStore:    userStore,
		handshakeSem: make(chan struct{}, cfg.MaxParallelHandshakes), // N параллельных Argon2id (N × 4MB RAM)
	}

	// Загружаем пользователей
	if err := srv.loadUsers(); err != nil {
		cancel()
		return nil, err
	}

	return srv, nil
}

// loadUsers загружает список пользователей.
func (s *VPNServer) loadUsers() error {
	if err := s.userStore.LoadUsers(); err != nil {
		log.Printf("[WARN] Не удалось загрузить пользователей из %s: %v",
			s.cfg.UsersFile, err)
		log.Println("[WARN] Добавьте пользователей: novavpn-server -adduser -email user@example.com -password secret")
		return nil
	}

	log.Printf("[CONFIG] Загружено %d пользователей", s.userStore.Count())
	return nil
}

// tuneSocketBuffers увеличивает буферы UDP-сокета.
// Пытается установить 16 МБ, при неудаче fallback к меньшим значениям.
// Логирует реальные размеры буферов, установленные ядром.
func (s *VPNServer) tuneSocketBuffers(conn *net.UDPConn) {
	// Попытки в порядке убывания: 16MB, 8MB, 4MB
	targets := []int{16 * 1024 * 1024, 8 * 1024 * 1024, 4 * 1024 * 1024}

	for _, size := range targets {
		if err := conn.SetReadBuffer(size); err == nil {
			log.Printf("[UDP] Read buffer установлен: %d МБ", size/1024/1024)
			break
		}
	}
	for _, size := range targets {
		if err := conn.SetWriteBuffer(size); err == nil {
			log.Printf("[UDP] Write buffer установлен: %d МБ", size/1024/1024)
			break
		}
	}
}

// Start запускает VPN-сервер.
func (s *VPNServer) Start() error {
	log.Println("═══════════════════════════════════════════")
	log.Println("  NovaVPN Server v1.0")
	log.Println("  Собственный VPN-протокол")
	log.Println("═══════════════════════════════════════════")

	// 1. Создаём TUN-интерфейс
	log.Printf("[TUN] Создаём интерфейс %s...", s.cfg.TunName)

	// GRO/GSO: определяем, нужно ли пытаться включить
	enableGRO := s.cfg.EnableGROGSO == "auto" || s.cfg.EnableGROGSO == "true"
	if s.cfg.EnableGROGSO == "false" {
		log.Println("[TUN] GRO/GSO отключён в конфигурации (enable_gro_gso: false)")
	}

	tunDev, err := tun.NewTUN(s.cfg.TunName, s.cfg.MTU, enableGRO)
	if err != nil {
		return fmt.Errorf("ошибка создания TUN: %w", err)
	}
	s.tunDev = tunDev

	// Парсим маску подсети из CIDR
	subnetMask := 24
	parts := strings.Split(s.cfg.VPNSubnet, "/")
	if len(parts) == 2 {
		if mask, err := strconv.Atoi(parts[1]); err == nil {
			subnetMask = mask
		}
	}

	if err := tunDev.Configure(s.cfg.ServerVPNIP, subnetMask); err != nil {
		return fmt.Errorf("ошибка настройки TUN: %w", err)
	}
	// Wire MTU = TUN MTU + DataOverhead(14) + UDP(8) + IP(20) = TUN MTU + 42
	wireMTU := s.cfg.MTU + protocol.DataOverhead + 8 + 20
	log.Printf("[TUN] Интерфейс %s настроен: %s/%d, MTU: %d (wire: %d)",
		tunDev.Name(), s.cfg.ServerVPNIP, subnetMask, s.cfg.MTU, wireMTU)
	if wireMTU > 1420 {
		log.Printf("[WARN] Wire MTU %d > 1420: возможна фрагментация на PPPoE/LTE. Рекомендуется MTU ≤ 1380", wireMTU)
	}

	// 2. Настраиваем маршрутизацию
	if s.cfg.EnableNAT {
		log.Printf("[NAT] Настраиваем NAT через %s...", s.cfg.ExternalInterface)
		if err := tun.SetupRouting(s.cfg.VPNSubnet, s.cfg.TunName, s.cfg.ExternalInterface, true); err != nil {
			return fmt.Errorf("ошибка настройки маршрутизации: %w", err)
		}
		log.Println("[NAT] NAT настроен")
	}

	// 3. Открываем UDP-сокет
	addr := &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.ListenAddr),
		Port: s.cfg.ListenPort,
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("ошибка открытия UDP: %w", err)
	}
	s.udpConn = conn

	// Увеличиваем буферы сокета до 16 МБ (fallback к 4 МБ если ядро не позволяет)
	s.tuneSocketBuffers(conn)

	log.Printf("[UDP] Слушаем на %s:%d", s.cfg.ListenAddr, s.cfg.ListenPort)

	// Инициализируем batch I/O (sendmmsg + recvmmsg)
	maxPktSize := s.cfg.MTU + protocol.TotalOverhead + 100
	fd, rawConn, err := getUDPSocketFdAndRawConn(conn)
	if err != nil {
		log.Printf("[BATCH] Не удалось получить fd/rawConn сокета: %v — используем обычную отправку", err)
	} else {
		s.batch = newBatchSender(fd, maxPktSize)
		s.batch.Start()
		s.batchRecv = newBatchReceiver(rawConn, maxPktSize)
		log.Printf("[BATCH] sendmmsg/recvmmsg активированы (batch=%d, flush=%v)", batchSize, flushInterval)
	}

	// 4. Запускаем горутины
	s.wg.Add(3)
	go s.udpReadLoop()
	go s.tunReadLoop()
	go s.maintenanceLoop()

	log.Println("[SERVER] Сервер запущен и готов к приёму подключений")

	return nil
}

// Stop останавливает VPN-сервер.
func (s *VPNServer) Stop() {
	log.Println("[SERVER] Останавливаем сервер...")

	// Уведомляем всех подключённых клиентов об остановке сервера.
	// Клиенты получат PacketDisconnect и сразу начнут переподключение,
	// не дожидаясь dead-peer detection (45 сек).
	s.notifyShutdown()

	s.cancel()

	// Останавливаем batch sender (флушит оставшиеся пакеты)
	if s.batch != nil {
		s.batch.Stop()
	}

	// Закрываем UDP-сокет (прерывает ReadFromUDP)
	if s.udpConn != nil {
		s.udpConn.Close()
	}

	// Закрываем TUN (прерывает Read)
	if s.tunDev != nil {
		s.tunDev.Close()
	}

	// Очищаем маршрутизацию
	if s.cfg.EnableNAT {
		tun.CleanupRouting(s.cfg.VPNSubnet, s.cfg.TunName, s.cfg.ExternalInterface, true)
	}

	// Ждём завершения горутин
	s.wg.Wait()

	log.Println("[SERVER] Сервер остановлен")
}

// udpReadLoop — основной цикл приёма UDP-пакетов.
// Использует batch приём (recvmmsg) если batchRecv инициализирован,
// иначе fallback на обычный ReadFromUDP.
// Data/Keepalive/Disconnect обрабатываются inline (без горутин и пулов).
// Handshake-пакеты обрабатываются в отдельной горутине (редкие).
func (s *VPNServer) udpReadLoop() {
	defer s.wg.Done()

	// Привязываем к OS thread — устраняет goroutine scheduling jitter.
	// udpReadLoop — hot path: каждый приԽятый пакет обрабатывается здесь.
	// Без LockOSThread Go runtime может отобрать ось thread,
	// вызывая задержки до сотен мс (источник p99 spikes).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Println("[UDP] Запущен цикл приёма пакетов")

	// Пре-аллоцированный буфер для дешифрования (zero-alloc, single goroutine — safe)
	decryptBuf := make([]byte, 0, s.cfg.MTU+100)
	// LRU-1 кеш сессий — устраняет RWMutex lookup при повторяющихся пакетах
	cache := &sessionCache{}

	if s.batchRecv != nil {
		// Batch path: recvmmsg — до 64 пакетов за 1 syscall
		log.Println("[UDP] Используется batch приём (recvmmsg) с приоритизацией handshake")

		// Пре-аллоцированный массив индексов handshake-пакетов.
		// Избегаем двойного сканирования batch: один проход определяет тип,
		// затем обрабатываем handshake первыми, data — вторыми. Zero-alloc.
		var hsIndices [batchSize]int

		for {
			n, err := s.batchRecv.Recv()
			if err != nil {
				select {
				case <-s.ctx.Done():
					return
				default:
					log.Printf("[UDP] Ошибка recvmmsg: %v", err)
					continue
				}
			}

			// Один проход: классифицируем пакеты, handshake обрабатываем сразу.
			// Data-пакеты запоминаем в массив "остальные" (все кроме handshake).
			// Handshake-пакеты редки (~0.01% трафика), поэтому почти всегда hsCount=0
			// и цикл вырождается в простой for без overhead.
			hsCount := 0
			for i := 0; i < n; i++ {
				data, _ := s.batchRecv.GetPacket(i)
				if isHandshakePacket(data) {
					// Handshake — обрабатываем немедленно (приоритет)
					data, remoteAddr := s.batchRecv.GetPacket(i)
					decryptBuf = s.processUDPPacket(data, remoteAddr, decryptBuf, cache)
					hsIndices[hsCount] = i
					hsCount++
				}
			}

			// Data/keepalive/disconnect — основной трафик.
			// Если handshake-пакетов не было (99.99% batch'ей), пропускаем без проверок.
			if hsCount == 0 {
				// Быстрый путь: весь batch — data-пакеты, без дополнительных проверок
				for i := 0; i < n; i++ {
					data, remoteAddr := s.batchRecv.GetPacket(i)
					decryptBuf = s.processUDPPacket(data, remoteAddr, decryptBuf, cache)
				}
			} else {
				// Редкий путь: пропускаем уже обработанные handshake-пакеты
				hsIdx := 0
				for i := 0; i < n; i++ {
					if hsIdx < hsCount && i == hsIndices[hsIdx] {
						hsIdx++ // пропускаем — уже обработан
						continue
					}
					data, remoteAddr := s.batchRecv.GetPacket(i)
					decryptBuf = s.processUDPPacket(data, remoteAddr, decryptBuf, cache)
				}
			}
		}
	} else {
		// Fallback: обычный ReadFromUDP (один пакет за syscall)
		buf := make([]byte, s.cfg.MTU+protocol.TotalOverhead+100)
		for {
			n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-s.ctx.Done():
					return
				default:
					log.Printf("[UDP] Ошибка чтения: %v", err)
					continue
				}
			}

			if n < protocol.MinPacketSize {
				continue
			}

			decryptBuf = s.processUDPPacket(buf[:n], remoteAddr, decryptBuf, cache)
		}
	}
}

// isHandshakePacket быстро определяет, является ли пакет handshake-пакетом.
// Inline-проверка без аллокаций: TLS header(5) + SessionID(4) + Type(1) = байт 9 (тип).
// Используется для приоритизации handshake-пакетов в batch-обработке.
func isHandshakePacket(data []byte) bool {
	if len(data) < protocol.MinPacketSize {
		return false
	}
	raw := data
	if len(raw) >= protocol.TLSHeaderSize && raw[0] == protocol.TLSContentType {
		raw = raw[protocol.TLSHeaderSize:]
	}
	if len(raw) < 5 {
		return false
	}
	pktType := protocol.PacketType(raw[4])
	return pktType == protocol.PacketHandshakeInit || pktType == protocol.PacketHandshakeComplete
}

// processUDPPacket — обработка одного UDP-пакета (inline парсинг, дешифрование, TUN запись).
// Извлечена из udpReadLoop для переиспользования в batch и fallback путях.
// Возвращает decryptBuf для переиспользования (zero-alloc pattern).
// cache — LRU-1 кеш сессий для устранения RWMutex lookup при повторяющихся sessionID.
func (s *VPNServer) processUDPPacket(origData []byte, remoteAddr *net.UDPAddr, decryptBuf []byte, cache *sessionCache) []byte {
	if len(origData) < protocol.MinPacketSize {
		return decryptBuf
	}

	// Inline-парсинг заголовка без аллокаций
	raw := origData
	if len(raw) >= protocol.TLSHeaderSize && raw[0] == protocol.TLSContentType {
		raw = raw[protocol.TLSHeaderSize:]
	}
	// SessionID(4) + Type(1) = 5 минимум
	if len(raw) < 5 {
		return decryptBuf
	}

	sessionID := binary.BigEndian.Uint32(raw[0:4])
	pktType := protocol.PacketType(raw[4])

	switch pktType {
	case protocol.PacketData:
		// Hot path: inline обработка без горутины и Unmarshal
		// Data: SID(4) + Type(1) + Counter(4) + CT (plain ChaCha20, без auth tag)
		if len(raw) < 9 {
			return decryptBuf
		}

		session := cache.get(sessionID, s.sessions)
		if session == nil || !session.IsActive() {
			return decryptBuf
		}

		counter := binary.BigEndian.Uint32(raw[5:9])
		payload := raw[9:]

		// Восстанавливаем полный nonce
		var nonce [protocol.NonceSize]byte
		copy(nonce[:4], session.recvNoncePrefix[:])
		binary.BigEndian.PutUint64(nonce[4:], uint64(counter))

		// Plain ChaCha20 XOR дешифровка (zero-alloc)
		plaintextLen := len(payload)
		if cap(decryptBuf) < plaintextLen {
			decryptBuf = make([]byte, plaintextLen)
		} else {
			decryptBuf = decryptBuf[:plaintextLen]
		}
		c, err := chacha20.NewUnauthenticatedCipher(session.Keys.RecvKey[:], nonce[:])
		if err != nil {
			return decryptBuf
		}
		c.XORKeyStream(decryptBuf, payload)

		session.UpdateActivity()
		session.BytesRecv.Add(uint64(len(decryptBuf)))
		session.PacketsRecv.Add(1)

		if _, err := s.tunDev.Write(decryptBuf); err != nil {
			if s.cfg.LogLevel == "debug" {
				log.Printf("[TUN] Ошибка записи в TUN: %v", err)
			}
		}

	case protocol.PacketKeepalive:
		session := cache.get(sessionID, s.sessions)
		if session == nil {
			return decryptBuf
		}
		session.UpdateActivity()
		// Address migration: обновляем адрес клиента при смене IP/порта (0-RTT resume, NAT rebind)
		if session.ClientAddr.String() != remoteAddr.String() {
			log.Printf("[KEEPALIVE] Address migration #%d: %s -> %s", session.ID, session.ClientAddr, remoteAddr)
			// Копируем remoteAddr: UpdateClientAddr сохраняет указатель в сессии,
			// а pre-allocated UDPAddr из batchReceiver будет перезаписан при следующем Recv().
			s.sessions.UpdateClientAddr(session, copyUDPAddr(remoteAddr))
		}
		if s.cfg.LogLevel == "debug" {
			log.Printf("[KEEPALIVE] Получен от сессии #%d", session.ID)
		}
		// Lightweight keepalive response: TLS(5) + SID(4) + Type(1) = 10 bytes, zero-alloc
		var kaBuf [10]byte
		kaBuf[0] = protocol.TLSContentType
		kaBuf[1] = protocol.TLSVersionMajor
		kaBuf[2] = protocol.TLSVersionMinor
		binary.BigEndian.PutUint16(kaBuf[3:5], 5)
		binary.BigEndian.PutUint32(kaBuf[5:9], session.ID)
		kaBuf[9] = byte(protocol.PacketKeepalive)
		s.udpConn.WriteToUDP(kaBuf[:], remoteAddr)

	case protocol.PacketDisconnect:
		session := cache.get(sessionID, s.sessions)
		if session == nil {
			return decryptBuf
		}
		// НЕ удаляем сессию — держим для 0-RTT resume.
		// Истечёт по таймауту (SessionTimeout) в maintenanceLoop.
		session.UpdateActivity()
		log.Printf("[DISCONNECT] Клиент отключается: сессия #%d (%s) — сохранена для 0-RTT resume", session.ID, remoteAddr)

	case protocol.PacketHandshakeInit, protocol.PacketHandshakeComplete:
		// Handshake требует сложной обработки — выносим в горутину.
		// Копируем оригинальные данные (с TLS заголовком), т.к. буфер
		// batchReceiver будет переиспользован при следующем Recv().
		packet := make([]byte, len(origData))
		copy(packet, origData)
		// Копируем remoteAddr: handlePacket выполняется в горутине,
		// а pre-allocated UDPAddr из batchReceiver будет перезаписан при следующем Recv().
		go s.handlePacket(packet, copyUDPAddr(remoteAddr))

	default:
		if s.cfg.LogLevel == "debug" {
			log.Printf("[PROTO] Неизвестный тип пакета 0x%02X от %s", pktType, remoteAddr)
		}
	}

	return decryptBuf
}

// copyUDPAddr создаёт глубокую копию net.UDPAddr.
// Используется когда адрес нужно сохранить за пределами текущего цикла обработки:
// - горутины (handlePacket) — адрес живёт дольше, чем слот batchReceiver
// - persistent storage (UpdateClientAddr) — адрес хранится в сессии
// На hot path (data-пакеты) НЕ вызывается — zero-alloc.
func copyUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	ip := make(net.IP, len(addr.IP))
	copy(ip, addr.IP)
	return &net.UDPAddr{IP: ip, Port: addr.Port}
}

// tunReadLoop — цикл чтения пакетов из TUN-интерфейса.
// Использует batch sender (sendmmsg) для пакетной отправки, если доступен.
// При GRO: обрабатывает GRO-коалесцированные пакеты (сегментация TCP в userspace).
// Fallback на обычный WriteToUDP если batch sender не инициализирован.
func (s *VPNServer) tunReadLoop() {
	defer s.wg.Done()

	// Привязываем к OS thread — устраняет goroutine scheduling jitter.
	// tunReadLoop — hot path: все пакеты из TUN обрабатываются здесь.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Println("[TUN] Запущен цикл чтения из TUN")

	// GRO: увеличенный буфер для коалесцированных пакетов (до 64KB TCP segment)
	useGRO := s.tunDev.GROEnabled()
	var bufSize int
	if useGRO {
		bufSize = 65536 + tun.VirtioNetHdrLen // Макс. GRO-пакет + virtio заголовок
		log.Println("[TUN] GRO активен: буфер чтения 65KB, TCP-сегментация в userspace")
	} else {
		bufSize = s.cfg.MTU + 100
	}
	buf := make([]byte, bufSize)

	// Пре-аллоцированный буфер для сегментов GRO (zero-alloc при сегментации)
	segBuf := make([]byte, s.cfg.MTU+200)

	// Пре-аллоцированный буфер для fallback отправки (zero-alloc hot path)
	sendBuf := make([]byte, s.cfg.MTU+protocol.TotalOverhead+100)

	useBatch := s.batch != nil
	if useBatch {
		log.Println("[TUN] Используется batch sender (sendmmsg)")
	}

	// LRU-1 кеш сессий по IP — устраняет RWMutex lookup при повторяющихся dst IP
	ipCache := &ipSessionCache{}

	// Обработка одного IP-пакета: lookup сессии + шифрование + отправка.
	// Извлечена в локальную функцию для переиспользования в GRO и обычном путях.
	processPacket := func(packet []byte) {
		if len(packet) < 20 {
			return
		}

		// Определяем адресата по destination IP (zero-alloc: [4]byte ключ)
		dstKey, ok := tun.ExtractDstIPKey(packet)
		if !ok {
			return
		}

		// Ищем сессию по VPN IP (LRU-1 кеш, zero-alloc при cache hit)
		session := ipCache.get(dstKey, s.sessions)
		if session == nil {
			if s.cfg.LogLevel == "debug" {
				log.Printf("[TUN] Нет сессии для IP %d.%d.%d.%d", dstKey[0], dstKey[1], dstKey[2], dstKey[3])
			}
			return
		}

		if !session.IsActive() {
			return
		}

		// Шифруем и отправляем: batch (sendmmsg) или fallback (WriteToUDP)
		if useBatch {
			s.sendToClientBatch(session, packet, s.batch)
		} else {
			s.sendToClient(session, packet, sendBuf)
		}
	}

	for {
		n, err := s.tunDev.Read(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("[TUN] Ошибка чтения: %v", err)
				continue
			}
		}

		if useGRO {
			// GRO path: парсим virtio заголовок, обрабатываем коалесцированные пакеты
			packet, gsoType, gsoSize := tun.ParseGROHeader(buf[:n])
			if len(packet) < 20 {
				continue
			}

			if gsoType == tun.GSONone {
				// Обычный пакет — обрабатываем напрямую
				processPacket(packet)
			} else {
				// GRO-коалесцированный: TCP-сегментация в userspace
				tun.ForEachGROSegment(packet, gsoType, gsoSize, segBuf, processPacket)
			}
		} else {
			// Обычный path без GRO
			if n < 20 {
				continue
			}
			processPacket(buf[:n])
		}
	}
}

// maintenanceLoop — периодические задачи обслуживания.
func (s *VPNServer) maintenanceLoop() {
	defer s.wg.Done()

	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	// Рандомизированный keepalive для уменьшения DPI fingerprinting
	// Интервал: базовый ± 7 секунд (например, 25±7 = 18-32 сек)
	randomKeepaliveInterval := func() time.Duration {
		baseInterval := time.Duration(s.cfg.KeepaliveInterval) * time.Second

		// Генерируем случайное отклонение от -7 до +7 секунд (без big.Int аллокации)
		var buf [1]byte
		rand.Read(buf[:])
		offset := time.Duration(int(buf[0]%15)-7) * time.Second // -7 to +7

		interval := baseInterval + offset
		if interval < 10*time.Second {
			interval = 10 * time.Second // минимум 10 секунд
		}
		return interval
	}

	keepaliveTicker := time.NewTicker(randomKeepaliveInterval())
	defer keepaliveTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return

		case <-cleanupTicker.C:
			removed := s.sessions.CleanupExpired()
			if removed > 0 {
				log.Printf("[MAINTENANCE] Удалено %d истёкших сессий", removed)
			}
			// Очищаем устаревшие записи кеша аутентификации
			s.userStore.CleanupAuthCache()

		case <-statsTicker.C:
			s.printStats()

		case <-keepaliveTicker.C:
			s.sendKeepalives()
			// Сбрасываем тикер с новым случайным интервалом
			keepaliveTicker.Reset(randomKeepaliveInterval())
		}
	}
}

// printStats выводит статистику.
func (s *VPNServer) printStats() {
	total := s.sessions.TotalCount()
	active := s.sessions.ActiveCount()
	available := s.sessions.ipPool.AvailableCount()

	log.Printf("[STATS] Сессий: %d (активных: %d), IP доступно: %d", total, active, available)

	if s.cfg.LogLevel == "debug" {
		sessions := s.sessions.GetAllSessions()
		for _, sess := range sessions {
			log.Printf("[STATS]   #%d: %s -> %s | state=%s | tx=%d rx=%d | pkts tx=%d rx=%d",
				sess.ID,
				sess.ClientAddr,
				sess.AssignedIP,
				sess.GetState(),
				sess.BytesSent.Load(),
				sess.BytesRecv.Load(),
				sess.PacketsSent.Load(),
				sess.PacketsRecv.Load(),
			)
		}
	}
}

// Wait ожидает завершения сервера.
func (s *VPNServer) Wait() {
	s.wg.Wait()
}

// notifyShutdown отправляет PacketDisconnect всем активным клиентам.
// Вызывается перед остановкой сервера, чтобы клиенты сразу начали переподключение.
// Метод вызывается в начале Stop(), до закрытия udpConn — race condition исключён.
func (s *VPNServer) notifyShutdown() {
	if s.udpConn == nil {
		return
	}
	sessions := s.sessions.GetAllSessions()
	var buf [10]byte
	buf[0] = protocol.TLSContentType
	buf[1] = protocol.TLSVersionMajor
	buf[2] = protocol.TLSVersionMinor
	binary.BigEndian.PutUint16(buf[3:5], 5)
	buf[9] = byte(protocol.PacketDisconnect)
	count := 0
	for _, session := range sessions {
		if session.IsActive() {
			binary.BigEndian.PutUint32(buf[5:9], session.ID)
			if _, err := s.udpConn.WriteToUDP(buf[:], session.ClientAddr); err != nil {
				log.Printf("[SERVER] Ошибка отправки disconnect сессии #%d: %v", session.ID, err)
			} else {
				count++
			}
		}
	}
	if count > 0 {
		log.Printf("[SERVER] Отправлен disconnect %d клиентам", count)
	}
}

// ReloadUsers перезагружает список пользователей из файла.
// Используется по сигналу SIGHUP для hot-reload без перезапуска.
func (s *VPNServer) ReloadUsers() error {
	if err := s.userStore.LoadUsers(); err != nil {
		log.Printf("[RELOAD] Ошибка перезагрузки пользователей: %v", err)
		return err
	}
	log.Printf("[RELOAD] Перезагружено %d пользователей", s.userStore.Count())
	return nil
}

// GetUserStore возвращает хранилище пользователей (для CLI-команд).
func (s *VPNServer) GetUserStore() *auth.UserStore {
	return s.userStore
}
