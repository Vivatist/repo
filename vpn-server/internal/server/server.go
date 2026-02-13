package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
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
		cfg:       cfg,
		psk:       psk,
		sessions:  sessions,
		ctx:       ctx,
		cancel:    cancel,
		userStore: userStore,
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

// Start запускает VPN-сервер.
func (s *VPNServer) Start() error {
	log.Println("═══════════════════════════════════════════")
	log.Println("  NovaVPN Server v1.0")
	log.Println("  Собственный VPN-протокол")
	log.Println("═══════════════════════════════════════════")

	// 1. Создаём TUN-интерфейс
	log.Printf("[TUN] Создаём интерфейс %s...", s.cfg.TunName)
	tunDev, err := tun.NewTUN(s.cfg.TunName, s.cfg.MTU)
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
	log.Printf("[TUN] Интерфейс %s настроен: %s/%d, MTU: %d",
		tunDev.Name(), s.cfg.ServerVPNIP, subnetMask, s.cfg.MTU)

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

	// Увеличиваем буферы сокета
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("[UDP] Слушаем на %s:%d", s.cfg.ListenAddr, s.cfg.ListenPort)

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
	s.cancel()

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
// Data/Keepalive/Disconnect обрабатываются inline (без горутин и пулов).
// Handshake-пакеты обрабатываются в отдельной горутине (редкие).
func (s *VPNServer) udpReadLoop() {
	defer s.wg.Done()

	log.Println("[UDP] Запущен цикл приёма пакетов")

	buf := make([]byte, s.cfg.MTU+protocol.TotalOverhead+100)
	// Пре-аллоцированный буфер для дешифрования (zero-alloc)
	decryptBuf := make([]byte, 0, s.cfg.MTU+100)

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

		if n < protocol.HeaderSize {
			continue
		}

		// Inline-парсинг заголовка без аллокаций
		raw := buf[:n]
		if len(raw) >= protocol.TLSHeaderSize && raw[0] == protocol.TLSContentType {
			raw = raw[protocol.TLSHeaderSize:]
		}
		// SessionID(4) + Type(1) = 5 минимум
		if len(raw) < 5 {
			continue
		}

		sessionID := binary.BigEndian.Uint32(raw[0:4])
		pktType := protocol.PacketType(raw[4])

		switch pktType {
		case protocol.PacketData:
			// Hot path: inline обработка без горутины и Unmarshal
			// Data: SID(4) + Type(1) + Counter(4) + CT (plain ChaCha20, без auth tag)
			if len(raw) < 9 {
				continue
			}

			session := s.sessions.GetSessionByID(sessionID)
			if session == nil || !session.IsActive() {
				continue
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
				continue
			}
			c.XORKeyStream(decryptBuf, payload)
			plaintext := decryptBuf

			session.UpdateActivity()
			session.BytesRecv.Add(uint64(len(plaintext)))
			session.PacketsRecv.Add(1)

			if _, err := s.tunDev.Write(plaintext); err != nil {
				if s.cfg.LogLevel == "debug" {
					log.Printf("[TUN] Ошибка записи в TUN: %v", err)
				}
			}

		case protocol.PacketKeepalive:
			session := s.sessions.GetSessionByID(sessionID)
			if session == nil {
				continue
			}
			session.UpdateActivity()
			// Address migration: обновляем адрес клиента при смене IP/порта (0-RTT resume, NAT rebind)
			if session.ClientAddr.String() != remoteAddr.String() {
				log.Printf("[KEEPALIVE] Address migration #%d: %s -> %s", session.ID, session.ClientAddr, remoteAddr)
				session.ClientAddr = remoteAddr
			}
			if s.cfg.LogLevel == "debug" {
				log.Printf("[KEEPALIVE] Получен от сессии #%d", session.ID)
			}
			respPkt := protocol.NewKeepalivePacket(session.ID, session.NextSendSeq())
			respBytes, _ := respPkt.Marshal()
			s.udpConn.WriteToUDP(respBytes, remoteAddr)

		case protocol.PacketDisconnect:
			session := s.sessions.GetSessionByID(sessionID)
			if session == nil {
				continue
			}
			// НЕ удаляем сессию — держим для 0-RTT resume.
			// Истечёт по таймауту (SessionTimeout) в maintenanceLoop.
			session.UpdateActivity()
			log.Printf("[DISCONNECT] Клиент отключается: сессия #%d (%s) — сохранена для 0-RTT resume", session.ID, remoteAddr)

		case protocol.PacketHandshakeInit, protocol.PacketHandshakeComplete:
			// Handshake требует сложной обработки — выносим в горутину
			packet := make([]byte, n)
			copy(packet, buf[:n])
			go s.handlePacket(packet, remoteAddr)

		default:
			if s.cfg.LogLevel == "debug" {
				log.Printf("[PROTO] Неизвестный тип пакета 0x%02X от %s", pktType, remoteAddr)
			}
		}
	}
}

// tunReadLoop — цикл чтения пакетов из TUN-интерфейса.
func (s *VPNServer) tunReadLoop() {
	defer s.wg.Done()

	log.Println("[TUN] Запущен цикл чтения из TUN")

	buf := make([]byte, s.cfg.MTU+100)
	// Пре-аллоцированный буфер для отправки (zero-alloc hot path)
	sendBuf := make([]byte, s.cfg.MTU+protocol.TotalOverhead+100)

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

		if n < 20 { // Минимальный IPv4 заголовок
			continue
		}

		// Определяем адресата по destination IP (без копирования пакета)
		dstIP := tun.ExtractDstIP(buf[:n])
		if dstIP == nil {
			continue
		}

		// Ищем сессию по VPN IP
		session := s.sessions.GetSessionByVPNIP(dstIP)
		if session == nil {
			if s.cfg.LogLevel == "debug" {
				log.Printf("[TUN] Нет сессии для IP %s", dstIP)
			}
			continue
		}

		if !session.IsActive() {
			continue
		}

		// Шифруем и отправляем без промежуточного копирования
		s.sendToClient(session, buf[:n], sendBuf)
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

		// Генерируем случайное отклонение от -7 до +7 секунд
		randomOffset, _ := rand.Int(rand.Reader, big.NewInt(15))      // 0-14
		offset := time.Duration(randomOffset.Int64()-7) * time.Second // -7 to +7

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
