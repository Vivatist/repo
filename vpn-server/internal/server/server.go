package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

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

	// Буферный пул для снижения нагрузки GC
	bufPool sync.Pool

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
		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.MTU+protocol.TotalOverhead+100)
				return &buf
			},
		},
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
func (s *VPNServer) udpReadLoop() {
	defer s.wg.Done()

	log.Println("[UDP] Запущен цикл приёма пакетов")

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		bufPtr := s.bufPool.Get().(*[]byte)
		buf := *bufPtr

		n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				s.bufPool.Put(bufPtr)
				return
			default:
				log.Printf("[UDP] Ошибка чтения: %v", err)
				s.bufPool.Put(bufPtr)
				continue
			}
		}

		if n < protocol.HeaderSize {
			s.bufPool.Put(bufPtr)
			continue
		}

		// Обрабатываем пакет
		go func() {
			defer s.bufPool.Put(bufPtr)
			s.handlePacket(buf[:n], remoteAddr)
		}()
	}
}

// tunReadLoop — цикл чтения пакетов из TUN-интерфейса.
func (s *VPNServer) tunReadLoop() {
	defer s.wg.Done()

	log.Println("[TUN] Запущен цикл чтения из TUN")

	buf := make([]byte, s.cfg.MTU+100)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

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

		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Определяем адресата по destination IP
		dstIP := tun.ExtractDstIP(packet)
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

		// Шифруем и отправляем
		s.sendToClient(session, packet)
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
