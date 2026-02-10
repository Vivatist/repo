package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/novavpn/vpn-server/config"
	"github.com/novavpn/vpn-server/internal/auth"
	novacrypto "github.com/novavpn/vpn-server/internal/crypto"
	"github.com/novavpn/vpn-server/internal/protocol"
	"github.com/novavpn/vpn-server/internal/tun"
)

// VPNServer представляет VPN-сервер.
type VPNServer struct {
	cfg *config.ServerConfig
	psk [novacrypto.KeySize]byte

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
	psk, err := novacrypto.DecodePSK(cfg.PreSharedKey)
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

// handlePacket обрабатывает входящий пакет.
func (s *VPNServer) handlePacket(data []byte, remoteAddr *net.UDPAddr) {
	pkt, err := protocol.Unmarshal(data)
	if err != nil {
		if s.cfg.LogLevel == "debug" {
			log.Printf("[PROTO] Невалидный пакет от %s: %v", remoteAddr, err)
		}
		return
	}

	switch pkt.Header.Type {
	case protocol.PacketHandshakeInit:
		s.handleHandshakeInit(pkt, remoteAddr)

	case protocol.PacketHandshakeComplete:
		s.handleHandshakeComplete(pkt, remoteAddr)

	case protocol.PacketData:
		s.handleDataPacket(pkt, remoteAddr)

	case protocol.PacketKeepalive:
		s.handleKeepalive(pkt, remoteAddr)

	case protocol.PacketDisconnect:
		s.handleDisconnect(pkt, remoteAddr)

	default:
		log.Printf("[PROTO] Неизвестный тип пакета 0x%02X от %s", pkt.Header.Type, remoteAddr)
	}
}

// handleHandshakeInit обрабатывает инициацию рукопожатия.
func (s *VPNServer) handleHandshakeInit(pkt *protocol.Packet, remoteAddr *net.UDPAddr) {
	log.Printf("[HANDSHAKE] Получен HandshakeInit от %s", remoteAddr)

	// Парсим данные рукопожатия
	hsInit, err := protocol.UnmarshalHandshakeInit(pkt.Payload)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка разбора HandshakeInit от %s: %v", remoteAddr, err)
		return
	}

	// Проверяем timestamp (защита от replay, допускаем 30 секунд)
	now := uint64(time.Now().Unix())
	if hsInit.Timestamp > now+30 || (now > 30 && hsInit.Timestamp < now-30) {
		log.Printf("[HANDSHAKE] Невалидный timestamp от %s (разница: %d сек)", remoteAddr, int64(now)-int64(hsInit.Timestamp))
		return
	}

	// Проверяем HMAC целостности (доказательство знания PSK)
	hmacData := make([]byte, 32+8+len(hsInit.EncryptedCredentials))
	copy(hmacData[0:32], hsInit.ClientPublicKey[:])
	binary.BigEndian.PutUint64(hmacData[32:40], hsInit.Timestamp)
	copy(hmacData[40:], hsInit.EncryptedCredentials)

	if !novacrypto.VerifyHMAC(s.psk, hmacData, hsInit.HMAC) {
		log.Printf("[HANDSHAKE] Неверный HMAC от %s — клиент не знает PSK", remoteAddr)
		return
	}

	// Расшифровываем credentials (email + пароль)
	if len(hsInit.EncryptedCredentials) < 12+16 {
		log.Printf("[HANDSHAKE] Зашифрованные credentials слишком короткие от %s", remoteAddr)
		return
	}

	var credsNonce [novacrypto.NonceSize]byte
	copy(credsNonce[:], hsInit.EncryptedCredentials[:12])
	credsCiphertext := hsInit.EncryptedCredentials[12:]

	credsPlaintext, err := novacrypto.Decrypt(s.psk, credsNonce, credsCiphertext, nil)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка расшифровки credentials от %s: %v", remoteAddr, err)
		return
	}

	email, password, err := protocol.UnmarshalCredentials(credsPlaintext)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка разбора credentials от %s: %v", remoteAddr, err)
		return
	}

	// Аутентификация по email + пароль
	user, err := s.userStore.Authenticate(email, password)
	if err != nil {
		log.Printf("[HANDSHAKE] Аутентификация неудачна для '%s' от %s: %v", email, remoteAddr, err)
		s.sendErrorPacket(remoteAddr, 0, "auth_failed")
		return
	}

	log.Printf("[HANDSHAKE] Пользователь '%s' аутентифицирован от %s", email, remoteAddr)

	// Создаём сессию
	session, err := s.sessions.CreateSession(remoteAddr)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка создания сессии для %s: %v", remoteAddr, err)
		return
	}
	session.ClientName = email

	// Если у пользователя фиксированный IP — назначаем его
	if user.AssignedIP != "" {
		fixedIP := net.ParseIP(user.AssignedIP)
		if fixedIP != nil {
			// Освобождаем автоматически выделенный IP
			s.sessions.ReleaseAndReassignIP(session, fixedIP)
		}
	}

	// Генерируем ephemeral ключевую пару сервера
	serverKP, err := novacrypto.GenerateKeyPair()
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка генерации ключей: %v", err)
		s.sessions.RemoveSession(session)
		return
	}
	session.ServerKeyPair = serverKP

	// Вычисляем shared secret
	sharedSecret, err := novacrypto.ComputeSharedSecret(serverKP.PrivateKey, hsInit.ClientPublicKey)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка ECDH: %v", err)
		s.sessions.RemoveSession(session)
		return
	}

	// Выводим сессионные ключи
	sessionKeys, err := novacrypto.DeriveSessionKeys(sharedSecret, s.psk, true)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка вывода ключей: %v", err)
		s.sessions.RemoveSession(session)
		return
	}
	session.Keys = sessionKeys

	// Обнуляем shared secret
	novacrypto.ZeroKey(&sharedSecret)

	// Формируем ответ
	dns1 := net.ParseIP("1.1.1.1").To4()
	dns2 := net.ParseIP("8.8.8.8").To4()
	if len(s.cfg.DNS) >= 1 {
		dns1 = net.ParseIP(s.cfg.DNS[0]).To4()
	}
	if len(s.cfg.DNS) >= 2 {
		dns2 = net.ParseIP(s.cfg.DNS[1]).To4()
	}

	// Вычисляем маску подсети
	subnetMask := uint8(24)
	parts := strings.Split(s.cfg.VPNSubnet, "/")
	if len(parts) == 2 {
		if mask, err := strconv.Atoi(parts[1]); err == nil {
			subnetMask = uint8(mask)
		}
	}

	hsResp := &protocol.HandshakeResp{
		ServerPublicKey: serverKP.PublicKey,
		SessionID:       session.ID,
		AssignedIP:      session.AssignedIP,
		SubnetMask:      subnetMask,
		DNS1:            dns1,
		DNS2:            dns2,
		MTU:             uint16(s.cfg.MTU),
	}

	// Подписываем ответ
	respData := protocol.MarshalHandshakeResp(hsResp)
	hsResp.ServerHMAC = novacrypto.ComputeHMAC(sessionKeys.HMACKey, respData[:51]) // до ServerHMAC
	respData = protocol.MarshalHandshakeResp(hsResp)

	// Шифруем payload (БЕЗ ServerPublicKey — он пойдёт открыто для ECDH на клиенте)
	nonce, encrypted, err := novacrypto.Encrypt(sessionKeys.SendKey, respData, nil)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка шифрования ответа: %v", err)
		s.sessions.RemoveSession(session)
		return
	}

	// Формат Payload: ServerPublicKey(32 bytes, открытый) + EncryptedResp
	// Клиент берёт ServerPublicKey → ECDH → сессионные ключи → расшифровывает остальное
	payload := make([]byte, 32+len(encrypted))
	copy(payload[:32], serverKP.PublicKey[:])
	copy(payload[32:], encrypted)

	// Формируем пакет
	var nonceArr [protocol.NonceSize]byte
	copy(nonceArr[:], nonce[:])

	respPkt := protocol.NewPacket(protocol.PacketHandshakeResp, session.ID, 0, nonceArr, payload)
	respBytes, err := respPkt.Marshal()
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка сериализации ответа: %v", err)
		s.sessions.RemoveSession(session)
		return
	}

	// Отправляем
	if _, err := s.udpConn.WriteToUDP(respBytes, remoteAddr); err != nil {
		log.Printf("[HANDSHAKE] Ошибка отправки ответа: %v", err)
		s.sessions.RemoveSession(session)
		return
	}

	log.Printf("[HANDSHAKE] Отправлен HandshakeResp сессии #%d для %s (VPN IP: %s)",
		session.ID, remoteAddr, session.AssignedIP)
}

// handleHandshakeComplete обрабатывает завершение рукопожатия.
func (s *VPNServer) handleHandshakeComplete(pkt *protocol.Packet, remoteAddr *net.UDPAddr) {
	session := s.sessions.GetSessionByID(pkt.Header.SessionID)
	if session == nil {
		log.Printf("[HANDSHAKE] HandshakeComplete для несуществующей сессии #%d от %s",
			pkt.Header.SessionID, remoteAddr)
		return
	}

	if session.GetState() != SessionStateHandshake {
		log.Printf("[HANDSHAKE] HandshakeComplete для сессии #%d в неверном состоянии: %s",
			session.ID, session.GetState())
		return
	}

	// Расшифровываем payload
	plaintext, err := novacrypto.Decrypt(session.Keys.RecvKey, pkt.Nonce, pkt.Payload, nil)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка расшифровки HandshakeComplete от %s: %v", remoteAddr, err)
		return
	}

	// Парсим
	hsComplete, err := protocol.UnmarshalHandshakeComplete(plaintext)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка разбора HandshakeComplete: %v", err)
		return
	}

	// Проверяем HMAC
	confirmData := []byte(fmt.Sprintf("novavpn-confirm-%d", session.ID))
	expectedHMAC := novacrypto.ComputeHMAC(session.Keys.HMACKey, confirmData)
	if expectedHMAC != hsComplete.ConfirmHMAC {
		log.Printf("[HANDSHAKE] Неверный ConfirmHMAC от %s", remoteAddr)
		return
	}

	// Активируем сессию
	session.SetState(SessionStateActive)
	session.UpdateActivity()

	log.Printf("[HANDSHAKE] ✓ Сессия #%d активирована (клиент: %s, VPN IP: %s)",
		session.ID, remoteAddr, session.AssignedIP)
}

// handleDataPacket обрабатывает зашифрованный пакет данных.
func (s *VPNServer) handleDataPacket(pkt *protocol.Packet, remoteAddr *net.UDPAddr) {
	session := s.sessions.GetSessionByID(pkt.Header.SessionID)
	if session == nil {
		return
	}

	if !session.IsActive() {
		return
	}

	// Расшифровываем
	additionalData := pkt.Header.MarshalHeader()
	plaintext, err := novacrypto.Decrypt(session.Keys.RecvKey, pkt.Nonce, pkt.Payload, additionalData)
	if err != nil {
		if s.cfg.LogLevel == "debug" {
			log.Printf("[DATA] Ошибка расшифровки от сессии #%d: %v", session.ID, err)
		}
		return
	}

	session.UpdateActivity()
	session.BytesRecv.Add(uint64(len(plaintext)))
	session.PacketsRecv.Add(1)

	// Записываем IP-пакет в TUN
	if _, err := s.tunDev.Write(plaintext); err != nil {
		if s.cfg.LogLevel == "debug" {
			log.Printf("[TUN] Ошибка записи в TUN: %v", err)
		}
	}
}

// handleKeepalive обрабатывает keepalive пакет.
func (s *VPNServer) handleKeepalive(pkt *protocol.Packet, remoteAddr *net.UDPAddr) {
	session := s.sessions.GetSessionByID(pkt.Header.SessionID)
	if session == nil {
		return
	}

	session.UpdateActivity()

	if s.cfg.LogLevel == "debug" {
		log.Printf("[KEEPALIVE] Получен от сессии #%d", session.ID)
	}

	// Отправляем keepalive обратно
	respPkt := protocol.NewKeepalivePacket(session.ID, session.NextSendSeq())
	respBytes, _ := respPkt.Marshal()
	s.udpConn.WriteToUDP(respBytes, remoteAddr)
}

// handleDisconnect обрабатывает запрос на отключение.
func (s *VPNServer) handleDisconnect(pkt *protocol.Packet, remoteAddr *net.UDPAddr) {
	session := s.sessions.GetSessionByID(pkt.Header.SessionID)
	if session == nil {
		return
	}

	log.Printf("[DISCONNECT] Клиент отключается: сессия #%d (%s)", session.ID, remoteAddr)
	s.sessions.RemoveSession(session)
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

// sendToClient шифрует и отправляет данные клиенту.
func (s *VPNServer) sendToClient(session *Session, plaintext []byte) {
	seq := session.NextSendSeq()

	// Формируем заголовок для additional data
	header := protocol.PacketHeader{
		Magic:      protocol.ProtocolMagic,
		Version:    protocol.ProtocolVersion,
		Type:       protocol.PacketData,
		SessionID:  session.ID,
		SequenceNo: seq,
		PayloadLen: uint16(len(plaintext)),
	}
	additionalData := header.MarshalHeader()

	// Шифруем
	nonce, ciphertext, err := novacrypto.Encrypt(session.Keys.SendKey, plaintext, additionalData)
	if err != nil {
		if s.cfg.LogLevel == "debug" {
			log.Printf("[SEND] Ошибка шифрования для сессии #%d: %v", session.ID, err)
		}
		return
	}

	// Формируем пакет — используем оригинальный header (PayloadLen = plaintext length) для консистентности AAD
	var nonceArr [protocol.NonceSize]byte
	copy(nonceArr[:], nonce[:])

	pkt := &protocol.Packet{
		Header:  header,
		Nonce:   nonceArr,
		Payload: ciphertext,
	}
	data, err := pkt.Marshal()
	if err != nil {
		return
	}

	// Отправляем
	if _, err := s.udpConn.WriteToUDP(data, session.ClientAddr); err != nil {
		if s.cfg.LogLevel == "debug" {
			log.Printf("[SEND] Ошибка отправки в сессию #%d: %v", session.ID, err)
		}
		return
	}

	session.BytesSent.Add(uint64(len(plaintext)))
	session.PacketsSent.Add(1)
}

// maintenanceLoop — периодические задачи обслуживания.
func (s *VPNServer) maintenanceLoop() {
	defer s.wg.Done()

	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	keepaliveTicker := time.NewTicker(time.Duration(s.cfg.KeepaliveInterval) * time.Second)
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
		}
	}
}

// sendKeepalives отправляет keepalive всем активным клиентам.
func (s *VPNServer) sendKeepalives() {
	sessions := s.sessions.GetAllSessions()
	for _, session := range sessions {
		if session.IsActive() {
			pkt := protocol.NewKeepalivePacket(session.ID, session.NextSendSeq())
			data, _ := pkt.Marshal()
			s.udpConn.WriteToUDP(data, session.ClientAddr)
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

// sendErrorPacket отправляет пакет ошибки клиенту.
func (s *VPNServer) sendErrorPacket(addr *net.UDPAddr, sessionID uint32, message string) {
	payload := []byte(message)
	pkt := protocol.NewPacket(protocol.PacketError, sessionID, 0, [protocol.NonceSize]byte{}, payload)
	data, err := pkt.Marshal()
	if err != nil {
		return
	}
	s.udpConn.WriteToUDP(data, addr)
}

// GetUserStore возвращает хранилище пользователей (для CLI-команд).
func (s *VPNServer) GetUserStore() *auth.UserStore {
	return s.userStore
}
