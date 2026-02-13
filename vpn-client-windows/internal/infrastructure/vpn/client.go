//go:build windows

// Package vpn реализует VPN-клиент с использованием доменных интерфейсов.
package vpn

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	domaincrypto "github.com/novavpn/vpn-client-windows/internal/domain/crypto"
	domainnet "github.com/novavpn/vpn-client-windows/internal/domain/network"
	domainvpn "github.com/novavpn/vpn-client-windows/internal/domain/vpn"
	infracrypto "github.com/novavpn/vpn-client-windows/internal/infrastructure/crypto"
	"github.com/novavpn/vpn-client-windows/internal/infrastructure/vpn/handshake"
	"github.com/novavpn/vpn-client-windows/internal/protocol"
)

// NovaVPNClient реализует интерфейс VPN-клиента.
type NovaVPNClient struct {
	// Зависимости
	tunnelDevice domainnet.TunnelDevice
	netConfig    domainnet.NetworkConfigurator

	// Состояние
	state   atomic.Int32
	stopped atomic.Bool
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Соединение
	conn       *net.UDPConn
	serverAddr *net.UDPAddr

	// Сессия
	sessionID uint32
	session   domaincrypto.Session
	sendSeq   atomic.Uint32

	// Конфигурация
	assignedIP  net.IP
	dns         []net.IP
	mtu         uint16
	subnetMask  uint8
	connectedAt time.Time

	// Статистика
	bytesSent   atomic.Uint64
	bytesRecv   atomic.Uint64
	packetsSent atomic.Uint64
	packetsRecv atomic.Uint64

	// Колбэки
	onStatus domainvpn.StatusCallback
	onPSK    domainvpn.PSKCallback

	// 0-RTT resume data
	resumeSessionID   uint32
	resumeKeys        *domaincrypto.SessionKeys
	resumeSendCounter uint64
	resumeIP          net.IP
	resumeDNS         []net.IP
	resumeMTU         uint16
	resumeSubnetMask  uint8
}

// NewNovaVPNClient создаёт новый VPN-клиент.
func NewNovaVPNClient(
	tunnelDevice domainnet.TunnelDevice,
	netConfig domainnet.NetworkConfigurator,
	onStatus domainvpn.StatusCallback,
	onPSK domainvpn.PSKCallback,
) domainvpn.Client {
	return &NovaVPNClient{
		tunnelDevice: tunnelDevice,
		netConfig:    netConfig,
		onStatus:     onStatus,
		onPSK:        onPSK,
	}
}

// Connect подключается к VPN-серверу.
func (c *NovaVPNClient) Connect(params domainvpn.ConnectParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.GetState() != domainvpn.StateDisconnected {
		return fmt.Errorf("already connected or connecting")
	}

	c.setState(domainvpn.StateConnecting)

	// Декодируем PSK
	var psk []byte
	if params.PSK != "" {
		var err error
		psk, err = infracrypto.DecodePSK(params.PSK)
		if err != nil {
			c.setState(domainvpn.StateDisconnected)
			return fmt.Errorf("invalid PSK: %w", err)
		}
	} else {
		// Bootstrap mode: нулевой PSK
		psk = make([]byte, domaincrypto.KeySize)
		log.Println("[VPN] Bootstrap mode (no PSK)")
	}

	// Резолвим адрес сервера
	serverAddr, err := net.ResolveUDPAddr("udp4", params.ServerAddr)
	if err != nil {
		c.setState(domainvpn.StateDisconnected)
		return fmt.Errorf("invalid server address: %w", err)
	}
	c.serverAddr = serverAddr

	// Создаём UDP-сокет
	conn, err := net.DialUDP("udp4", nil, serverAddr)
	if err != nil {
		c.setState(domainvpn.StateDisconnected)
		return fmt.Errorf("UDP connection failed: %w", err)
	}
	c.conn = conn
	log.Printf("[VPN] UDP socket: %s -> %s", conn.LocalAddr(), conn.RemoteAddr())

	// Увеличиваем буферы
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)

	// 0-RTT Resume: пробуем восстановить сессию
	resumed := false
	if c.resumeSessionID != 0 && c.resumeKeys != nil {
		resumed = c.tryResume()
		if !resumed {
			c.clearResumeData()
		}
	}

	if !resumed {
		// Выполняем рукопожатие
		performer := handshake.NewPerformer(conn, psk, params.Email, params.Password, c.onPSK)

		// Пробуем быстро с сохранённым PSK, затем bootstrap
		timeout := 2 * time.Second
		if params.PSK == "" {
			timeout = 10 * time.Second
		}

		result, err := performer.Perform(timeout)
		if err != nil {
			// Если есть PSK, пробуем bootstrap
			if params.PSK != "" {
				log.Printf("[VPN] Saved PSK failed, trying bootstrap: %v", err)
				psk = make([]byte, domaincrypto.KeySize)
				performer = handshake.NewPerformer(conn, psk, params.Email, params.Password, c.onPSK)
				result, err = performer.Perform(10 * time.Second)
				if err != nil {
					conn.Close()
					c.conn = nil
					c.setState(domainvpn.StateDisconnected)
					return fmt.Errorf("handshake failed: %w", err)
				}
			} else {
				conn.Close()
				c.conn = nil
				c.setState(domainvpn.StateDisconnected)
				return fmt.Errorf("handshake failed: %w", err)
			}
		}

		// Сохраняем результаты рукопожатия
		c.sessionID = result.SessionID
		c.assignedIP = result.AssignedIP
		c.mtu = result.MTU
		c.subnetMask = result.SubnetMask
		c.dns = []net.IP{result.DNS1, result.DNS2}
		c.connectedAt = time.Now()

		// Создаём криптографическую сессию
		session, err := infracrypto.NewChaCha20Session(result.Keys)
		if err != nil {
			conn.Close()
			c.conn = nil
			c.setState(domainvpn.StateDisconnected)
			return fmt.Errorf("create session: %w", err)
		}
		c.session = session
	}

	// Запускаем циклы обработки ДО настройки сети (UDP read/keepalive работают сразу)
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.stopped.Store(false)
	c.wg.Add(3)
	go c.udpReadLoop()
	go c.tunReadLoop()
	go c.keepaliveLoop()

	// Настраиваем сеть (параллельно с уже запущенными циклами)
	if err := c.configureNetwork(); err != nil {
		c.stopped.Store(true)
		c.cancel()
		if c.conn != nil {
			c.conn.Close()
		}
		c.wg.Wait()
		if c.session != nil {
			c.session.Close()
			c.session = nil
		}
		c.conn = nil
		c.setState(domainvpn.StateDisconnected)
		return fmt.Errorf("configure network: %w", err)
	}

	c.setState(domainvpn.StateConnected)
	log.Println("[VPN] Подключено к VPN")
	return nil
}

// Disconnect отключается от VPN-сервера.
func (c *NovaVPNClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.GetState() != domainvpn.StateConnected {
		return fmt.Errorf("not connected")
	}

	c.setState(domainvpn.StateDisconnecting)
	log.Println("[VPN] Отключение...")

	// Сохраняем данные для 0-RTT resume ДО очистки сессии
	if c.session != nil && c.sessionID != 0 {
		c.resumeSessionID = c.sessionID
		c.resumeKeys = copySessionKeys(c.session)
		c.resumeSendCounter = getSendCounter(c.session)
		c.resumeIP = c.assignedIP
		c.resumeDNS = c.dns
		c.resumeMTU = c.mtu
		c.resumeSubnetMask = c.subnetMask
	}

	// Уведомляем сервер об отключении (lightweight, без аллокаций)
	if c.conn != nil && c.sessionID != 0 {
		var disconnBuf [10]byte
		disconnBuf[0] = protocol.TLSContentType
		disconnBuf[1] = protocol.TLSVersionMajor
		disconnBuf[2] = protocol.TLSVersionMinor
		binary.BigEndian.PutUint16(disconnBuf[3:5], 5)
		binary.BigEndian.PutUint32(disconnBuf[5:9], c.sessionID)
		disconnBuf[9] = byte(protocol.PacketDisconnect)
		c.conn.Write(disconnBuf[:])
	}

	// Сначала ставим флаг остановки, затем cancel
	c.stopped.Store(true)

	// Останавливаем циклы
	if c.cancel != nil {
		c.cancel()
	}

	// Закрываем соединение ДО wg.Wait — разблокирует Read() в udpReadLoop
	if c.conn != nil {
		c.conn.Close()
	}

	c.wg.Wait()

	// Очищаем сессию
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}

	c.conn = nil

	c.setState(domainvpn.StateDisconnected)
	log.Println("[VPN] Отключено")
	return nil
}

// GetState возвращает текущее состояние подключения.
func (c *NovaVPNClient) GetState() domainvpn.ConnectionState {
	return domainvpn.ConnectionState(c.state.Load())
}

// GetInfo возвращает информацию о текущем подключении.
func (c *NovaVPNClient) GetInfo() domainvpn.ConnectionInfo {
	return domainvpn.ConnectionInfo{
		State:       c.GetState(),
		ServerAddr:  c.serverAddr.String(),
		AssignedIP:  c.assignedIP,
		DNS:         c.dns,
		MTU:         c.mtu,
		SubnetMask:  c.subnetMask,
		ConnectedAt: c.connectedAt,
	}
}

// GetStatistics возвращает статистику передачи данных.
func (c *NovaVPNClient) GetStatistics() domainvpn.Statistics {
	return domainvpn.Statistics{
		BytesSent:   c.bytesSent.Load(),
		BytesRecv:   c.bytesRecv.Load(),
		PacketsSent: c.packetsSent.Load(),
		PacketsRecv: c.packetsRecv.Load(),
	}
}

// setState устанавливает состояние и вызывает колбэк.
func (c *NovaVPNClient) setState(state domainvpn.ConnectionState) {
	c.state.Store(int32(state))
	if c.onStatus != nil {
		info := ""
		if state == domainvpn.StateConnected && c.assignedIP != nil {
			info = fmt.Sprintf("VPN IP: %s", c.assignedIP)
		}
		c.onStatus(state, info)
	}
}

// configureNetwork настраивает сетевые параметры.
func (c *NovaVPNClient) configureNetwork() error {
	ifaceName := c.tunnelDevice.Name()

	// IP-адрес должен быть первым (маршруты зависят от него)
	if err := c.netConfig.ConfigureInterface(ifaceName, c.assignedIP, c.subnetMask); err != nil {
		return fmt.Errorf("configure interface: %w", err)
	}

	// DNS и маршруты параллельно (~100-200мс экономии)
	errCh := make(chan error, 2)

	go func() {
		errCh <- c.netConfig.SetDNS(ifaceName, c.dns)
	}()

	go func() {
		if wc, ok := c.netConfig.(interface {
			SetupVPNRoutes(ifaceName string, vpnIP, serverIP net.IP) error
		}); ok {
			errCh <- wc.SetupVPNRoutes(ifaceName, c.assignedIP, net.ParseIP(c.serverAddr.IP.String()))
		} else {
			errCh <- nil
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			return fmt.Errorf("network config: %w", err)
		}
	}

	return nil
}

// udpReadLoop читает пакеты от сервера.
func (c *NovaVPNClient) udpReadLoop() {
	defer c.wg.Done()
	buf := make([]byte, 2048)

	// Без SetReadDeadline — разблокировка через conn.Close() в Disconnect.
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			if c.stopped.Load() {
				return
			}
			log.Printf("[VPN] UDP read error: %v", err)
			return
		}

		// Обрабатываем пакет без копирования
		c.handleUDPPacket(buf[:n])
	}
}

// handleUDPPacket обрабатывает входящий пакет от сервера.
func (c *NovaVPNClient) handleUDPPacket(data []byte) {
	// Быстрый inline-парсинг без аллокаций
	raw := data
	// Удаляем TLS заголовок
	if len(raw) >= protocol.TLSHeaderSize && raw[0] == protocol.TLSContentType {
		raw = raw[protocol.TLSHeaderSize:]
	}
	// SessionID(4) + Type(1) = 5 минимум
	if len(raw) < 5 {
		return
	}

	pktType := protocol.PacketType(raw[4])

	switch pktType {
	case protocol.PacketData:
		// Data: SessionID(4) + Type(1) + Counter(4) + CT (plain ChaCha20, без auth tag)
		if len(raw) < 9 {
			return
		}
		counter := binary.BigEndian.Uint32(raw[5:9])
		payload := raw[9:]

		// Дешифруем с восстановленным nonce
		plaintext, err := c.session.DecryptWithCounter(counter, payload, nil)
		if err != nil {
			log.Printf("[VPN] Decrypt error: %v", err)
			return
		}

		if _, err := c.tunnelDevice.Write(plaintext); err != nil {
			log.Printf("[VPN] TUN write error: %v", err)
			return
		}

		c.packetsRecv.Add(1)
		c.bytesRecv.Add(uint64(len(plaintext)))

	case protocol.PacketKeepalive:
		// Игнорируем keepalive

	default:
		log.Printf("[VPN] Unknown packet type: 0x%02X", uint8(pktType))
	}
}

// tunReadLoop читает пакеты из TUN и отправляет на сервер.
func (c *NovaVPNClient) tunReadLoop() {
	defer c.wg.Done()
	mtu := c.tunnelDevice.MTU()
	tunBuf := make([]byte, mtu+100)

	// Пре-аллоцируем буфер для исходящих пакетов
	// TLS(5) + SessionID(4) + Type(1) + Counter(4) + MaxPayload (без AuthTag)
	sendBuf := make([]byte, protocol.TLSHeaderSize+4+1+4+mtu+100)

	for {
		if c.stopped.Load() {
			return
		}

		n, err := c.tunnelDevice.Read(tunBuf)
		if err != nil {
			log.Printf("[VPN] TUN read error: %v", err)
			return
		}

		// EncryptInto: nonce + ciphertext прямо в sendBuf[10:]
		encLen, err := c.session.EncryptInto(sendBuf[10:], tunBuf[:n], nil)
		if err != nil {
			log.Printf("[VPN] Encrypt error: %v", err)
			continue
		}

		// Собираем пакет inline без аллокаций
		// Формат: TLS_Header(5) + SessionID(4) + Type(1) + Counter(4) + Ciphertext + Tag
		dataLen := 4 + 1 + encLen

		// TLS Record Header
		sendBuf[0] = protocol.TLSContentType
		sendBuf[1] = protocol.TLSVersionMajor
		sendBuf[2] = protocol.TLSVersionMinor
		sendBuf[3] = byte(dataLen >> 8)
		sendBuf[4] = byte(dataLen)

		// SessionID
		sendBuf[5] = byte(c.sessionID >> 24)
		sendBuf[6] = byte(c.sessionID >> 16)
		sendBuf[7] = byte(c.sessionID >> 8)
		sendBuf[8] = byte(c.sessionID)

		// Type
		sendBuf[9] = byte(protocol.PacketData)

		// Counter + Ciphertext уже на месте (sendBuf[10:10+encLen])

		totalLen := protocol.TLSHeaderSize + dataLen

		if _, err := c.conn.Write(sendBuf[:totalLen]); err != nil {
			log.Printf("[VPN] UDP write error: %v", err)
			return
		}

		c.packetsSent.Add(1)
		c.bytesSent.Add(uint64(n))
	}
}

// keepaliveLoop отправляет keepalive пакеты.
func (c *NovaVPNClient) keepaliveLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Lightweight keepalive: TLS(5) + SID(4) + Type(1) = 10 bytes, zero-alloc
	var kaBuf [10]byte
	kaBuf[0] = protocol.TLSContentType
	kaBuf[1] = protocol.TLSVersionMajor
	kaBuf[2] = protocol.TLSVersionMinor
	binary.BigEndian.PutUint16(kaBuf[3:5], 5)
	binary.BigEndian.PutUint32(kaBuf[5:9], c.sessionID)
	kaBuf[9] = byte(protocol.PacketKeepalive)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.conn.Write(kaBuf[:])
		}
	}
}

// tryResume пытается восстановить сессию по сохранённым данным (0-RTT).
func (c *NovaVPNClient) tryResume() bool {
	log.Printf("[VPN] 0-RTT resume: пробуем сессию #%d", c.resumeSessionID)

	// Lightweight keepalive probe: TLS(5) + SID(4) + Type(1) = 10 bytes
	var kaBuf [10]byte
	kaBuf[0] = protocol.TLSContentType
	kaBuf[1] = protocol.TLSVersionMajor
	kaBuf[2] = protocol.TLSVersionMinor
	binary.BigEndian.PutUint16(kaBuf[3:5], 5)
	binary.BigEndian.PutUint32(kaBuf[5:9], c.resumeSessionID)
	kaBuf[9] = byte(protocol.PacketKeepalive)
	if _, err := c.conn.Write(kaBuf[:]); err != nil {
		log.Printf("[VPN] 0-RTT resume: ошибка отправки keepalive: %v", err)
		return false
	}

	// Ждём ответ (1 секунда)
	c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 2048)
	n, err := c.conn.Read(buf)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("[VPN] 0-RTT resume: нет ответа, переход к полному handshake")
		return false
	}

	// Проверяем что это keepalive-ответ
	raw := buf[:n]
	if len(raw) >= protocol.TLSHeaderSize && raw[0] == protocol.TLSContentType {
		raw = raw[protocol.TLSHeaderSize:]
	}
	if len(raw) < 5 || protocol.PacketType(raw[4]) != protocol.PacketKeepalive {
		log.Printf("[VPN] 0-RTT resume: получен не keepalive, переход к handshake")
		return false
	}

	// Session жива на сервере! Восстанавливаем.
	session, err := infracrypto.NewChaCha20Session(c.resumeKeys)
	if err != nil {
		log.Printf("[VPN] 0-RTT resume: ошибка создания сессии: %v", err)
		return false
	}

	// Восстанавливаем счётчик, чтобы избежать повторного использования nonce
	session.SetSendCounter(c.resumeSendCounter)

	c.sessionID = c.resumeSessionID
	c.session = session
	c.assignedIP = c.resumeIP
	c.dns = c.resumeDNS
	c.mtu = c.resumeMTU
	c.subnetMask = c.resumeSubnetMask
	c.connectedAt = time.Now()

	log.Printf("[VPN] 0-RTT resume: сессия #%d восстановлена (VPN IP: %s)", c.sessionID, c.assignedIP)
	return true
}

// clearResumeData очищает сохранённые данные для resume.
func (c *NovaVPNClient) clearResumeData() {
	c.resumeSessionID = 0
	c.resumeKeys = nil
	c.resumeSendCounter = 0
	c.resumeIP = nil
	c.resumeDNS = nil
	c.resumeMTU = 0
	c.resumeSubnetMask = 0
}

// copySessionKeys создаёт копию ключей сессии для 0-RTT resume.
func copySessionKeys(session domaincrypto.Session) *domaincrypto.SessionKeys {
	// Получаем ключи через интерфейс KeysProvider
	if kp, ok := session.(interface {
		GetKeys() *domaincrypto.SessionKeys
	}); ok {
		orig := kp.GetKeys()
		return &domaincrypto.SessionKeys{
			SendKey: append([]byte{}, orig.SendKey...),
			RecvKey: append([]byte{}, orig.RecvKey...),
			HMACKey: append([]byte{}, orig.HMACKey...),
		}
	}
	return nil
}

// getSendCounter получает текущее значение sendCounter сессии (для 0-RTT resume).
func getSendCounter(session domaincrypto.Session) uint64 {
	if sc, ok := session.(interface{ GetSendCounter() uint64 }); ok {
		return sc.GetSendCounter()
	}
	return 0
}
