//go:build windows

// Package vpn реализует VPN-клиент с использованием доменных интерфейсов.
package vpn

import (
	"context"
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

	// Настраиваем сеть
	if err := c.configureNetwork(); err != nil {
		session.Close()
		conn.Close()
		c.conn = nil
		c.setState(domainvpn.StateDisconnected)
		return fmt.Errorf("configure network: %w", err)
	}

	// Запускаем циклы обработки
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.stopped.Store(false)
	c.wg.Add(3)
	go c.udpReadLoop()
	go c.tunReadLoop()
	go c.keepaliveLoop()

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

	// Настраиваем IP-адрес
	if err := c.netConfig.ConfigureInterface(ifaceName, c.assignedIP, c.subnetMask); err != nil {
		return fmt.Errorf("configure interface: %w", err)
	}

	// Настраиваем DNS
	if err := c.netConfig.SetDNS(ifaceName, c.dns); err != nil {
		return fmt.Errorf("set DNS: %w", err)
	}

	// Настраиваем маршруты (требует специального метода в configurator)
	// Временно используем прямой вызов
	if wc, ok := c.netConfig.(interface {
		SetupVPNRoutes(ifaceName string, vpnIP, serverIP net.IP) error
	}); ok {
		if err := wc.SetupVPNRoutes(ifaceName, c.assignedIP, net.ParseIP(c.serverAddr.IP.String())); err != nil {
			return fmt.Errorf("setup routes: %w", err)
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
	// SessionID(4) + Type(1) + Nonce(12) = 17
	if len(raw) < 17 {
		return
	}

	pktType := protocol.PacketType(raw[4])

	switch pktType {
	case protocol.PacketData:
		nonce := raw[5:17]
		payload := raw[17:]

		// Дешифруем напрямую без промежуточного буфера
		plaintext, err := c.session.DecryptWithNonce(nonce, payload, nil)
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
	// TLS(5) + SessionID(4) + Type(1) + Nonce(12) + MaxPayload + AuthTag(16)
	sendBuf := make([]byte, protocol.TLSHeaderSize+4+1+protocol.NonceSize+mtu+100+protocol.AuthTagSize)

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
		// Формат: TLS_Header(5) + SessionID(4) + Type(1) + Nonce(12) + Ciphertext
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

		// Nonce + Ciphertext уже на месте (sendBuf[10:10+encLen])

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

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			seq := c.sendSeq.Add(1)
			pkt := protocol.NewPacket(protocol.PacketKeepalive, c.sessionID, seq, [protocol.NonceSize]byte{}, nil)
			pktBytes, _ := pkt.Marshal()
			c.conn.Write(pktBytes)
		}
	}
}
