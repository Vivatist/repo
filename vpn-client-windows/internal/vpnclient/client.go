//go:build windows

// Package vpnclient реализует VPN-подключение по протоколу NovaVPN.
package vpnclient

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	novacrypto "github.com/novavpn/vpn-client-windows/internal/crypto"
	"github.com/novavpn/vpn-client-windows/internal/protocol"
	"github.com/novavpn/vpn-client-windows/internal/tunnel"
)

// ConnectionState — состояние VPN-подключения.
type ConnectionState int32

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateConnected
	StateDisconnecting
)

func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "Отключён"
	case StateConnecting:
		return "Подключение..."
	case StateConnected:
		return "Подключён"
	case StateDisconnecting:
		return "Отключение..."
	default:
		return "Неизвестно"
	}
}

// ConnectParams — параметры подключения.
type ConnectParams struct {
	ServerAddr string // host:port
	PSK        string // hex-encoded PSK (пустой = bootstrap-режим)
	Email      string
	Password   string
}

// StatusCallback — колбэк для уведомлений UI о смене состояния.
type StatusCallback func(state ConnectionState, info string)

// PSKCallback — колбэк для сохранения полученного PSK.
type PSKCallback func(pskHex string)

// Client — VPN-клиент NovaVPN.
type Client struct {
	state      atomic.Int32
	onStatus   StatusCallback
	onPSK      PSKCallback
	mu         sync.Mutex
	conn       *net.UDPConn
	tun        *tunnel.WinTUN
	sessionID  uint32
	keys       *novacrypto.SessionKeys
	sendSeq    atomic.Uint32
	assignedIP net.IP
	dns1       net.IP
	dns2       net.IP
	mtu        uint16
	subnetMask uint8
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	serverAddr *net.UDPAddr
	psk        [novacrypto.KeySize]byte

	// Статистика
	BytesSent   atomic.Uint64
	BytesRecv   atomic.Uint64
	PacketsSent atomic.Uint64
	PacketsRecv atomic.Uint64
}

// NewClient создаёт новый VPN-клиент.
func NewClient(onStatus StatusCallback, onPSK PSKCallback) *Client {
	return &Client{
		onStatus: onStatus,
		onPSK:    onPSK,
	}
}

// GetState возвращает текущее состояние подключения.
func (c *Client) GetState() ConnectionState {
	return ConnectionState(c.state.Load())
}

func (c *Client) setState(s ConnectionState) {
	c.state.Store(int32(s))
	if c.onStatus != nil {
		info := ""
		if s == StateConnected && c.assignedIP != nil {
			info = fmt.Sprintf("VPN IP: %s", c.assignedIP)
		}
		c.onStatus(s, info)
	}
}

// GetAssignedIP возвращает назначенный VPN IP.
func (c *Client) GetAssignedIP() net.IP {
	return c.assignedIP
}

// Connect выполняет подключение к VPN-серверу.
func (c *Client) Connect(params ConnectParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.GetState() != StateDisconnected {
		return fmt.Errorf("уже подключён или подключается")
	}

	c.setState(StateConnecting)

	// Декодируем PSK (пустой = bootstrap-режим с нулевым PSK)
	if params.PSK != "" {
		psk, err := novacrypto.DecodePSK(params.PSK)
		if err != nil {
			c.setState(StateDisconnected)
			return fmt.Errorf("неверный PSK: %w", err)
		}
		c.psk = psk
	} else {
		// Bootstrap-режим: используем нулевой PSK
		c.psk = [novacrypto.KeySize]byte{}
		log.Println("[VPN] Режим без PSK (bootstrap)")
	}

	// Резолвим адрес сервера
	serverAddr, err := net.ResolveUDPAddr("udp4", params.ServerAddr)
	if err != nil {
		c.setState(StateDisconnected)
		return fmt.Errorf("неверный адрес сервера: %w", err)
	}
	c.serverAddr = serverAddr

	// Определяем физический IP для привязки UDP (обход Tailscale WFP)
	physIP, err := tunnel.GetPhysicalLocalIP()
	if err != nil {
		log.Printf("[VPN] Не удалось определить физ. IP, используем DialUDP: %v", err)
	}

	// Создаём UDP-сокет с привязкой к физическому адаптеру
	var conn *net.UDPConn
	if physIP != nil {
		localAddr := &net.UDPAddr{IP: physIP, Port: 0}
		conn, err = net.DialUDP("udp4", localAddr, serverAddr)
	} else {
		conn, err = net.DialUDP("udp4", nil, serverAddr)
	}
	if err != nil {
		c.setState(StateDisconnected)
		return fmt.Errorf("ошибка UDP: %w", err)
	}
	c.conn = conn
	log.Printf("[VPN] UDP сокет: %s -> %s", conn.LocalAddr(), conn.RemoteAddr())

	// Увеличиваем буферы
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)

	// Выполняем рукопожатие
	// Определяем, есть ли сохранённый PSK
	var zeroPSK [novacrypto.KeySize]byte
	hasStoredPSK := c.psk != zeroPSK

	if hasStoredPSK {
		// Быстрая попытка с сохранённым PSK (2 сек)
		if err := c.performHandshake(params.Email, params.Password, 2*time.Second); err != nil {
			log.Printf("[VPN] Сохранённый PSK не подошёл, пробуем bootstrap: %v", err)
			c.psk = zeroPSK
			if err2 := c.performHandshake(params.Email, params.Password, 10*time.Second); err2 != nil {
				conn.Close()
				c.conn = nil
				c.setState(StateDisconnected)
				return fmt.Errorf("рукопожатие: %w", err2)
			}
			// Bootstrap удался — новый PSK уже сохранён через onPSK callback
		}
	} else {
		// Bootstrap-режим напрямую
		if err := c.performHandshake(params.Email, params.Password, 10*time.Second); err != nil {
			conn.Close()
			c.conn = nil
			c.setState(StateDisconnected)
			return fmt.Errorf("рукопожатие: %w", err)
		}
	}

	// Создаём TUN-адаптер
	tunDev, err := tunnel.NewWinTUN("NovaVPN", int(c.mtu))
	if err != nil {
		conn.Close()
		c.conn = nil
		c.setState(StateDisconnected)
		return fmt.Errorf("ошибка TUN: %w", err)
	}
	c.tun = tunDev

	// Настраиваем сеть
	if err := tunDev.ConfigureNetwork(c.assignedIP, c.subnetMask, c.dns1, c.dns2, serverAddr.IP); err != nil {
		tunDev.Close()
		conn.Close()
		c.conn = nil
		c.setState(StateDisconnected)
		return fmt.Errorf("ошибка настройки сети: %w", err)
	}

	// Запускаем I/O горутины
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.wg.Add(3)
	go c.udpReadLoop()
	go c.tunReadLoop()
	go c.keepaliveLoop()

	c.setState(StateConnected)
	log.Printf("[VPN] Подключён. VPN IP: %s, SessionID: %d", c.assignedIP, c.sessionID)
	return nil
}

// Disconnect завершает VPN-подключение.
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.GetState() == StateDisconnected || c.GetState() == StateDisconnecting {
		return
	}
	c.setState(StateDisconnecting)

	// Отправляем Disconnect-пакет серверу
	if c.conn != nil && c.sessionID != 0 {
		pkt := protocol.NewDisconnectPacket(c.sessionID, c.sendSeq.Add(1))
		if data, err := pkt.Marshal(); err == nil {
			c.conn.Write(data)
		}
	}

	// Останавливаем горутины
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	c.wg.Wait()

	// Закрываем TUN
	if c.tun != nil {
		c.tun.Close()
		c.tun = nil
	}

	c.conn = nil
	c.sessionID = 0
	c.keys = nil
	c.assignedIP = nil
	c.sendSeq.Store(0)
	c.BytesSent.Store(0)
	c.BytesRecv.Store(0)
	c.PacketsSent.Store(0)
	c.PacketsRecv.Store(0)

	c.setState(StateDisconnected)
	log.Println("[VPN] Отключён")
}

// performHandshake выполняет 3-way handshake с сервером.
func (c *Client) performHandshake(email, password string, timeout time.Duration) error {
	// 1. Генерируем ephemeral ключевую пару
	clientKP, err := novacrypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("генерация ключей: %w", err)
	}

	// 2. Шифруем credentials PSK-ключом
	credsPlaintext := protocol.MarshalCredentials(email, password)
	credsNonce, credsCiphertext, err := novacrypto.Encrypt(c.psk, credsPlaintext, nil)
	if err != nil {
		return fmt.Errorf("шифрование credentials: %w", err)
	}

	// Формат EncryptedCredentials: Nonce(12) + Ciphertext (включая AuthTag)
	encCreds := make([]byte, novacrypto.NonceSize+len(credsCiphertext))
	copy(encCreds[:novacrypto.NonceSize], credsNonce[:])
	copy(encCreds[novacrypto.NonceSize:], credsCiphertext)

	// 3. Формируем HandshakeInit
	timestamp := uint64(time.Now().Unix())

	// HMAC = HMAC-SHA256(PSK, clientPubKey + timestamp + encryptedCredentials)
	hmacData := make([]byte, 32+8+len(encCreds))
	copy(hmacData[0:32], clientKP.PublicKey[:])
	binary.BigEndian.PutUint64(hmacData[32:40], timestamp)
	copy(hmacData[40:], encCreds)
	hmacVal := novacrypto.ComputeHMAC(c.psk, hmacData)

	hsInit := &protocol.HandshakeInit{
		ClientPublicKey:      clientKP.PublicKey,
		Timestamp:            timestamp,
		EncryptedCredentials: encCreds,
		HMAC:                 hmacVal,
	}

	initPayload := protocol.MarshalHandshakeInit(hsInit)

	// Отправляем HandshakeInit (не шифрованный, только HMAC для целостности)
	pkt := protocol.NewPacket(protocol.PacketHandshakeInit, 0, 0, [protocol.NonceSize]byte{}, initPayload)
	pktBytes, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("сериализация: %w", err)
	}

	// Ставим таймаут на чтение
	c.conn.SetReadDeadline(time.Now().Add(timeout))

	if _, err := c.conn.Write(pktBytes); err != nil {
		return fmt.Errorf("отправка HandshakeInit: %w", err)
	}
	log.Println("[HANDSHAKE] Отправлен HandshakeInit")

	// 4. Ждём HandshakeResp
	buf := make([]byte, 4096)
	n, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("ожидание HandshakeResp: %w", err)
	}

	respPkt, err := protocol.Unmarshal(buf[:n])
	if err != nil {
		return fmt.Errorf("разбор ответа: %w", err)
	}

	if respPkt.Header.Type == protocol.PacketError {
		return fmt.Errorf("сервер отклонил подключение (неверные учётные данные)")
	}

	if respPkt.Header.Type != protocol.PacketHandshakeResp {
		return fmt.Errorf("ожидался HandshakeResp, получен %s", respPkt.Header.Type)
	}

	// Формат Payload: ServerPublicKey(32B, открытый) + Encrypt(sessionKey, HandshakeResp)
	if len(respPkt.Payload) < 32 {
		return fmt.Errorf("HandshakeResp payload слишком короткий")
	}

	// Извлекаем ServerPublicKey (открытая часть)
	var serverPubKey [32]byte
	copy(serverPubKey[:], respPkt.Payload[:32])

	// ECDH: вычисляем shared secret
	sharedSecret, err := novacrypto.ComputeSharedSecret(clientKP.PrivateKey, serverPubKey)
	if err != nil {
		return fmt.Errorf("ECDH: %w", err)
	}

	sessionKeys, err := novacrypto.DeriveSessionKeys(sharedSecret, c.psk, false)
	if err != nil {
		return fmt.Errorf("вывод ключей: %w", err)
	}
	novacrypto.ZeroKey(&sharedSecret)

	// Расшифровываем остальную часть payload
	encryptedResp := respPkt.Payload[32:]
	respPlaintext, err := novacrypto.Decrypt(sessionKeys.RecvKey, respPkt.Nonce, encryptedResp, nil)
	if err != nil {
		return fmt.Errorf("расшифровка HandshakeResp: %w", err)
	}

	hsResp, err := protocol.UnmarshalHandshakeResp(respPlaintext)
	if err != nil {
		return fmt.Errorf("разбор HandshakeResp: %w", err)
	}

	c.sessionID = hsResp.SessionID
	c.assignedIP = hsResp.AssignedIP
	c.subnetMask = hsResp.SubnetMask
	c.dns1 = hsResp.DNS1
	c.dns2 = hsResp.DNS2
	c.mtu = hsResp.MTU
	c.keys = sessionKeys

	// Если сервер прислал PSK (bootstrap-режим) — сохраняем
	if len(hsResp.PSK) == 32 {
		copy(c.psk[:], hsResp.PSK)
		pskHex := hex.EncodeToString(hsResp.PSK)
		log.Printf("[HANDSHAKE] Получен PSK от сервера (bootstrap)")
		if c.onPSK != nil {
			c.onPSK(pskHex)
		}
	}

	log.Printf("[HANDSHAKE] Получен HandshakeResp: SessionID=%d, VPN IP=%s, MTU=%d",
		c.sessionID, c.assignedIP, c.mtu)

	// 5. Отправляем HandshakeComplete
	confirmData := []byte(fmt.Sprintf("novavpn-confirm-%d", c.sessionID))
	confirmHMAC := novacrypto.ComputeHMAC(sessionKeys.HMACKey, confirmData)

	hsComplete := &protocol.HandshakeComplete{ConfirmHMAC: confirmHMAC}
	completePayload := protocol.MarshalHandshakeComplete(hsComplete)

	nonce, encrypted, err := novacrypto.Encrypt(sessionKeys.SendKey, completePayload, nil)
	if err != nil {
		return fmt.Errorf("шифрование HandshakeComplete: %w", err)
	}

	var nonceArr [protocol.NonceSize]byte
	copy(nonceArr[:], nonce[:])

	completePkt := protocol.NewPacket(protocol.PacketHandshakeComplete, c.sessionID, 1, nonceArr, encrypted)
	completeBytes, err := completePkt.Marshal()
	if err != nil {
		return fmt.Errorf("сериализация HandshakeComplete: %w", err)
	}

	c.conn.SetReadDeadline(time.Time{}) // убираем таймаут

	if _, err := c.conn.Write(completeBytes); err != nil {
		return fmt.Errorf("отправка HandshakeComplete: %w", err)
	}

	novacrypto.ZeroKey(&clientKP.PrivateKey)
	log.Println("[HANDSHAKE] Отправлен HandshakeComplete. Рукопожатие завершено.")
	return nil
}

// udpReadLoop — цикл приёма пакетов от сервера.
func (c *Client) udpReadLoop() {
	defer c.wg.Done()

	buf := make([]byte, int(c.mtu)+protocol.TotalOverhead+100)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := c.conn.Read(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}

		if n < protocol.HeaderSize {
			continue
		}

		pkt, err := protocol.Unmarshal(buf[:n])
		if err != nil {
			continue
		}

		switch pkt.Header.Type {
		case protocol.PacketData:
			c.handleData(pkt)
		case protocol.PacketKeepalive:
			log.Println("[UDP] Получен Keepalive от сервера")
		case protocol.PacketError:
			log.Printf("[VPN] Ошибка от сервера")
			go c.Disconnect()
			return
		case protocol.PacketDisconnect:
			log.Println("[VPN] Сервер запросил отключение")
			go c.Disconnect()
			return
		}
	}
}

// handleData — обработка зашифрованного пакета данных.
func (c *Client) handleData(pkt *protocol.Packet) {
	if c.keys == nil {
		return
	}

	// В v2 протоколе AAD не используется для data-пакетов
	plaintext, err := novacrypto.Decrypt(c.keys.RecvKey, pkt.Nonce, pkt.Payload, nil)
	if err != nil {
		log.Printf("[DATA] Ошибка расшифровки: %v (payloadLen=%d, headerPayloadLen=%d)",
			err, len(pkt.Payload), pkt.Header.PayloadLen)
		return
	}

	c.BytesRecv.Add(uint64(len(plaintext)))
	c.PacketsRecv.Add(1)

	if c.PacketsRecv.Load()%100 == 1 {
		log.Printf("[DATA] Получен пакет #%d (%d байт), всего получено: %d байт",
			c.PacketsRecv.Load(), len(plaintext), c.BytesRecv.Load())
	}

	// Пишем IP-пакет в TUN
	if c.tun != nil {
		if _, err := c.tun.Write(plaintext); err != nil {
			log.Printf("[DATA] Ошибка записи в TUN: %v", err)
		}
	}
}

// tunReadLoop — цикл чтения пакетов из TUN-адаптера.
func (c *Client) tunReadLoop() {
	defer c.wg.Done()

	buf := make([]byte, int(c.mtu)+100)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, err := c.tun.Read(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}

		if n < 20 || c.keys == nil {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Шифруем и отправляем
		seq := c.sendSeq.Add(1)
		header := protocol.PacketHeader{
			Version:    protocol.ProtocolVersion,
			Type:       protocol.PacketData,
			SessionID:  c.sessionID,
			SequenceNo: seq,
			PayloadLen: uint16(len(packet)),
		}

		// В v2 протоколе AAD не используется для data-пакетов
		nonce, ciphertext, err := novacrypto.Encrypt(c.keys.SendKey, packet, nil)
		if err != nil {
			continue
		}

		var nonceArr [protocol.NonceSize]byte
		copy(nonceArr[:], nonce[:])

		// Используем оригинальный header (с PayloadLen = plaintext length) для консистентности AAD
		pkt := &protocol.Packet{
			Header:  header,
			Nonce:   nonceArr,
			Payload: ciphertext,
		}
		pktBytes, err := pkt.Marshal()
		if err != nil {
			continue
		}

		if _, err := c.conn.Write(pktBytes); err != nil {
			log.Printf("[DATA] Ошибка отправки UDP: %v", err)
			continue
		}

		c.BytesSent.Add(uint64(n))
		c.PacketsSent.Add(1)

		if c.PacketsSent.Load()%100 == 1 {
			log.Printf("[DATA] Отправлен пакет #%d (%d байт), всего отправлено: %d байт",
				c.PacketsSent.Load(), n, c.BytesSent.Load())
		}
	}
}

// keepaliveLoop — отправка keepalive-пакетов с рандомизированными интервалами.
// Интервал: 20-35 секунд (для уменьшения DPI fingerprinting)
func (c *Client) keepaliveLoop() {
	defer c.wg.Done()

	// Функция генерации случайного интервала keepalive
	randomKeepaliveInterval := func() time.Duration {
		minInterval := 20 * time.Second
		_ = 35 * time.Second // maxInterval для документации

		// Генерируем случайное значение от 0 до 15 секунд
		randomSec, _ := rand.Int(rand.Reader, big.NewInt(16)) // 0-15
		interval := minInterval + time.Duration(randomSec.Int64())*time.Second

		return interval
	}

	ticker := time.NewTicker(randomKeepaliveInterval())
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if c.GetState() == StateConnected {
				pkt := protocol.NewKeepalivePacket(c.sessionID, c.sendSeq.Add(1))
				if data, err := pkt.Marshal(); err == nil {
					c.conn.Write(data)
				}
			}
			// Сбрасываем тикер с новым случайным интервалом
			ticker.Reset(randomKeepaliveInterval())
		}
	}
}
