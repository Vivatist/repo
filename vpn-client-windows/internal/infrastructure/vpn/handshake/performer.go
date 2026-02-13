//go:build windows

// Package handshake реализует протокол рукопожатия NovaVPN.
package handshake

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	domaincrypto "github.com/novavpn/vpn-client-windows/internal/domain/crypto"
	infracrypto "github.com/novavpn/vpn-client-windows/internal/infrastructure/crypto"
	"github.com/novavpn/vpn-client-windows/internal/protocol"
)

// Result — результат успешного рукопожатия.
type Result struct {
	SessionID  uint32
	Keys       *domaincrypto.SessionKeys
	AssignedIP net.IP
	DNS1       net.IP
	DNS2       net.IP
	MTU        uint16
	SubnetMask uint8
	NewPSK     []byte // новый PSK если был bootstrap
}

// Performer выполняет рукопожатие с сервером.
type Performer struct {
	conn     *net.UDPConn
	keyEx    domaincrypto.KeyExchange
	psk      []byte
	email    string
	password string
	onNewPSK func(pskHex string)
}

// NewPerformer создаёт новый объект для выполнения рукопожатия.
func NewPerformer(conn *net.UDPConn, psk []byte, email, password string, onNewPSK func(string)) *Performer {
	return &Performer{
		conn:     conn,
		keyEx:    infracrypto.NewCurve25519KeyExchange(),
		psk:      psk,
		email:    email,
		password: password,
		onNewPSK: onNewPSK,
	}
}

// Perform выполняет полное рукопожатие с сервером.
func (p *Performer) Perform(timeout time.Duration) (*Result, error) {
	// 1. Генерируем ephemeral ключевую пару
	clientPrivKey, clientPubKey, err := p.keyEx.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	defer zeroBytes(clientPrivKey)

	// 2. Отправляем HandshakeInit
	if err := p.sendHandshakeInit(clientPubKey); err != nil {
		return nil, fmt.Errorf("send handshake init: %w", err)
	}

	// 3. Получаем HandshakeResp
	p.conn.SetReadDeadline(time.Now().Add(timeout))
	result, err := p.receiveHandshakeResp(clientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("receive handshake resp: %w", err)
	}
	p.conn.SetReadDeadline(time.Time{}) // убираем таймаут

	// 4. Отправляем HandshakeComplete fire-and-forget (1-RTT: сессия уже активна на сервере)
	go func() {
		if err := p.sendHandshakeComplete(result); err != nil {
			log.Printf("[HANDSHAKE] Ошибка отправки HandshakeComplete: %v", err)
		}
	}()

	log.Println("[HANDSHAKE] Рукопожатие завершено (1-RTT)")
	return result, nil
}

// sendHandshakeInit отправляет HandshakeInit пакет.
func (p *Performer) sendHandshakeInit(clientPubKey []byte) error {
	// Шифруем credentials PSK-ключом
	credsPlaintext := protocol.MarshalCredentials(p.email, p.password)

	// Создаём временную сессию для шифрования (копируем PSK, чтобы Close() не занулил оригинал)
	pskCopy := make([]byte, len(p.psk))
	copy(pskCopy, p.psk)
	tempKeys := &domaincrypto.SessionKeys{
		SendKey: pskCopy,
		RecvKey: pskCopy,
		HMACKey: pskCopy,
	}
	tempSession, err := infracrypto.NewChaCha20Session(tempKeys)
	if err != nil {
		return fmt.Errorf("create temp session: %w", err)
	}
	defer tempSession.Close()

	encCreds, err := tempSession.Encrypt(credsPlaintext, nil)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}

	// Формируем HandshakeInit
	timestamp := uint64(time.Now().Unix())

	// HMAC = HMAC-SHA256(PSK, clientPubKey + timestamp + encryptedCredentials)
	hmacData := make([]byte, 32+8+len(encCreds))
	copy(hmacData[0:32], clientPubKey)
	binary.BigEndian.PutUint64(hmacData[32:40], timestamp)
	copy(hmacData[40:], encCreds)
	hmac := tempSession.ComputeHMAC(hmacData)

	var pubKey32 [32]byte
	copy(pubKey32[:], clientPubKey)
	var hmac32 [32]byte
	copy(hmac32[:], hmac)

	hsInit := &protocol.HandshakeInit{
		ClientPublicKey:      pubKey32,
		Timestamp:            timestamp,
		EncryptedCredentials: encCreds,
		HMAC:                 hmac32,
	}

	initPayload := protocol.MarshalHandshakeInit(hsInit)
	pkt := protocol.NewPacket(protocol.PacketHandshakeInit, 0, 0, [protocol.NonceSize]byte{}, initPayload)

	pktBytes, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal packet: %w", err)
	}

	if _, err := p.conn.Write(pktBytes); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	log.Println("[HANDSHAKE] Отправлен HandshakeInit")
	return nil
}

// receiveHandshakeResp получает и обрабатывает HandshakeResp.
func (p *Performer) receiveHandshakeResp(clientPrivKey []byte) (*Result, error) {
	buf := make([]byte, 4096)
	n, err := p.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	respPkt, err := protocol.Unmarshal(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if respPkt.Header.Type == protocol.PacketError {
		return nil, fmt.Errorf("server rejected connection (invalid credentials)")
	}

	if respPkt.Header.Type != protocol.PacketHandshakeResp {
		return nil, fmt.Errorf("expected HandshakeResp, got %s", respPkt.Header.Type)
	}

	// Извлекаем ServerPublicKey (первые 32 байта payload)
	if len(respPkt.Payload) < 32 {
		return nil, fmt.Errorf("HandshakeResp payload too short")
	}
	serverPubKey := respPkt.Payload[:32]

	// ECDH: вычисляем shared secret
	sharedSecret, err := p.keyEx.ComputeSharedSecret(clientPrivKey, serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	defer zeroBytes(sharedSecret)

	// Выводим ключи сессии
	sessionKeys, err := p.keyEx.DeriveSessionKeys(sharedSecret, p.psk)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	// Создаём сессию для дешифрования
	// НЕ вызываем defer session.Close() — он зануляет ключи,
	// а sessionKeys будет использоваться далее (HandshakeComplete + основная сессия)
	session, err := infracrypto.NewChaCha20Session(sessionKeys)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Расшифровываем остальную часть payload
	// Nonce находится в заголовке пакета, а не в payload — нужно подставить его
	encryptedResp := respPkt.Payload[32:]
	decryptData := make([]byte, protocol.NonceSize+len(encryptedResp))
	copy(decryptData[:protocol.NonceSize], respPkt.Nonce[:])
	copy(decryptData[protocol.NonceSize:], encryptedResp)
	respPlaintext, err := session.Decrypt(decryptData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt HandshakeResp: %w", err)
	}

	hsResp, err := protocol.UnmarshalHandshakeResp(respPlaintext)
	if err != nil {
		return nil, fmt.Errorf("unmarshal HandshakeResp: %w", err)
	}

	result := &Result{
		SessionID:  hsResp.SessionID,
		Keys:       sessionKeys,
		AssignedIP: hsResp.AssignedIP,
		DNS1:       hsResp.DNS1,
		DNS2:       hsResp.DNS2,
		MTU:        hsResp.MTU,
		SubnetMask: hsResp.SubnetMask,
	}

	// Если сервер прислал PSK (bootstrap-режим)
	if len(hsResp.PSK) == 32 {
		result.NewPSK = make([]byte, 32)
		copy(result.NewPSK, hsResp.PSK)
		pskHex := hex.EncodeToString(hsResp.PSK)
		log.Printf("[HANDSHAKE] Получен PSK от сервера (bootstrap)")
		if p.onNewPSK != nil {
			p.onNewPSK(pskHex)
		}
	}

	log.Printf("[HANDSHAKE] SessionID=%d, VPN IP=%s, MTU=%d", result.SessionID, result.AssignedIP, result.MTU)
	return result, nil
}

// sendHandshakeComplete отправляет HandshakeComplete пакет.
func (p *Performer) sendHandshakeComplete(result *Result) error {
	// Создаём сессию
	// НЕ вызываем defer session.Close() — он зануляет result.Keys,
	// которые нужны для основной VPN-сессии после рукопожатия
	session, err := infracrypto.NewChaCha20Session(result.Keys)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	confirmData := []byte(fmt.Sprintf("novavpn-confirm-%d", result.SessionID))
	confirmHMAC := session.ComputeHMAC(confirmData)

	var hmac32 [32]byte
	copy(hmac32[:], confirmHMAC)

	hsComplete := &protocol.HandshakeComplete{ConfirmHMAC: hmac32}
	completePayload := protocol.MarshalHandshakeComplete(hsComplete)

	encrypted, err := session.Encrypt(completePayload, nil)
	if err != nil {
		return fmt.Errorf("encrypt HandshakeComplete: %w", err)
	}

	// Извлекаем nonce из зашифрованных данных (первые 12 байт)
	var nonceArr [protocol.NonceSize]byte
	copy(nonceArr[:], encrypted[:protocol.NonceSize])

	completePkt := protocol.NewPacket(protocol.PacketHandshakeComplete, result.SessionID, 1, nonceArr, encrypted[protocol.NonceSize:])
	completeBytes, err := completePkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal packet: %w", err)
	}

	if _, err := p.conn.Write(completeBytes); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	log.Println("[HANDSHAKE] Отправлен HandshakeComplete")
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
