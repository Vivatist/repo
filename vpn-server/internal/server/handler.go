package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/novavpn/vpn-server/internal/protocol"
)

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

	// Пробуем настоящий PSK, затем нулевой (bootstrap-режим)
	isBootstrap := false
	activePSK := s.psk
	if !protocol.VerifyHMAC(s.psk, hmacData, hsInit.HMAC) {
		var zeroPSK [protocol.KeySize]byte
		if !protocol.VerifyHMAC(zeroPSK, hmacData, hsInit.HMAC) {
			log.Printf("[HANDSHAKE] Неверный HMAC от %s — клиент не знает PSK", remoteAddr)
			return
		}
		isBootstrap = true
		activePSK = zeroPSK
		log.Printf("[HANDSHAKE] Bootstrap-режим для %s (клиент без PSK)", remoteAddr)
	}

	// Расшифровываем credentials (email + пароль)
	if len(hsInit.EncryptedCredentials) < 12+16 {
		log.Printf("[HANDSHAKE] Зашифрованные credentials слишком короткие от %s", remoteAddr)
		return
	}

	var credsNonce [protocol.NonceSize]byte
	copy(credsNonce[:], hsInit.EncryptedCredentials[:12])
	credsCiphertext := hsInit.EncryptedCredentials[12:]

	credsPlaintext, err := protocol.Decrypt(activePSK, credsNonce, credsCiphertext, nil)
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
	serverKP, err := protocol.GenerateKeyPair()
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка генерации ключей: %v", err)
		s.sessions.RemoveSession(session)
		return
	}
	session.ServerKeyPair = serverKP

	// Вычисляем shared secret
	sharedSecret, err := protocol.ComputeSharedSecret(serverKP.PrivateKey, hsInit.ClientPublicKey)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка ECDH: %v", err)
		s.sessions.RemoveSession(session)
		return
	}

	// Выводим сессионные ключи (при bootstrap используем нулевой PSK)
	sessionKeys, err := protocol.DeriveSessionKeys(sharedSecret, activePSK, true)
	if err != nil {
		log.Printf("[HANDSHAKE] Ошибка вывода ключей: %v", err)
		s.sessions.RemoveSession(session)
		return
	}
	session.Keys = sessionKeys

	// Обнуляем shared secret
	protocol.ZeroKey(&sharedSecret)

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

	// При bootstrap-режиме передаём настоящий PSK клиенту
	if isBootstrap {
		hsResp.PSK = s.psk[:]
		log.Printf("[HANDSHAKE] Передаём PSK клиенту в bootstrap-режиме")
	}

	// Подписываем ответ
	respData := protocol.MarshalHandshakeResp(hsResp)
	hsResp.ServerHMAC = protocol.ComputeHMAC(sessionKeys.HMACKey, respData[:51]) // до ServerHMAC
	respData = protocol.MarshalHandshakeResp(hsResp)

	// Шифруем payload (БЕЗ ServerPublicKey — он пойдёт открыто для ECDH на клиенте)
	nonce, encrypted, err := protocol.Encrypt(sessionKeys.SendKey, respData, nil)
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
	plaintext, err := protocol.Decrypt(session.Keys.RecvKey, pkt.Nonce, pkt.Payload, nil)
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
	expectedHMAC := protocol.ComputeHMAC(session.Keys.HMACKey, confirmData)
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
	plaintext, err := protocol.Decrypt(session.Keys.RecvKey, pkt.Nonce, pkt.Payload, nil)
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

// sendToClient шифрует и отправляет данные клиенту.
func (s *VPNServer) sendToClient(session *Session, plaintext []byte) {
	seq := session.NextSendSeq()

	// Формируем заголовок пакета
	header := protocol.PacketHeader{
		Version:    protocol.ProtocolVersion,
		Type:       protocol.PacketData,
		SessionID:  session.ID,
		SequenceNo: seq,
		PayloadLen: uint16(len(plaintext)),
	}

	// В v2 протоколе AAD не используется для data-пакетов
	nonce, ciphertext, err := protocol.Encrypt(session.Keys.SendKey, plaintext, nil)
	if err != nil {
		if s.cfg.LogLevel == "debug" {
			log.Printf("[SEND] Ошибка шифрования для сессии #%d: %v", session.ID, err)
		}
		return
	}

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
