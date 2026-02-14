package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/novavpn/vpn-server/internal/protocol"
	"golang.org/x/crypto/chacha20"
)

// benchClient — легковесный VPN-клиент для нагрузочного тестирования.
// Не использует TUN — работает только на уровне протокола.
type benchClient struct {
	conn       *net.UDPConn
	serverAddr *net.UDPAddr

	sessionID  uint32
	assignedIP net.IP
	keys       *protocol.SessionKeys

	// Counter-nonce: prefix(4) + counter(8) = 12 byte nonce
	noncePrefix     [4]byte
	recvNoncePrefix [4]byte
	sendCounter     uint64
}

// newBenchClient подключается к серверу, выполняет handshake и возвращает готового клиента.
func newBenchClient(cfg *BenchConfig) (*benchClient, error) {
	// Резолвим адрес сервера
	addr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	// Создаём UDP-сокет
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	bc := &benchClient{
		conn:       conn,
		serverAddr: addr,
	}

	// Выполняем handshake с таймаутом
	if err := bc.doHandshake(cfg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return bc, nil
}

// doHandshake выполняет полный VPN handshake (1-RTT).
func (bc *benchClient) doHandshake(cfg *BenchConfig) error {
	// PSK: если задан — декодируем, иначе нулевой (bootstrap)
	var psk [protocol.KeySize]byte
	if cfg.PSKHex != "" {
		decoded, err := protocol.DecodePSK(cfg.PSKHex)
		if err != nil {
			return fmt.Errorf("PSK decode: %w", err)
		}
		psk = decoded
	}

	// 1. Генерируем ephemeral ключевую пару клиента
	clientKP, err := protocol.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	// 2. Шифруем credentials
	credPlain := protocol.MarshalCredentials(cfg.Email, cfg.Password)
	credNonce, credCipher, err := protocol.Encrypt(psk, credPlain, nil)
	if err != nil {
		return fmt.Errorf("encrypt creds: %w", err)
	}

	// EncryptedCredentials = Nonce(12) + AEAD(credentials + authTag)
	encCreds := make([]byte, protocol.NonceSize+len(credCipher))
	copy(encCreds[:protocol.NonceSize], credNonce[:])
	copy(encCreds[protocol.NonceSize:], credCipher)

	// 3. Формируем HandshakeInit
	hsInit := &protocol.HandshakeInit{
		ClientPublicKey:      clientKP.PublicKey,
		Timestamp:            uint64(time.Now().Unix()),
		EncryptedCredentials: encCreds,
	}

	// HMAC целостности: HMAC(PSK, pubkey + timestamp + encCreds)
	hmacData := make([]byte, 32+8+len(encCreds))
	copy(hmacData[0:32], clientKP.PublicKey[:])
	binary.BigEndian.PutUint64(hmacData[32:40], hsInit.Timestamp)
	copy(hmacData[40:], encCreds)
	hsInit.HMAC = protocol.ComputeHMAC(psk, hmacData)

	// 4. Сериализуем и оборачиваем в пакет
	initPayload := protocol.MarshalHandshakeInit(hsInit)
	initPkt := protocol.NewPacket(protocol.PacketHandshakeInit, 0, 0, [protocol.NonceSize]byte{}, initPayload)
	initBytes, err := initPkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal init: %w", err)
	}

	// 5. Отправляем
	bc.conn.SetWriteDeadline(time.Now().Add(cfg.HandshakeTimeout))
	if _, err := bc.conn.Write(initBytes); err != nil {
		return fmt.Errorf("send init: %w", err)
	}

	// 6. Ждём ответ (HandshakeResp)
	bc.conn.SetReadDeadline(time.Now().Add(cfg.HandshakeTimeout))
	respBuf := make([]byte, 4096)
	n, err := bc.conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("recv resp: %w", err)
	}
	respBuf = respBuf[:n]

	// 7. Парсим пакет
	respPkt, err := protocol.Unmarshal(respBuf)
	if err != nil {
		return fmt.Errorf("unmarshal resp: %w", err)
	}
	if respPkt.Header.Type != protocol.PacketHandshakeResp {
		return fmt.Errorf("ожидался HandshakeResp, получен 0x%02X", respPkt.Header.Type)
	}

	bc.sessionID = respPkt.Header.SessionID

	// 8. Payload: ServerPublicKey(32, открытый) + Encrypted(rest)
	if len(respPkt.Payload) < 32 {
		return fmt.Errorf("resp payload слишком короткий: %d", len(respPkt.Payload))
	}
	var serverPubKey [protocol.KeySize]byte
	copy(serverPubKey[:], respPkt.Payload[:32])
	encryptedResp := respPkt.Payload[32:]

	// 9. ECDH: вычисляем shared secret
	sharedSecret, err := protocol.ComputeSharedSecret(clientKP.PrivateKey, serverPubKey)
	if err != nil {
		return fmt.Errorf("ecdh: %w", err)
	}

	// 10. Выводим сессионные ключи (isServer=false: key2 = send, key1 = recv)
	sessionKeys, err := protocol.DeriveSessionKeys(sharedSecret, psk, false)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}
	bc.keys = sessionKeys

	// 11. Расшифровываем ответ сервера
	respPlain, err := protocol.Decrypt(sessionKeys.RecvKey, respPkt.Nonce, encryptedResp, nil)
	if err != nil {
		return fmt.Errorf("decrypt resp: %w", err)
	}

	// 12. Парсим HandshakeResp
	hsResp, err := protocol.UnmarshalHandshakeResp(respPlain)
	if err != nil {
		return fmt.Errorf("unmarshal resp data: %w", err)
	}

	bc.sessionID = hsResp.SessionID
	bc.assignedIP = hsResp.AssignedIP

	// Если получили PSK (bootstrap) — запоминаем (в реальном клиенте сохранили бы)
	if len(hsResp.PSK) == 32 {
		log.Printf("[BENCH] Получен PSK через bootstrap")
	}

	// 13. Инициализируем nonce prefixes
	bc.noncePrefix = deriveNoncePrefix(sessionKeys.SendKey[:])
	bc.recvNoncePrefix = deriveNoncePrefix(sessionKeys.RecvKey[:])

	// 14. Отправляем HandshakeComplete (fire-and-forget)
	confirmData := []byte(fmt.Sprintf("novavpn-confirm-%d", bc.sessionID))
	confirmHMAC := protocol.ComputeHMAC(sessionKeys.HMACKey, confirmData)

	hsComplete := &protocol.HandshakeComplete{ConfirmHMAC: confirmHMAC}
	completePayload := protocol.MarshalHandshakeComplete(hsComplete)

	// Шифруем payload
	completeNonce, completeCipher, err := protocol.Encrypt(sessionKeys.SendKey, completePayload, nil)
	if err != nil {
		return fmt.Errorf("encrypt complete: %w", err)
	}

	completePkt := protocol.NewPacket(protocol.PacketHandshakeComplete, bc.sessionID, 0, completeNonce, completeCipher)
	completeBytes, err := completePkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal complete: %w", err)
	}

	bc.conn.SetWriteDeadline(time.Now().Add(cfg.HandshakeTimeout))
	if _, err := bc.conn.Write(completeBytes); err != nil {
		return fmt.Errorf("send complete: %w", err)
	}

	// Обнуляем секреты
	protocol.ZeroKey(&sharedSecret)
	protocol.ZeroKey(&clientKP.PrivateKey)

	// Сбрасываем дедлайны
	bc.conn.SetDeadline(time.Time{})

	return nil
}

// runDataExchange выполняет обмен данными (keepalive ping-pong) в течение duration.
// Отправляет keepalive, измеряет RTT по получению ответного keepalive.
// Используется FIFO-очередь: каждый ответ соответствует следующему неопознанному запросу.
func (bc *benchClient) runDataExchange(duration time.Duration, pktSize int, interval time.Duration, clientIdx int) clientResult {
	result := clientResult{}
	deadline := time.Now().Add(duration)

	// Канал для приёма пакетов
	recvCh := make(chan recvPacket, 1000)
	stopCh := make(chan struct{})

	// Горутина приёма
	go func() {
		buf := make([]byte, 2048)
		for {
			bc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := bc.conn.Read(buf)
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
				}
				continue
			}

			// Копируем данные — буфер будет переиспользован
			pktData := make([]byte, n)
			copy(pktData, buf[:n])

			select {
			case recvCh <- recvPacket{data: pktData, at: time.Now()}:
			case <-stopCh:
				return
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// FIFO-очередь времён отправки keepalive для корректного RTT
	var sendTimes []time.Time

	for time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			// Отправляем keepalive
			kaBuf, err := bc.buildKeepalive()
			if err != nil {
				result.sendErrors++
				continue
			}
			sendTime := time.Now()
			bc.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			if _, err := bc.conn.Write(kaBuf); err != nil {
				result.sendErrors++
				continue
			}
			result.packetsSent++
			sendTimes = append(sendTimes, sendTime)

		case rp := <-recvCh:
			// Обрабатываем полученный пакет
			if len(rp.data) < protocol.MinPacketSize {
				continue
			}

			// Inline-парсинг
			raw := rp.data
			if len(raw) >= protocol.TLSHeaderSize && raw[0] == protocol.TLSContentType {
				raw = raw[protocol.TLSHeaderSize:]
			}
			if len(raw) < 5 {
				continue
			}

			pktType := protocol.PacketType(raw[4])

			switch pktType {
			case protocol.PacketKeepalive:
				// Keepalive ответ от сервера — FIFO RTT
				result.packetsRecv++
				if len(sendTimes) > 0 {
					rtt := rp.at.Sub(sendTimes[0])
					if rtt >= 0 {
						result.rttSamples = append(result.rttSamples, rtt)
					}
					sendTimes = sendTimes[1:]
				}

			case protocol.PacketData:
				result.packetsRecv++

			case protocol.PacketError:
				result.recvTimeouts++
			}

			// Чистим старые pending (>5 сек)
			now := time.Now()
			for len(sendTimes) > 0 && now.Sub(sendTimes[0]) > 5*time.Second {
				sendTimes = sendTimes[1:]
				result.recvTimeouts++
			}
		}
	}

	close(stopCh)
	return result
}

// buildKeepalive создаёт keepalive пакет.
// Формат: TLS(5) + SID(4) + Type(1) = 10 bytes
func (bc *benchClient) buildKeepalive() ([]byte, error) {
	bc.sendCounter++

	var buf [10]byte
	buf[0] = protocol.TLSContentType
	buf[1] = protocol.TLSVersionMajor
	buf[2] = protocol.TLSVersionMinor
	binary.BigEndian.PutUint16(buf[3:5], 5) // длина TLS payload = 5 (SID+Type)
	binary.BigEndian.PutUint32(buf[5:9], bc.sessionID)
	buf[9] = byte(protocol.PacketKeepalive)

	return buf[:], nil
}

// runThroughputTest — режим максимальной пропускной способности.
// Шлёт data-пакеты без пауз (fire-and-forget). Сервер получает, дешифрует, пишет в TUN.
// Параллельно считает отправленные пакеты и ошибки.
func (bc *benchClient) runThroughputTest(duration time.Duration, pktSize int, clientIdx int) clientResult {
	result := clientResult{}
	deadline := time.Now().Add(duration)

	// Пре-аллоцированный plaintext (заполняем случайными данными один раз)
	plaintext := make([]byte, pktSize)
	// Минимальный IPv4 заголовок чтобы сервер мог записать в TUN без ошибки
	if pktSize >= 20 {
		plaintext[0] = 0x45                                         // IPv4, IHL=5
		plaintext[1] = 0x00                                         // DSCP
		binary.BigEndian.PutUint16(plaintext[2:4], uint16(pktSize)) // Total Length
		plaintext[8] = 64                                           // TTL
		plaintext[9] = 0x11                                         // UDP protocol
		// Src IP: 10.8.0.x (наш VPN IP)
		if bc.assignedIP != nil {
			ip4 := bc.assignedIP.To4()
			if ip4 != nil {
				copy(plaintext[12:16], ip4)
			}
		}
		// Dst IP: 10.8.0.1 (сервер VPN IP)
		plaintext[16] = 10
		plaintext[17] = 8
		plaintext[18] = 0
		plaintext[19] = 1
	}

	// Пре-аллоцированный буфер для шифрованного пакета
	ciphertextLen := pktSize
	dataLen := 4 + 1 + 4 + ciphertextLen // SID + Type + Counter + CT
	totalLen := protocol.TLSHeaderSize + dataLen
	sendBuf := make([]byte, totalLen)

	// Заполняем статическую часть один раз
	sendBuf[0] = protocol.TLSContentType
	sendBuf[1] = protocol.TLSVersionMajor
	sendBuf[2] = protocol.TLSVersionMinor
	binary.BigEndian.PutUint16(sendBuf[3:5], uint16(dataLen))
	binary.BigEndian.PutUint32(sendBuf[5:9], bc.sessionID)
	sendBuf[9] = byte(protocol.PacketData)

	// Горутина приёма (для drain — иначе буфер UDP переполнится)
	stopCh := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			bc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := bc.conn.Read(buf)
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
				}
				continue
			}
			// Не считаем полученные — throughput считается по отправленным
			select {
			case <-stopCh:
				return
			default:
			}
		}
	}()

	// Основной цикл: шлём data-пакеты максимально быстро
	for time.Now().Before(deadline) {
		bc.sendCounter++
		wireCtr := uint32(bc.sendCounter)

		// Counter на wire
		binary.BigEndian.PutUint32(sendBuf[10:14], wireCtr)

		// Nonce: prefix(4) + uint64(counter)(8)
		var nonce [protocol.NonceSize]byte
		copy(nonce[0:4], bc.noncePrefix[:])
		binary.BigEndian.PutUint64(nonce[4:12], uint64(wireCtr))

		// Plain ChaCha20 XOR
		c, err := chacha20.NewUnauthenticatedCipher(bc.keys.SendKey[:], nonce[:])
		if err != nil {
			result.sendErrors++
			continue
		}
		c.XORKeyStream(sendBuf[14:14+pktSize], plaintext)

		bc.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := bc.conn.Write(sendBuf); err != nil {
			result.sendErrors++
			continue
		}
		result.packetsSent++
	}

	close(stopCh)
	return result
}

// buildDataPacket создаёт data-пакет с plain ChaCha20 XOR.
// Формат: TLS(5) + SID(4) + Type(1) + Counter(4) + Ciphertext
func (bc *benchClient) buildDataPacket(plaintext []byte) ([]byte, error) {
	bc.sendCounter++
	wireCtr := uint32(bc.sendCounter)

	ciphertextLen := len(plaintext) // plain XOR, без auth tag
	dataLen := 4 + 1 + 4 + ciphertextLen
	totalLen := protocol.TLSHeaderSize + dataLen

	buf := make([]byte, totalLen)

	// TLS Record Header
	buf[0] = protocol.TLSContentType
	buf[1] = protocol.TLSVersionMajor
	buf[2] = protocol.TLSVersionMinor
	binary.BigEndian.PutUint16(buf[3:5], uint16(dataLen))

	// SessionID
	binary.BigEndian.PutUint32(buf[5:9], bc.sessionID)

	// Type
	buf[9] = byte(protocol.PacketData)

	// Counter (4 bytes on wire)
	binary.BigEndian.PutUint32(buf[10:14], wireCtr)

	// Full nonce: prefix(4) + uint64(counter)(8)
	var nonce [protocol.NonceSize]byte
	copy(nonce[0:4], bc.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], uint64(wireCtr))

	// Plain ChaCha20 XOR
	c, err := chacha20.NewUnauthenticatedCipher(bc.keys.SendKey[:], nonce[:])
	if err != nil {
		return nil, fmt.Errorf("chacha20 init: %w", err)
	}
	c.XORKeyStream(buf[14:14+len(plaintext)], plaintext)

	return buf, nil
}

// disconnect отправляет пакет отключения серверу.
func (bc *benchClient) disconnect() {
	// Lightweight disconnect: TLS(5) + SID(4) + Type(1) = 10 bytes
	var buf [10]byte
	buf[0] = protocol.TLSContentType
	buf[1] = protocol.TLSVersionMajor
	buf[2] = protocol.TLSVersionMinor
	binary.BigEndian.PutUint16(buf[3:5], 5)
	binary.BigEndian.PutUint32(buf[5:9], bc.sessionID)
	buf[9] = byte(protocol.PacketDisconnect)

	bc.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	bc.conn.Write(buf[:])
	bc.conn.Close()
}

// deriveNoncePrefix выводит 4-байтный nonce prefix из ключа.
func deriveNoncePrefix(key []byte) [4]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("nova-nonce-prefix"))
	sum := mac.Sum(nil)
	var prefix [4]byte
	copy(prefix[:], sum[:4])
	return prefix
}

// recvPacket — полученный пакет с временной меткой.
type recvPacket struct {
	data []byte
	at   time.Time
}
