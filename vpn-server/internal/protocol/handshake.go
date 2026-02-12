package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

// HandshakeInit — данные инициации рукопожатия от клиента.
// Клиент отправляет ephemeral public key + зашифрованные credentials (email + пароль).
//
// Формат payload:
// ┌──────────────────┬────────────┬────────────────────────┬───────────┐
// │ ClientPubKey 32B │ Timestamp  │ EncryptedCredentials   │  HMAC     │
// │                  │    8B      │    variable            │  32B      │
// └──────────────────┴────────────┴────────────────────────┴───────────┘
//
// EncryptedCredentials (зашифровано PSK через ChaCha20-Poly1305):
// ┌──────────┬──────────────────────┬──────────────────────┐
// │ Nonce 12B│ encrypted(           │ AuthTag 16B          │
// │          │   EmailLen 2B        │                      │
// │          │   Email              │                      │
// │          │   PasswordLen 2B     │                      │
// │          │   Password           │                      │
// │          │ )                    │                      │
// └──────────┴──────────────────────┴──────────────────────┘
type HandshakeInit struct {
	ClientPublicKey      [32]byte // Ephemeral Curve25519 public key клиента
	Timestamp            uint64   // Unix timestamp (для защиты от replay)
	EncryptedCredentials []byte   // Nonce(12) + ChaCha20-Poly1305(email + password)
	HMAC                 [32]byte // HMAC-SHA256(PSK, весь пакет) — целостность
}

// CredentialsMinSize — минимальный размер зашифрованных credentials
// nonce(12) + encrypted(emailLen(2) + minEmail(5) + passLen(2) + minPass(8)) + authTag(16)
const CredentialsMinSize = 12 + 2 + 5 + 2 + 8 + 16

// HandshakeResp — ответ сервера на рукопожатие.
//
// Формат payload (зашифрованный сессионным ключом):
// ┌──────────────────┬───────────┬──────────────┬─────────┬──────────┬──────────┬───────────┐
// │ ServerPubKey 32B │ SessionID │ AssignedIP   │ Subnet  │ DNS1     │ DNS2     │ ServerHMAC│
// │                  │    4B     │    4B (IPv4) │ 1B mask │  4B      │  4B      │  32B      │
// └──────────────────┴───────────┴──────────────┴─────────┴──────────┴──────────┴───────────┘
type HandshakeResp struct {
	ServerPublicKey [32]byte // Ephemeral Curve25519 public key сервера
	SessionID       uint32   // Назначенный ID сессии
	AssignedIP      net.IP   // IP-адрес для клиента внутри VPN
	SubnetMask      uint8    // Маска подсети
	DNS1            net.IP   // Первый DNS
	DNS2            net.IP   // Второй DNS
	MTU             uint16   // MTU туннеля
	ServerHMAC      [32]byte // Подтверждение сервера
	PSK             []byte   // PSK для bootstrap-подключений (32 байта или nil)
}

// HandshakeComplete — подтверждение от клиента, что рукопожатие завершено.
//
// Формат payload (зашифрованный сессионным ключом):
// ┌───────────┐
// │ ConfHMAC  │
// │   32B     │
// └───────────┘
type HandshakeComplete struct {
	ConfirmHMAC [32]byte // HMAC для подтверждения успешного обмена ключами
}

// MarshalHandshakeInit сериализует HandshakeInit в байты.
func MarshalHandshakeInit(h *HandshakeInit) []byte {
	credsLen := len(h.EncryptedCredentials)
	// pubkey(32) + timestamp(8) + credsLen(2) + creds(variable) + hmac(32)
	totalLen := 32 + 8 + 2 + credsLen + 32
	buf := make([]byte, totalLen)

	copy(buf[0:32], h.ClientPublicKey[:])
	binary.BigEndian.PutUint64(buf[32:40], h.Timestamp)
	binary.BigEndian.PutUint16(buf[40:42], uint16(credsLen))
	copy(buf[42:42+credsLen], h.EncryptedCredentials)
	copy(buf[42+credsLen:42+credsLen+32], h.HMAC[:])

	return buf
}

// UnmarshalHandshakeInit десериализует HandshakeInit из байтов.
func UnmarshalHandshakeInit(data []byte) (*HandshakeInit, error) {
	// Минимум: pubkey(32) + timestamp(8) + credsLen(2) + hmac(32) = 74
	if len(data) < 74 {
		return nil, fmt.Errorf("handshake init слишком короткий: %d байт", len(data))
	}

	h := &HandshakeInit{}
	copy(h.ClientPublicKey[:], data[0:32])
	h.Timestamp = binary.BigEndian.Uint64(data[32:40])

	credsLen := int(binary.BigEndian.Uint16(data[40:42]))
	if len(data) < 42+credsLen+32 {
		return nil, fmt.Errorf("handshake init неполный: нужно %d байт, есть %d", 42+credsLen+32, len(data))
	}

	h.EncryptedCredentials = make([]byte, credsLen)
	copy(h.EncryptedCredentials, data[42:42+credsLen])
	copy(h.HMAC[:], data[42+credsLen:42+credsLen+32])

	return h, nil
}

// MarshalCredentials сериализует email и пароль в байты (для последующего шифрования).
func MarshalCredentials(email, password string) []byte {
	emailBytes := []byte(email)
	passBytes := []byte(password)

	buf := make([]byte, 2+len(emailBytes)+2+len(passBytes))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(emailBytes)))
	copy(buf[2:2+len(emailBytes)], emailBytes)
	offset := 2 + len(emailBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(passBytes)))
	copy(buf[offset+2:], passBytes)

	return buf
}

// UnmarshalCredentials десериализует email и пароль из расшифрованных байтов.
func UnmarshalCredentials(data []byte) (email, password string, err error) {
	if len(data) < 4 {
		return "", "", fmt.Errorf("credentials слишком короткие")
	}

	emailLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+emailLen+2 {
		return "", "", fmt.Errorf("credentials: невалидная длина email")
	}

	email = string(data[2 : 2+emailLen])
	offset := 2 + emailLen

	passLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	if len(data) < offset+2+passLen {
		return "", "", fmt.Errorf("credentials: невалидная длина пароля")
	}

	password = string(data[offset+2 : offset+2+passLen])
	return email, password, nil
}

// MarshalHandshakeResp сериализует HandshakeResp в байты.
func MarshalHandshakeResp(h *HandshakeResp) []byte {
	// Базовый размер: 83 байта + 1 (hasPSK) + 0 или 32 (PSK)
	hasPSK := len(h.PSK) == 32
	size := 84 // 83 + 1 byte hasPSK flag
	if hasPSK {
		size += 32
	}
	buf := make([]byte, size)
	copy(buf[0:32], h.ServerPublicKey[:])
	binary.BigEndian.PutUint32(buf[32:36], h.SessionID)

	ip4 := h.AssignedIP.To4()
	if ip4 != nil {
		copy(buf[36:40], ip4)
	}

	buf[40] = h.SubnetMask

	dns1 := h.DNS1.To4()
	if dns1 != nil {
		copy(buf[41:45], dns1)
	}

	dns2 := h.DNS2.To4()
	if dns2 != nil {
		copy(buf[45:49], dns2)
	}

	binary.BigEndian.PutUint16(buf[49:51], h.MTU)
	copy(buf[51:83], h.ServerHMAC[:])

	if hasPSK {
		buf[83] = 1
		copy(buf[84:116], h.PSK)
	} else {
		buf[83] = 0
	}
	return buf
}

// UnmarshalHandshakeResp десериализует HandshakeResp из байтов.
func UnmarshalHandshakeResp(data []byte) (*HandshakeResp, error) {
	if len(data) < 84 {
		return nil, fmt.Errorf("handshake resp слишком короткий: %d байт", len(data))
	}

	h := &HandshakeResp{}
	copy(h.ServerPublicKey[:], data[0:32])
	h.SessionID = binary.BigEndian.Uint32(data[32:36])
	h.AssignedIP = net.IPv4(data[36], data[37], data[38], data[39])
	h.SubnetMask = data[40]
	h.DNS1 = net.IPv4(data[41], data[42], data[43], data[44])
	h.DNS2 = net.IPv4(data[45], data[46], data[47], data[48])
	h.MTU = binary.BigEndian.Uint16(data[49:51])
	copy(h.ServerHMAC[:], data[51:83])

	// PSK (bootstrap)
	if data[83] == 1 && len(data) >= 116 {
		h.PSK = make([]byte, 32)
		copy(h.PSK, data[84:116])
	}

	return h, nil
}

// MarshalHandshakeComplete сериализует HandshakeComplete в байты.
func MarshalHandshakeComplete(h *HandshakeComplete) []byte {
	buf := make([]byte, 32)
	copy(buf[0:32], h.ConfirmHMAC[:])
	return buf
}

// UnmarshalHandshakeComplete десериализует HandshakeComplete из байтов.
func UnmarshalHandshakeComplete(data []byte) (*HandshakeComplete, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("handshake complete слишком короткий: %d байт", len(data))
	}

	h := &HandshakeComplete{}
	copy(h.ConfirmHMAC[:], data[0:32])
	return h, nil
}
