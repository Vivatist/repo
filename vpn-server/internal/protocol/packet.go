// Package protocol реализует собственный VPN-протокол NovaVPN v2 (stealth).
//
// Формат пакета v2 (с маскировкой под TLS):
// ┌────────────────────────┬───────────┬───────┬─────────────────────────────────────┐
// │   TLS Record Header    │ SessionID │ Nonce │    ChaCha20-Poly1305 Encrypted      │
// │  0x17 0x03 0x03 + len  │    4B     │  12B  │   (Header+Padding+Payload+Tag)      │
// └────────────────────────┴───────────┴───────┴─────────────────────────────────────┘
//
// Encrypted part contains:
// ┌─────────┬──────┬─────┬────────────┬─────────┬─────────┬─────────┐
// │ Version │ Type │ Seq │ PayloadLen │ Padding │ Payload │ AuthTag │
// │   1B    │  1B  │ 4B  │     2B     │  0-32B  │   var   │   16B   │
// └─────────┴──────┴─────┴────────────┴─────────┴─────────┴─────────┘
//
// Только SessionID передаётся открыто для роутинга. Всё остальное зашифровано.
// TLS Record Header имитирует TLS 1.2 Application Data для обхода DPI.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ProtocolVersion — версия протокола v2 (stealth)
	ProtocolVersion uint8 = 0x02

	// TLS Record Header constants (для имитации TLS 1.2 Application Data)
	TLSContentType    byte   = 0x17 // Application Data
	TLSVersionMajor   byte   = 0x03 // TLS 1.x
	TLSVersionMinor   byte   = 0x03 // TLS 1.2
	TLSHeaderSize            = 5    // type(1) + version(2) + length(2)

	// SessionIDSize — размер SessionID (единственное открытое поле)
	SessionIDSize = 4

	// NonceSize — размер nonce для ChaCha20-Poly1305
	NonceSize = 12

	// AuthTagSize — размер authentication tag
	AuthTagSize = 16

	// MinEncryptedHeaderSize — минимальный размер зашифрованного заголовка
	// version(1) + type(1) + seq(4) + payloadLen(2) = 8 байт
	MinEncryptedHeaderSize = 8

	// MaxPaddingSize — максимальный размер padding для маскировки
	MaxPaddingSize = 32

	// MinPacketSize — минимальный размер пакета
	MinPacketSize = TLSHeaderSize + SessionIDSize + NonceSize + MinEncryptedHeaderSize + AuthTagSize

	// MaxPayloadSize — максимальный размер полезной нагрузки
	MaxPayloadSize = 65535

	// MaxPacketSize — максимальный размер пакета
	MaxPacketSize = TLSHeaderSize + SessionIDSize + NonceSize + MinEncryptedHeaderSize + MaxPaddingSize + MaxPayloadSize + AuthTagSize
)

// PacketType определяет тип пакета протокола.
type PacketType uint8

const (
	// PacketHandshakeInit — инициация рукопожатия (клиент -> сервер)
	PacketHandshakeInit PacketType = 0x01

	// PacketHandshakeResp — ответ на рукопожатие (сервер -> клиент)
	PacketHandshakeResp PacketType = 0x02

	// PacketHandshakeComplete — завершение рукопожатия (клиент -> сервер)
	PacketHandshakeComplete PacketType = 0x03

	// PacketData — зашифрованные данные (IP-пакет)
	PacketData PacketType = 0x10

	// PacketKeepalive — keepalive сообщение
	PacketKeepalive PacketType = 0x20

	// PacketDisconnect — запрос на отключение
	PacketDisconnect PacketType = 0x30

	// PacketError — сообщение об ошибке
	PacketError PacketType = 0xF0
)

// String возвращает строковое представление типа пакета.
func (pt PacketType) String() string {
	switch pt {
	case PacketHandshakeInit:
		return "HandshakeInit"
	case PacketHandshakeResp:
		return "HandshakeResp"
	case PacketHandshakeComplete:
		return "HandshakeComplete"
	case PacketData:
		return "Data"
	case PacketKeepalive:
		return "Keepalive"
	case PacketDisconnect:
		return "Disconnect"
	case PacketError:
		return "Error"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(pt))
	}
}

// PacketHeader представляет заголовок пакета протокола v2.
// В v2 только SessionID передаётся открыто, остальное шифруется.
type PacketHeader struct {
	SessionID  uint32     // открыто для роутинга
	Version    uint8      // зашифровано
	Type       PacketType // зашифровано
	SequenceNo uint32     // зашифровано
	PayloadLen uint16     // зашифровано (длина plaintext без padding)
	Padding    []byte     // случайный padding 0-32 байта
}

// Packet представляет полный пакет протокола.
type Packet struct {
	Header  PacketHeader
	Nonce   [NonceSize]byte
	Payload []byte // зашифрованные данные (включая auth tag для Data-пакетов)
}

// Ошибки протокола.
var (
	ErrPacketTooShort  = errors.New("пакет слишком короткий")
	ErrPacketTooLarge  = errors.New("пакет слишком большой")
	ErrInvalidChecksum = errors.New("неверная контрольная сумма")
	ErrInvalidType     = errors.New("неизвестный тип пакета")
	ErrDecryptFailed   = errors.New("ошибка расшифровки")
	ErrInvalidTLS      = errors.New("неверный TLS заголовок")
)

// MarshalEncryptedHeader сериализует зашифрованную часть заголовка.
// Формат: version(1) + type(1) + seq(4) + payloadLen(2) + padding(0-32B)
func (h *PacketHeader) MarshalEncryptedHeader() []byte {
	size := 8 + len(h.Padding)
	buf := make([]byte, size)
	buf[0] = h.Version
	buf[1] = uint8(h.Type)
	binary.BigEndian.PutUint32(buf[2:6], h.SequenceNo)
	binary.BigEndian.PutUint16(buf[6:8], h.PayloadLen)
	if len(h.Padding) > 0 {
		copy(buf[8:], h.Padding)
	}
	return buf
}

// UnmarshalEncryptedHeader десериализует зашифрованную часть заголовка.
func UnmarshalEncryptedHeader(data []byte, sessionID uint32) (*PacketHeader, error) {
	if len(data) < 8 {
		return nil, ErrPacketTooShort
	}

	h := &PacketHeader{
		SessionID:  sessionID,
		Version:    data[0],
		Type:       PacketType(data[1]),
		SequenceNo: binary.BigEndian.Uint32(data[2:6]),
		PayloadLen: binary.BigEndian.Uint16(data[6:8]),
	}

	// Padding — всё что после первых 8 байт
	if len(data) > 8 {
		h.Padding = make([]byte, len(data)-8)
		copy(h.Padding, data[8:])
	}

	return h, nil
}

// AddTLSHeader добавляет TLS Record Header к данным.
// Имитирует TLS 1.2 Application Data для обхода DPI.
func AddTLSHeader(data []byte) []byte {
	length := uint16(len(data))
	header := make([]byte, TLSHeaderSize)
	header[0] = TLSContentType    // 0x17 = Application Data
	header[1] = TLSVersionMajor   // 0x03
	header[2] = TLSVersionMinor   // 0x03 = TLS 1.2
	binary.BigEndian.PutUint16(header[3:5], length)
	
	result := make([]byte, TLSHeaderSize+len(data))
	copy(result[0:TLSHeaderSize], header)
	copy(result[TLSHeaderSize:], data)
	return result
}

// ParseTLSHeader проверяет и удаляет TLS Record Header.
func ParseTLSHeader(data []byte) ([]byte, error) {
	if len(data) < TLSHeaderSize {
		return nil, ErrPacketTooShort
	}
	
	// Опциональная проверка TLS заголовка (для дополнительной валидации)
	if data[0] != TLSContentType {
		// Не критично - можем пропустить пакеты без TLS обёртки
	}
	
	// Извлекаем длину из TLS заголовка
	length := binary.BigEndian.Uint16(data[3:5])
	if int(length) != len(data)-TLSHeaderSize {
		return nil, ErrInvalidTLS
	}
	
	return data[TLSHeaderSize:], nil
}

// Marshal сериализует пакет в байты для отправки по сети.
// Внимание: Payload должен быть уже зашифрован!
// Формат: TLS_Header(5) + SessionID(4) + Nonce(12) + EncryptedData
func (p *Packet) Marshal() ([]byte, error) {
	// Собираем пакет без TLS заголовка
	rawSize := SessionIDSize + NonceSize + len(p.Payload)
	raw := make([]byte, rawSize)
	
	// SessionID (открытый)
	binary.BigEndian.PutUint32(raw[0:4], p.Header.SessionID)
	
	// Nonce
	copy(raw[4:16], p.Nonce[:])
	
	// Payload (уже зашифрованный)
	copy(raw[16:], p.Payload)
	
	// Добавляем TLS обёртку
	return AddTLSHeader(raw), nil
}

// Unmarshal десериализует пакет из сетевых байтов.
// Внимание: Payload остаётся зашифрованным!
// Возвращает только SessionID, Nonce и зашифрованные данные.
func Unmarshal(data []byte) (*Packet, error) {
	// Удаляем TLS обёртку (если есть)
	raw := data
	if len(data) >= TLSHeaderSize && data[0] == TLSContentType {
		var err error
		raw, err = ParseTLSHeader(data)
		if err != nil {
			return nil, err
		}
	}
	
	if len(raw) < SessionIDSize+NonceSize {
		return nil, ErrPacketTooShort
	}
	
	// Извлекаем SessionID
	sessionID := binary.BigEndian.Uint32(raw[0:4])
	
	// Извлекаем Nonce
	var nonce [NonceSize]byte
	copy(nonce[:], raw[4:16])
	
	// Payload (зашифрованный)
	payload := make([]byte, len(raw)-16)
	copy(payload, raw[16:])
	
	p := &Packet{
		Header: PacketHeader{
			SessionID: sessionID,
		},
		Nonce:   nonce,
		Payload: payload,
	}
	
	return p, nil
}

// NewPacket создаёт новый пакет с указанными параметрами.
// Внимание: payload должен быть уже зашифрован!
func NewPacket(pType PacketType, sessionID uint32, seq uint32, nonce [NonceSize]byte, encryptedPayload []byte) *Packet {
	return &Packet{
		Header: PacketHeader{
			SessionID:  sessionID,
			Version:    ProtocolVersion,
			Type:       pType,
			SequenceNo: seq,
			// PayloadLen будет установлен при шифровании
		},
		Nonce:   nonce,
		Payload: encryptedPayload,
	}
}

// NewKeepalivePacket создаёт keepalive-пакет.
// Внимание: возвращает пакет с пустым payload, требует шифрования!
func NewKeepalivePacket(sessionID uint32, seq uint32) *Packet {
	var nonce [NonceSize]byte
	return &Packet{
		Header: PacketHeader{
			SessionID:  sessionID,
			Version:    ProtocolVersion,
			Type:       PacketKeepalive,
			SequenceNo: seq,
			PayloadLen: 0,
		},
		Nonce:   nonce,
		Payload: nil,
	}
}

// NewDisconnectPacket создаёт пакет отключения.
// Внимание: возвращает пакет с пустым payload, требует шифрования!
func NewDisconnectPacket(sessionID uint32, seq uint32) *Packet {
	var nonce [NonceSize]byte
	return &Packet{
		Header: PacketHeader{
			SessionID:  sessionID,
			Version:    ProtocolVersion,
			Type:       PacketDisconnect,
			SequenceNo: seq,
			PayloadLen: 0,
		},
		Nonce:   nonce,
		Payload: nil,
	}
}

// IsHandshake проверяет, является ли пакет частью рукопожатия.
func (p *Packet) IsHandshake() bool {
	return p.Header.Type == PacketHandshakeInit ||
		p.Header.Type == PacketHandshakeResp ||
		p.Header.Type == PacketHandshakeComplete
}
