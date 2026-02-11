// Package protocol реализует собственный VPN-протокол NovaVPN.
//
// Формат пакета:
// ┌──────────┬─────────┬──────┬───────────┬─────┬────────────┬───────┬───────────────────┐
// │ Magic 2B │ Ver 1B  │ Type │ SessionID │ Seq │ PayloadLen │ Nonce │ Encrypted Payload │
// │ 0x4E56   │  0x01   │ 1B   │    4B     │ 4B  │    2B      │ 12B   │    variable        │
// └──────────┴─────────┴──────┴───────────┴─────┴────────────┴───────┴───────────────────┘
// ChaCha20-Poly1305 AuthTag (16B) включён в Encrypted Payload.
// Общий overhead = 26 байт заголовка + 12 nonce + 16 auth tag = 54 байта.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// SessionIDSize — размер SessionID (единственное поле в открытом виде)
	SessionIDSize = 4

	// EncryptedHeaderSize — размер зашифрованной части заголовка
	// version(1) + type(1) + seq(4) + payloadLen(2) + padding(0-32) = variable
	EncryptedHeaderSize = 8 // минимальный размер без padding

	// NonceSize — размер nonce
	NonceSize = 12

	// AuthTagSize — размер authentication tag
	AuthTagSize = 16

	// MinPacketSize — минимальный размер пакета
	MinPacketSize = SessionIDSize + NonceSize + EncryptedHeaderSize + AuthTagSize

	// MaxPayloadSize — максимальный размер полезной нагрузки
	MaxPayloadSize = 65535

	// MaxPacketSize — максимальный размер пакета
	MaxPacketSize = SessionIDSize + NonceSize + EncryptedHeaderSize + 32 + MaxPayloadSize + AuthTagSize

	// MaxPaddingSize — максимальный размер padding для маскировки
	MaxPaddingSize = 32
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

// PacketHeader представляет заголовок пакета протокола.
// Теперь только SessionID передаётся открыто, остальное шифруется.
type PacketHeader struct {
	SessionID  uint32     // открытое поле для роутинга
	Version    uint8      // зашифровано
	Type       PacketType // зашифровано
	SequenceNo uint32     // зашифровано
	PayloadLen uint16     // зашифровано (длина plaintext)
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
)

// MarshalHeader сериализует заголовок пакета в байты (для шифрования).
// Формат: version(1) + type(1) + seq(4) + payloadLen(2) + padding(variable)
func (h *PacketHeader) MarshalHeader() []byte {
	headerSize := 1 + 1 + 4 + 2 + len(h.Padding)
	buf := make([]byte, headerSize)
	buf[0] = h.Version
	buf[1] = uint8(h.Type)
	binary.BigEndian.PutUint32(buf[2:6], h.SequenceNo)
	binary.BigEndian.PutUint16(buf[6:8], h.PayloadLen)
	if len(h.Padding) > 0 {
		copy(buf[8:], h.Padding)
	}
	return buf
}

// UnmarshalHeader десериализует заголовок из байтов (после расшифровки).
func UnmarshalHeader(data []byte, sessionID uint32) (*PacketHeader, error) {
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

// Marshal сериализует пакет в байты для отправки по сети.
func (p *Packet) Marshal() ([]byte, error) {
	headerBytes := p.Header.MarshalHeader()
	totalLen := HeaderSize + NonceSize + len(p.Payload)

	buf := make([]byte, totalLen)
	copy(buf[0:HeaderSize], headerBytes)
	copy(buf[HeaderSize:HeaderSize+NonceSize], p.Nonce[:])
	copy(buf[HeaderSize+NonceSize:], p.Payload)

	return buf, nil
}

// Unmarshal десериализует пакет из сетевых байтов.
func Unmarshal(data []byte) (*Packet, error) {
	if len(data) < HeaderSize+NonceSize {
		return nil, ErrPacketTooShort
	}

	header, err := UnmarshalHeader(data)
	if err != nil {
		return nil, err
	}

	p := &Packet{
		Header: *header,
	}

	copy(p.Nonce[:], data[HeaderSize:HeaderSize+NonceSize])

	payloadStart := HeaderSize + NonceSize
	if payloadStart < len(data) {
		p.Payload = make([]byte, len(data)-payloadStart)
		copy(p.Payload, data[payloadStart:])
	}

	return p, nil
}

// NewPacket создаёт новый пакет с указанными параметрами.
func NewPacket(pType PacketType, sessionID uint32, seq uint32, nonce [NonceSize]byte, payload []byte) *Packet {
	return &Packet{
		Header: PacketHeader{
			Magic:      ProtocolMagic,
			Version:    ProtocolVersion,
			Type:       pType,
			SessionID:  sessionID,
			SequenceNo: seq,
			PayloadLen: uint16(len(payload)),
		},
		Nonce:   nonce,
		Payload: payload,
	}
}

// NewKeepalivePacket создаёт keepalive-пакет.
func NewKeepalivePacket(sessionID uint32, seq uint32) *Packet {
	return NewPacket(PacketKeepalive, sessionID, seq, [NonceSize]byte{}, nil)
}

// NewDisconnectPacket создаёт пакет отключения.
func NewDisconnectPacket(sessionID uint32, seq uint32) *Packet {
	return NewPacket(PacketDisconnect, sessionID, seq, [NonceSize]byte{}, nil)
}

// IsHandshake проверяет, является ли пакет частью рукопожатия.
func (p *Packet) IsHandshake() bool {
	return p.Header.Type == PacketHandshakeInit ||
		p.Header.Type == PacketHandshakeResp ||
		p.Header.Type == PacketHandshakeComplete
}
