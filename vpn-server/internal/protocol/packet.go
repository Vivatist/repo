// Package protocol реализует собственный VPN-протокол NovaVPN v3 (stealth).
//
// Формат пакета v3 (маскировка под QUIC Short Header):
// ┌─────────────────────────────┬───────────┬──────┬───────┬───────────────────────────┐
// │   QUIC Short Header (5B)    │ SessionID │ Type │ Nonce │  ChaCha20-Poly1305 AEAD   │
// │ Flags(1) + ObfPad(4)        │    4B     │  1B  │  12B  │  (Payload + AuthTag 16B)  │
// └─────────────────────────────┴───────────┴──────┴───────┴───────────────────────────┘
//
// Пакет маскируется под QUIC Short Header (UDP:443).
// DPI видит валидный QUIC Short Header byte (0x40 | variable bits).
// Все поля после заголовка обфусцированы XOR-маской из PSK.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ProtocolVersion — версия протокола v3 (QUIC stealth)
	ProtocolVersion uint8 = 0x03

	// QUIC Short Header constants (маскировка под QUIC)
	// Flags byte: Header Form=0 (Short), Fixed Bit=1, остальное — random
	QUICFixedBitMask byte = 0x40 // bit 6 = 1 (QUIC Fixed Bit, обязателен)
	QUICHeaderSize        = 5    // flags(1) + obfuscated_pad(4)

	// Обратная совместимость: TLSHeaderSize = QUICHeaderSize (5 байт, все смещения сохраняются)
	TLSHeaderSize = QUICHeaderSize

	// Устаревшие константы (для поиска в коде, значения не используются при формировании)
	TLSContentType  byte = 0x17
	TLSVersionMajor byte = 0x03
	TLSVersionMinor byte = 0x03

	// SessionIDSize — размер SessionID (единственное открытое поле)
	SessionIDSize = 4

	// NonceSize — размер nonce для ChaCha20-Poly1305
	NonceSize = 12

	// AuthTagSize — размер authentication tag
	AuthTagSize = 16

	// MaxPayloadSize — максимальный размер полезной нагрузки
	MaxPayloadSize = 65535

	// PacketTypeSize — размер поля типа пакета (открытое, для маршрутизации)
	PacketTypeSize = 1

	// TotalOverhead — общий оверхед handshake/control пакетов (для расчёта буферов)
	TotalOverhead = TLSHeaderSize + SessionIDSize + PacketTypeSize + NonceSize + AuthTagSize

	// CounterSize — размер counter на wire (4 байта uint32)
	CounterSize = 4

	// DataOverhead — оверхед data-пакетов: TLS(5) + SID(4) + Type(1) + Counter(4) = 14
	DataOverhead = TLSHeaderSize + SessionIDSize + PacketTypeSize + CounterSize

	// MinPacketSize — минимальный размер пакета (keepalive/disconnect): TLS(5) + SID(4) + Type(1) = 10
	MinPacketSize = TLSHeaderSize + SessionIDSize + PacketTypeSize

	// HeaderSize — размер заголовка handshake-пакетов
	HeaderSize = TLSHeaderSize + SessionIDSize + PacketTypeSize + NonceSize
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
// SessionID и Type передаются открыто для маршрутизации.
type PacketHeader struct {
	SessionID  uint32     // открыто для роутинга
	Type       PacketType // открыто для маршрутизации
	Version    uint8      // версия протокола (метаданные)
	SequenceNo uint32     // порядковый номер (метаданные)
	PayloadLen uint16     // длина plaintext (метаданные)
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
	ErrInvalidHeader   = errors.New("неверный заголовок")
)

// WriteQUICHeader записывает QUIC Short Header (5 байт) в начало buf.
// Flags byte: 0x40 | random_6bits (имитирует QUIC Short Header).
// Bytes 1-4: случайные (обфусцированная «DCID-подобная» область).
// buf должен быть >= QUICHeaderSize.
func WriteQUICHeader(buf []byte) {
	// Flags: Header Form=0 (Short Header), Fixed Bit=1, остальное — random
	var rnd [5]byte
	rand.Read(rnd[:])
	buf[0] = QUICFixedBitMask | (rnd[0] & 0x3F) // 0b01XXXXXX
	buf[1] = rnd[1]
	buf[2] = rnd[2]
	buf[3] = rnd[3]
	buf[4] = rnd[4]
}

// IsQUICShortHeader проверяет, является ли первый байт валидным QUIC Short Header.
// QUIC Short Header: Header Form=0 (bit 7), Fixed Bit=1 (bit 6) → 0b01XXXXXX.
func IsQUICShortHeader(firstByte byte) bool {
	return firstByte&0xC0 == 0x40 // bits 7-6 = 01
}

// AddQUICHeader добавляет QUIC Short Header (5 байт) к данным.
// Обратная совместимость: все смещения после заголовка сохраняются.
func AddQUICHeader(data []byte) []byte {
	result := make([]byte, QUICHeaderSize+len(data))
	WriteQUICHeader(result)
	copy(result[QUICHeaderSize:], data)
	return result
}

// SkipHeader пропускает 5-байтный заголовок (QUIC Short Header).
// Не проверяет содержимое заголовка (валидация через header mask).
func SkipHeader(data []byte) ([]byte, error) {
	if len(data) < QUICHeaderSize {
		return nil, ErrPacketTooShort
	}
	return data[QUICHeaderSize:], nil
}

// Устаревшие обёртки для обратной совместимости
var AddTLSHeader = AddQUICHeader
var ParseTLSHeader = SkipHeader

// Marshal сериализует пакет в байты для отправки по сети.
// Внимание: Payload должен быть уже зашифрован!
// Формат: QUIC_Header(5) + SessionID(4) + Type(1) + Nonce(12) + EncryptedData
func (p *Packet) Marshal() ([]byte, error) {
	// Собираем пакет без QUIC заголовка
	rawSize := SessionIDSize + 1 + NonceSize + len(p.Payload)
	raw := make([]byte, rawSize)

	// SessionID (открытый)
	binary.BigEndian.PutUint32(raw[0:4], p.Header.SessionID)

	// PacketType (открытый, для маршрутизации)
	raw[4] = uint8(p.Header.Type)

	// Nonce
	copy(raw[5:17], p.Nonce[:])

	// Payload (уже зашифрованный)
	copy(raw[17:], p.Payload)

	// Добавляем QUIC Short Header обёртку
	return AddQUICHeader(raw), nil
}

// Unmarshal десериализует пакет из сетевых байтов.
// Внимание: Payload остаётся зашифрованным!
// Возвращает только SessionID, Nonce и зашифрованные данные.
func Unmarshal(data []byte) (*Packet, error) {
	// Пропускаем QUIC Short Header (5 байт)
	raw := data
	if len(data) >= QUICHeaderSize {
		var err error
		raw, err = SkipHeader(data)
		if err != nil {
			return nil, err
		}
	}

	// SessionID(4) + Type(1) + Nonce(12) = 17 bytes minimum
	if len(raw) < SessionIDSize+1+NonceSize {
		return nil, ErrPacketTooShort
	}

	// Извлекаем SessionID
	sessionID := binary.BigEndian.Uint32(raw[0:4])

	// Извлекаем PacketType
	pktType := PacketType(raw[4])

	// Извлекаем Nonce
	var nonce [NonceSize]byte
	copy(nonce[:], raw[5:17])

	// Payload (зашифрованный)
	payload := make([]byte, len(raw)-17)
	copy(payload, raw[17:])

	p := &Packet{
		Header: PacketHeader{
			SessionID: sessionID,
			Type:      pktType,
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
