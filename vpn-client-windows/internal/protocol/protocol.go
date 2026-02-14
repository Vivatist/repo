// Package protocol реализует протокол NovaVPN v3 (клиентская часть).
// Stealth-версия с маскировкой под QUIC Short Header (UDP:443).
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ProtocolVersion uint8 = 0x03

	// QUIC Short Header constants (маскировка под QUIC)
	// Flags byte: Header Form=0 (Short), Fixed Bit=1, остальное — random
	QUICFixedBitMask byte = 0x40 // bit 6 = 1 (QUIC Fixed Bit, обязателен)
	QUICHeaderSize        = 5    // flags(1) + obfuscated_pad(4)

	// Обратная совместимость: TLSHeaderSize = QUICHeaderSize (5 байт, все смещения сохраняются)
	TLSHeaderSize = QUICHeaderSize

	// Устаревшие константы (для поиска в коде, больше не используются при формировании)
	TLSContentType  byte = 0x17
	TLSVersionMajor byte = 0x03
	TLSVersionMinor byte = 0x03

	SessionIDSize          = 4
	NonceSize              = 12
	AuthTagSize            = 16
	MinEncryptedHeaderSize = 8
	MaxPaddingSize         = 32
	MinHandshakePacketSize = TLSHeaderSize + SessionIDSize + NonceSize + MinEncryptedHeaderSize + AuthTagSize
	MaxPayloadSize         = 65535
	MaxPacketSize          = TLSHeaderSize + SessionIDSize + NonceSize + MinEncryptedHeaderSize + MaxPaddingSize + MaxPayloadSize + AuthTagSize
	// PacketTypeSize — размер поля типа пакета
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

	// HeaderMaskSize — размер маски обфускации заголовка: SID(4) + Type(1) + Counter(4) = 9 байт
	HeaderMaskSize = 9
)

type PacketType uint8

const (
	PacketHandshakeInit     PacketType = 0x01
	PacketHandshakeResp     PacketType = 0x02
	PacketHandshakeComplete PacketType = 0x03
	PacketData              PacketType = 0x10
	PacketKeepalive         PacketType = 0x20
	PacketDisconnect        PacketType = 0x30
	PacketError             PacketType = 0xF0
)

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

type PacketHeader struct {
	SessionID  uint32
	Version    uint8
	Type       PacketType
	SequenceNo uint32
	PayloadLen uint16
	Padding    []byte
}

type Packet struct {
	Header  PacketHeader
	Nonce   [NonceSize]byte
	Payload []byte
}

var (
	ErrPacketTooShort = errors.New("packet too short")
	ErrDecryptFailed  = errors.New("decrypt failed")
	ErrInvalidHeader  = errors.New("invalid header")
)

// WriteQUICHeader записывает QUIC Short Header (5 байт) в начало buf.
// Flags byte: 0x40 | random_6bits (имитирует QUIC Short Header).
// Bytes 1-4: случайные (обфусцированная «DCID-подобная» область).
// buf должен быть >= QUICHeaderSize.
func WriteQUICHeader(buf []byte) {
	var rnd [5]byte
	rand.Read(rnd[:])
	buf[0] = QUICFixedBitMask | (rnd[0] & 0x3F) // 0b01XXXXXX
	buf[1] = rnd[1]
	buf[2] = rnd[2]
	buf[3] = rnd[3]
	buf[4] = rnd[4]
}

// IsQUICShortHeader проверяет, является ли первый байт валидным QUIC Short Header.
func IsQUICShortHeader(firstByte byte) bool {
	return firstByte&0xC0 == 0x40 // bits 7-6 = 01
}

// AddQUICHeader добавляет QUIC Short Header (5 байт) к данным.
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
func AddTLSHeader(data []byte) []byte { return AddQUICHeader(data) }
func ParseTLSHeader(data []byte) ([]byte, error) { return SkipHeader(data) }

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
	if len(data) > 8 {
		h.Padding = make([]byte, len(data)-8)
		copy(h.Padding, data[8:])
	}
	return h, nil
}

func (p *Packet) Marshal() ([]byte, error) {
	// Формат: QUIC_Header(5) + SessionID(4) + Type(1) + Nonce(12) + Payload
	rawSize := SessionIDSize + 1 + NonceSize + len(p.Payload)
	raw := make([]byte, rawSize)
	binary.BigEndian.PutUint32(raw[0:4], p.Header.SessionID)
	raw[4] = uint8(p.Header.Type)
	copy(raw[5:17], p.Nonce[:])
	copy(raw[17:], p.Payload)
	return AddQUICHeader(raw), nil
}

func Unmarshal(data []byte) (*Packet, error) {
	// Всегда пропускаем 5-байтный заголовок (QUIC Short Header)
	raw, err := SkipHeader(data)
	if err != nil {
		return nil, err
	}
	// SessionID(4) + Type(1) + Nonce(12) = 17 bytes minimum
	if len(raw) < SessionIDSize+1+NonceSize {
		return nil, ErrPacketTooShort
	}
	sessionID := binary.BigEndian.Uint32(raw[0:4])
	pktType := PacketType(raw[4])
	var nonce [NonceSize]byte
	copy(nonce[:], raw[5:17])
	payload := make([]byte, len(raw)-17)
	copy(payload, raw[17:])
	p := &Packet{
		Header:  PacketHeader{SessionID: sessionID, Type: pktType},
		Nonce:   nonce,
		Payload: payload,
	}
	return p, nil
}

func NewPacket(pType PacketType, sessionID uint32, seq uint32, nonce [NonceSize]byte, encryptedPayload []byte) *Packet {
	return &Packet{
		Header: PacketHeader{
			SessionID:  sessionID,
			Version:    ProtocolVersion,
			Type:       pType,
			SequenceNo: seq,
		},
		Nonce:   nonce,
		Payload: encryptedPayload,
	}
}

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

// --- Handshake structures ---

type HandshakeInit struct {
	ClientPublicKey      [32]byte // Ephemeral Curve25519 public key
	Timestamp            uint64
	EncryptedCredentials []byte
	HMAC                 [32]byte // HMAC-SHA256(PSK, pubkey+timestamp+creds)
}

type HandshakeResp struct {
	SessionID  uint32
	AssignedIP net.IP
	SubnetMask uint8
	DNS1       net.IP
	DNS2       net.IP
	MTU        uint16
	PSK        []byte // PSK от сервера при bootstrap-подключении (32 байта или nil)
}

type HandshakeComplete struct {
	ConfirmHMAC [32]byte
}

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

func MarshalHandshakeComplete(h *HandshakeComplete) []byte {
	buf := make([]byte, 32)
	copy(buf[0:32], h.ConfirmHMAC[:])
	return buf
}

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

func UnmarshalHandshakeResp(data []byte) (*HandshakeResp, error) {
	// Серверный формат: ServerPublicKey(32) + SessionID(4) + IP(4) + Mask(1) + DNS1(4) + DNS2(4) + MTU(2) + ServerHMAC(32) + HasPSK(1) [+ PSK(32)]
	// Минимум 84 байта (83 + 1 байт hasPSK)
	if len(data) < 84 {
		return nil, fmt.Errorf("handshake resp too short: %d bytes", len(data))
	}
	h := &HandshakeResp{}
	h.SessionID = binary.BigEndian.Uint32(data[32:36])
	h.AssignedIP = net.IPv4(data[36], data[37], data[38], data[39])
	h.SubnetMask = data[40]
	h.DNS1 = net.IPv4(data[41], data[42], data[43], data[44])
	h.DNS2 = net.IPv4(data[45], data[46], data[47], data[48])
	h.MTU = binary.BigEndian.Uint16(data[49:51])

	// PSK (bootstrap-режим)
	if data[83] == 1 && len(data) >= 116 {
		h.PSK = make([]byte, 32)
		copy(h.PSK, data[84:116])
	}
	return h, nil
}
