// Package protocol реализует протокол NovaVPN v2 (клиентская часть).
// Stealth-версия с полной маскировкой под TLS.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ProtocolVersion uint8 = 0x02

	// TLS Record Header constants
	TLSContentType  byte = 0x17
	TLSVersionMajor byte = 0x03
	TLSVersionMinor byte = 0x03
	TLSHeaderSize        = 5

	SessionIDSize          = 4
	NonceSize              = 12
	AuthTagSize            = 16
	MinEncryptedHeaderSize = 8
	MaxPaddingSize         = 32
	MinPacketSize          = TLSHeaderSize + SessionIDSize + NonceSize + MinEncryptedHeaderSize + AuthTagSize
	MaxPayloadSize         = 65535
	MaxPacketSize          = TLSHeaderSize + SessionIDSize + NonceSize + MinEncryptedHeaderSize + MaxPaddingSize + MaxPayloadSize + AuthTagSize
	// PacketTypeSize — размер поля типа пакета
	PacketTypeSize = 1

	// TotalOverhead — общий оверхед протокола (для расчёта буферов)
	TotalOverhead = TLSHeaderSize + SessionIDSize + PacketTypeSize + NonceSize + AuthTagSize

	// HeaderSize — минимальный размер заголовка для валидации входящих пакетов
	HeaderSize = TLSHeaderSize + SessionIDSize + PacketTypeSize + NonceSize
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
	ErrInvalidTLS     = errors.New("invalid TLS header")
)

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

func AddTLSHeader(data []byte) []byte {
	length := uint16(len(data))
	header := make([]byte, TLSHeaderSize)
	header[0] = TLSContentType
	header[1] = TLSVersionMajor
	header[2] = TLSVersionMinor
	binary.BigEndian.PutUint16(header[3:5], length)
	result := make([]byte, TLSHeaderSize+len(data))
	copy(result[0:TLSHeaderSize], header)
	copy(result[TLSHeaderSize:], data)
	return result
}

func ParseTLSHeader(data []byte) ([]byte, error) {
	if len(data) < TLSHeaderSize {
		return nil, ErrPacketTooShort
	}
	if data[0] != TLSContentType {
		// Опционально
	}
	length := binary.BigEndian.Uint16(data[3:5])
	if int(length) != len(data)-TLSHeaderSize {
		return nil, ErrInvalidTLS
	}
	return data[TLSHeaderSize:], nil
}

func (p *Packet) Marshal() ([]byte, error) {
	// Формат: SessionID(4) + Type(1) + Nonce(12) + Payload
	rawSize := SessionIDSize + 1 + NonceSize + len(p.Payload)
	raw := make([]byte, rawSize)
	binary.BigEndian.PutUint32(raw[0:4], p.Header.SessionID)
	raw[4] = uint8(p.Header.Type)
	copy(raw[5:17], p.Nonce[:])
	copy(raw[17:], p.Payload)
	return AddTLSHeader(raw), nil
}

func Unmarshal(data []byte) (*Packet, error) {
	raw := data
	if len(data) >= TLSHeaderSize && data[0] == TLSContentType {
		var err error
		raw, err = ParseTLSHeader(data)
		if err != nil {
			return nil, err
		}
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
