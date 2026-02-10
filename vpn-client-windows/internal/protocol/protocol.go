// Package protocol реализует протокол NovaVPN (клиентская часть).
// Полная совместимость с серверным протоколом.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ProtocolMagic   uint16 = 0x4E56
	ProtocolVersion uint8  = 0x01
	HeaderSize             = 14
	NonceSize              = 12
	AuthTagSize            = 16
	TotalOverhead          = HeaderSize + NonceSize + AuthTagSize
	MaxPayloadSize         = 65535
	MaxPacketSize          = HeaderSize + NonceSize + MaxPayloadSize + AuthTagSize
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
	Magic      uint16
	Version    uint8
	Type       PacketType
	SessionID  uint32
	SequenceNo uint32
	PayloadLen uint16
}

type Packet struct {
	Header  PacketHeader
	Nonce   [NonceSize]byte
	Payload []byte
}

var (
	ErrInvalidMagic   = errors.New("invalid magic bytes")
	ErrInvalidVersion = errors.New("unsupported protocol version")
	ErrPacketTooShort = errors.New("packet too short")
)

func (h *PacketHeader) MarshalHeader() []byte {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], h.Magic)
	buf[2] = h.Version
	buf[3] = uint8(h.Type)
	binary.BigEndian.PutUint32(buf[4:8], h.SessionID)
	binary.BigEndian.PutUint32(buf[8:12], h.SequenceNo)
	binary.BigEndian.PutUint16(buf[12:14], h.PayloadLen)
	return buf
}

func UnmarshalHeader(data []byte) (*PacketHeader, error) {
	if len(data) < HeaderSize {
		return nil, ErrPacketTooShort
	}
	h := &PacketHeader{
		Magic:      binary.BigEndian.Uint16(data[0:2]),
		Version:    data[2],
		Type:       PacketType(data[3]),
		SessionID:  binary.BigEndian.Uint32(data[4:8]),
		SequenceNo: binary.BigEndian.Uint32(data[8:12]),
		PayloadLen: binary.BigEndian.Uint16(data[12:14]),
	}
	if h.Magic != ProtocolMagic {
		return nil, ErrInvalidMagic
	}
	if h.Version != ProtocolVersion {
		return nil, ErrInvalidVersion
	}
	return h, nil
}

func (p *Packet) Marshal() ([]byte, error) {
	headerBytes := p.Header.MarshalHeader()
	totalLen := HeaderSize + NonceSize + len(p.Payload)
	buf := make([]byte, totalLen)
	copy(buf[0:HeaderSize], headerBytes)
	copy(buf[HeaderSize:HeaderSize+NonceSize], p.Nonce[:])
	copy(buf[HeaderSize+NonceSize:], p.Payload)
	return buf, nil
}

func Unmarshal(data []byte) (*Packet, error) {
	if len(data) < HeaderSize+NonceSize {
		return nil, ErrPacketTooShort
	}
	header, err := UnmarshalHeader(data)
	if err != nil {
		return nil, err
	}
	p := &Packet{Header: *header}
	copy(p.Nonce[:], data[HeaderSize:HeaderSize+NonceSize])
	payloadStart := HeaderSize + NonceSize
	if payloadStart < len(data) {
		p.Payload = make([]byte, len(data)-payloadStart)
		copy(p.Payload, data[payloadStart:])
	}
	return p, nil
}

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

func NewKeepalivePacket(sessionID uint32, seq uint32) *Packet {
	return NewPacket(PacketKeepalive, sessionID, seq, [NonceSize]byte{}, nil)
}

func NewDisconnectPacket(sessionID uint32, seq uint32) *Packet {
	return NewPacket(PacketDisconnect, sessionID, seq, [NonceSize]byte{}, nil)
}

// --- Handshake structures ---

type HandshakeInit struct {
	ClientPublicKey      [32]byte
	Timestamp            uint64
	EncryptedCredentials []byte
	HMAC                 [32]byte
}

type HandshakeResp struct {
	ServerPublicKey [32]byte
	SessionID       uint32
	AssignedIP      net.IP
	SubnetMask      uint8
	DNS1            net.IP
	DNS2            net.IP
	MTU             uint16
	ServerHMAC      [32]byte
}

type HandshakeComplete struct {
	ConfirmHMAC [32]byte
}

func MarshalHandshakeInit(h *HandshakeInit) []byte {
	credsLen := len(h.EncryptedCredentials)
	totalLen := 32 + 8 + 2 + credsLen + 32
	buf := make([]byte, totalLen)
	copy(buf[0:32], h.ClientPublicKey[:])
	binary.BigEndian.PutUint64(buf[32:40], h.Timestamp)
	binary.BigEndian.PutUint16(buf[40:42], uint16(credsLen))
	copy(buf[42:42+credsLen], h.EncryptedCredentials)
	copy(buf[42+credsLen:42+credsLen+32], h.HMAC[:])
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
	if len(data) < 83 {
		return nil, fmt.Errorf("handshake resp too short: %d bytes", len(data))
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
	return h, nil
}

func MarshalHandshakeComplete(h *HandshakeComplete) []byte {
	buf := make([]byte, 32)
	copy(buf[0:32], h.ConfirmHMAC[:])
	return buf
}
