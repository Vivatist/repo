// Package ipc реализует IPC-протокол между GUI и сервисом NovaVPN
// через именованный канал (Named Pipe).
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// PipeName — имя Named Pipe для связи GUI ↔ Service.
const PipeName = `\\.\pipe\NovaVPN`

// PipeSecurity — SDDL дескриптор безопасности пайпа.
// AU = Authenticated Users (чтение/запись), SY = SYSTEM (полный доступ), BA = Admins (полный доступ).
const PipeSecurity = "D:(A;;GRGW;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)"

const maxMessageSize = 64 * 1024 // 64 КБ максимальный размер сообщения

// Состояния VPN-подключения (дублирует vpnclient.ConnectionState для изоляции GUI от vpnclient).
const (
	StateDisconnected  = 0
	StateConnecting    = 1
	StateConnected     = 2
	StateDisconnecting = 3
)

// Типы команд GUI → Service.
const (
	CmdConnect    = "connect"
	CmdDisconnect = "disconnect"
	CmdGetStatus  = "get_status"
)

// Типы ответов Service → GUI.
const (
	RespOK     = "ok"
	RespError  = "error"
	RespStatus = "status"
)

// Request — запрос от GUI к сервису.
type Request struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Response — ответ от сервиса к GUI.
type Response struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// ConnectParams — параметры подключения.
type ConnectParams struct {
	ServerAddr string `json:"server_addr"`
	PSK        string `json:"psk"`
	Email      string `json:"email"`
	Password   string `json:"password"`
}

// StatusInfo — информация о состоянии VPN.
type StatusInfo struct {
	State       int    `json:"state"`
	StateText   string `json:"state_text"`
	AssignedIP  string `json:"assigned_ip,omitempty"`
	ReceivedPSK string `json:"received_psk,omitempty"` // PSK полученный при bootstrap-подключении
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

// StateText возвращает текстовое описание состояния.
func StateText(state int) string {
	switch state {
	case StateDisconnected:
		return "Отключён"
	case StateConnecting:
		return "Подключение..."
	case StateConnected:
		return "Подключён"
	case StateDisconnecting:
		return "Отключение..."
	default:
		return "Неизвестно"
	}
}

// WriteMsg записывает сообщение в соединение (4-байтный заголовок длины + JSON).
func WriteMsg(conn net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(data)))

	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// ReadMsg читает сообщение из соединения (4-байтный заголовок длины + JSON).
func ReadMsg(conn net.Conn, v interface{}) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	size := binary.LittleEndian.Uint32(header)
	if size > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes", size)
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	return json.Unmarshal(data, v)
}
