//go:build windows

// Package ipc реализует IPC через Named Pipe для Windows.
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	domainipc "github.com/novavpn/vpn-client-windows/internal/domain/ipc"
	domainvpn "github.com/novavpn/vpn-client-windows/internal/domain/vpn"
)

const (
	pipeName       = `\\.\pipe\NovaVPN`
	pipeTimeout    = 5 * time.Second
	maxMessageSize = 64 * 1024
)

// NamedPipeClient реализует IPC-клиент через Named Pipe.
type NamedPipeClient struct {
	conn net.Conn
}

// NewNamedPipeClient создаёт новый IPC-клиент.
func NewNamedPipeClient() domainipc.Client {
	return &NamedPipeClient{}
}

// Connect подключается к Named Pipe.
func (c *NamedPipeClient) connect() error {
	if c.conn != nil {
		return nil // уже подключены
	}

	conn, err := winio.DialPipe(pipeName, &pipeTimeout)
	if err != nil {
		return fmt.Errorf("dial pipe: %w", err)
	}

	c.conn = conn
	return nil
}

// Connect отправляет запрос на подключение к VPN.
func (c *NamedPipeClient) Connect(req domainipc.ConnectRequest) error {
	if err := c.connect(); err != nil {
		return err
	}

	request := map[string]interface{}{
		"type": "connect",
		"payload": map[string]string{
			"server_addr": req.ServerAddr,
			"email":       req.Email,
			"password":    req.Password,
			"psk":         req.PSK,
		},
	}

	resp, err := c.sendRequest(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	if resp["type"] == "error" {
		return fmt.Errorf("%v", resp["error"])
	}

	return nil
}

// Disconnect отправляет запрос на отключение.
func (c *NamedPipeClient) Disconnect() error {
	if err := c.connect(); err != nil {
		return err
	}

	request := map[string]interface{}{
		"type": "disconnect",
	}

	resp, err := c.sendRequest(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	if resp["type"] == "error" {
		return fmt.Errorf("%v", resp["error"])
	}

	return nil
}

// GetStatus запрашивает текущий статус.
func (c *NamedPipeClient) GetStatus() (*domainipc.StatusResponse, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	request := map[string]interface{}{
		"type": "get_status",
	}

	resp, err := c.sendRequest(request)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	if resp["type"] == "error" {
		return nil, fmt.Errorf("%v", resp["error"])
	}

	// Парсим статус
	payload, ok := resp["payload"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid payload")
	}

	status := &domainipc.StatusResponse{
		Info: fmt.Sprintf("%v", payload["state_text"]),
	}

	if stateFloat, ok := payload["state"].(float64); ok {
		status.State = domainvpn.ConnectionState(int32(stateFloat))
	}
	if bytes, ok := payload["bytes_sent"].(float64); ok {
		status.BytesSent = uint64(bytes)
	}
	if bytes, ok := payload["bytes_recv"].(float64); ok {
		status.BytesRecv = uint64(bytes)
	}
	if packets, ok := payload["packets_sent"].(float64); ok {
		status.PacketsSent = uint64(packets)
	}
	if packets, ok := payload["packets_recv"].(float64); ok {
		status.PacketsRecv = uint64(packets)
	}

	return status, nil
}

// Close закрывает соединение.
func (c *NamedPipeClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// sendRequest отправляет запрос и получает ответ.
func (c *NamedPipeClient) sendRequest(request map[string]interface{}) (map[string]interface{}, error) {
	// Сериализуем запрос
	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Отправляем (4 байта длины + данные)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(data)))
	
	if _, err := c.conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write data: %w", err)
	}

	// Читаем ответ
	if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	respLen := binary.LittleEndian.Uint32(lenBuf)
	if respLen > maxMessageSize {
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}

	respData := make([]byte, respLen)
	if _, err := io.ReadFull(c.conn, respData); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	// Парсим ответ
	var response map[string]interface{}
	if err := json.Unmarshal(respData, &response); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return response, nil
}
