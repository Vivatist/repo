package ipc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Microsoft/go-winio"
)

// Client — IPC-клиент для связи GUI с сервисом NovaVPN.
type Client struct{}

// NewClient создаёт IPC-клиент.
func NewClient() *Client {
	return &Client{}
}

// Connect отправляет команду подключения к VPN.
func (c *Client) Connect(params ConnectParams) error {
	payload, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}

	resp, err := c.sendRequest(&Request{
		Type:    CmdConnect,
		Payload: payload,
	}, 30*time.Second)
	if err != nil {
		return err
	}

	if resp.Type == RespError {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// Disconnect отправляет команду отключения VPN.
func (c *Client) Disconnect() error {
	resp, err := c.sendRequest(&Request{Type: CmdDisconnect}, 10*time.Second)
	if err != nil {
		return err
	}
	if resp.Type == RespError {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

// GetStatus запрашивает текущий статус VPN-подключения.
func (c *Client) GetStatus() (*StatusInfo, error) {
	resp, err := c.sendRequest(&Request{Type: CmdGetStatus}, 3*time.Second)
	if err != nil {
		return nil, err
	}

	if resp.Type == RespError {
		return nil, fmt.Errorf("%s", resp.Error)
	}

	var status StatusInfo
	if err := json.Unmarshal(resp.Payload, &status); err != nil {
		return nil, fmt.Errorf("unmarshal status: %w", err)
	}
	return &status, nil
}

// IsServiceRunning проверяет, доступен ли сервис (через попытку подключения к пайпу).
func (c *Client) IsServiceRunning() bool {
	timeout := 1 * time.Second
	conn, err := winio.DialPipe(PipeName, &timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// sendRequest — отправка запроса и получение ответа через Named Pipe.
func (c *Client) sendRequest(req *Request, timeout time.Duration) (*Response, error) {
	dialTimeout := 5 * time.Second
	conn, err := winio.DialPipe(PipeName, &dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к сервису NovaVPN: %w", err)
	}
	defer conn.Close()

	// Устанавливаем дедлайн на всю операцию
	conn.SetDeadline(time.Now().Add(timeout))

	if err := WriteMsg(conn, req); err != nil {
		return nil, fmt.Errorf("ошибка отправки: %w", err)
	}

	var resp Response
	if err := ReadMsg(conn, &resp); err != nil {
		return nil, fmt.Errorf("ошибка чтения ответа: %w", err)
	}

	return &resp, nil
}
