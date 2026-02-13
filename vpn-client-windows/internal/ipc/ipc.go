//go:build windows

// Package ipc — обёртка для обратной совместимости.
// Делегирует в domain/ipc и infrastructure/ipc.
package ipc

import (
	domainipc "github.com/novavpn/vpn-client-windows/internal/domain/ipc"
	infraipc "github.com/novavpn/vpn-client-windows/internal/infrastructure/ipc"
)

// Состояния подключения (совместимость со старым API).
const (
	StateDisconnected  = 0
	StateConnecting    = 1
	StateConnected     = 2
	StateDisconnecting = 3
)

// ConnectParams — параметры подключения (старый API).
type ConnectParams struct {
	ServerAddr string
	PSK        string
	Email      string
	Password   string
}

// StatusResponse — статус подключения (старый API).
type StatusResponse struct {
	State       int
	AssignedIP  string
	ReceivedPSK string
	BytesSent   uint64
	BytesRecv   uint64
}

// Client — IPC-клиент к сервису NovaVPN.
type Client struct {
	inner domainipc.Client
}

// NewClient создаёт новый IPC-клиент.
func NewClient() *Client {
	return &Client{
		inner: infraipc.NewNamedPipeClient(),
	}
}

// Connect отправляет запрос на подключение.
func (c *Client) Connect(params ConnectParams) error {
	return c.inner.Connect(domainipc.ConnectRequest{
		ServerAddr: params.ServerAddr,
		Email:      params.Email,
		Password:   params.Password,
		PSK:        params.PSK,
	})
}

// Disconnect отправляет запрос на отключение.
func (c *Client) Disconnect() error {
	return c.inner.Disconnect()
}

// GetStatus запрашивает текущий статус.
func (c *Client) GetStatus() (*StatusResponse, error) {
	resp, err := c.inner.GetStatus()
	if err != nil {
		return nil, err
	}
	return &StatusResponse{
		State:      int(resp.State),
		AssignedIP: resp.AssignedIP,
		BytesSent:  resp.BytesSent,
		BytesRecv:  resp.BytesRecv,
	}, nil
}

// IsServiceRunning проверяет, доступен ли сервис NovaVPN.
func (c *Client) IsServiceRunning() bool {
	_, err := c.inner.GetStatus()
	return err == nil
}

// Close закрывает соединение.
func (c *Client) Close() error {
	return c.inner.Close()
}
