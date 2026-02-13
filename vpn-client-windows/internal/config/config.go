//go:build windows

// Package config — обёртка для обратной совместимости.
// Делегирует в domain/config и infrastructure/config.
package config

import (
	"log"

	domainconfig "github.com/novavpn/vpn-client-windows/internal/domain/config"
	infraconfig "github.com/novavpn/vpn-client-windows/internal/infrastructure/config"
)

// Config — конфигурация приложения.
type Config struct {
	ServerAddr   string
	Email        string
	Password     string
	PSK          string
	WasConnected bool

	mgr domainconfig.Manager
}

// Load загружает конфигурацию из файла.
func Load() *Config {
	mgr := infraconfig.NewJSONConfigManager()
	dc, err := mgr.Load()
	if err != nil {
		log.Printf("[CONFIG] Ошибка загрузки: %v", err)
		dc = &domainconfig.Config{}
	}
	return &Config{
		ServerAddr:   dc.ServerAddr,
		Email:        dc.Email,
		Password:     dc.Password,
		PSK:          dc.PreSharedKey,
		WasConnected: dc.WasConnected,
		mgr:          mgr,
	}
}

// Save сохраняет конфигурацию в файл.
func (c *Config) Save() error {
	dc := &domainconfig.Config{
		ServerAddr:   c.ServerAddr,
		Email:        c.Email,
		Password:     c.Password,
		PreSharedKey: c.PSK,
		WasConnected: c.WasConnected,
	}
	return c.mgr.Save(dc)
}
