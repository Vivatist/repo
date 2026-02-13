//go:build windows

// Package config определяет интерфейс для работы с конфигурацией.
package config

// Config — конфигурация приложения.
type Config struct {
	ServerAddr   string `json:"server"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	PreSharedKey string `json:"pre_shared_key"`
	WasConnected bool   `json:"was_connected"`
}

// Manager — интерфейс для управления конфигурацией.
type Manager interface {
	// Load загружает конфигурацию из файла.
	Load() (*Config, error)

	// Save сохраняет конфигурацию в файл.
	Save(cfg *Config) error

	// GetConfigPath возвращает путь к файлу конфигурации.
	GetConfigPath() string
}
