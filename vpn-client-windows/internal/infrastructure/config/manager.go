//go:build windows

// Package config реализует управление конфигурацией приложения.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	domainConfig "github.com/novavpn/vpn-client-windows/internal/domain/config"
)

const configFileName = "novavpn-config.json"

// JSONConfigManager реализует Manager для хранения конфигурации в JSON.
type JSONConfigManager struct {
	configPath string
}

// NewJSONConfigManager создаёт новый менеджер конфигурации.
func NewJSONConfigManager() *JSONConfigManager {
	return &JSONConfigManager{
		configPath: getConfigPath(),
	}
}

// Load загружает конфигурацию из файла.
func (m *JSONConfigManager) Load() (*domainConfig.Config, error) {
	// Значения по умолчанию
	cfg := &domainConfig.Config{
		ServerAddr:   "",
		Email:        "",
		Password:     "",
		PreSharedKey: "",
		WasConnected: false,
	}

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Файл не существует - возвращаем default
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config JSON: %w", err)
	}

	return cfg, nil
}

// Save сохраняет конфигурацию в файл.
func (m *JSONConfigManager) Save(cfg *domainConfig.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Создаём директорию если не существует
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// GetConfigPath возвращает путь к файлу конфигурации.
func (m *JSONConfigManager) GetConfigPath() string {
	return m.configPath
}

// getConfigPath возвращает полный путь к файлу конфигурации.
func getConfigPath() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
	}
	dir := filepath.Join(appData, "NovaVPN")
	return filepath.Join(dir, configFileName)
}
