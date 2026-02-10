// Package config — конфигурация и сохранение состояния VPN-клиента.
package config

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

const configFileName = "novavpn-config.json"

// Config — настройки клиента.
type Config struct {
	ServerAddr   string `json:"server_addr"`   // host:port
	PSK          string `json:"psk"`           // hex-encoded PSK
	Email        string `json:"email"`         // логин
	Password     string `json:"password"`      // пароль (TODO: DPAPI encryption)
	AutoStart    bool   `json:"auto_start"`    // запуск при старте Windows
	WasConnected bool   `json:"was_connected"` // было ли соединение перед закрытием
}

// configDir возвращает директорию для конфигурации.
func configDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
	}
	dir := filepath.Join(appData, "NovaVPN")
	os.MkdirAll(dir, 0700)
	return dir
}

// ConfigPath возвращает полный путь к файлу конфигурации.
func ConfigPath() string {
	return filepath.Join(configDir(), configFileName)
}

// Load загружает конфигурацию из файла.
func Load() *Config {
	cfg := &Config{
		ServerAddr: "",
		PSK:        "",
		Email:      "",
		Password:   "",
		AutoStart:  false,
	}

	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return cfg
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("[CONFIG] Ошибка чтения конфигурации: %v", err)
		return cfg
	}

	return cfg
}

// Save сохраняет конфигурацию в файл.
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(), data, 0600)
}
