// Package config содержит конфигурацию VPN-сервера.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig — основная конфигурация сервера.
type ServerConfig struct {
	// Адрес и порт для прослушивания UDP
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`

	// Подсеть VPN (например, 10.8.0.0/16)
	VPNSubnet string `yaml:"vpn_subnet"`

	// IP-адрес сервера внутри VPN-подсети
	ServerVPNIP string `yaml:"server_vpn_ip"`

	// Имя TUN-интерфейса
	TunName string `yaml:"tun_name"`

	// MTU туннеля
	MTU int `yaml:"mtu"`

	// DNS-серверы для клиентов
	DNS []string `yaml:"dns"`

	// Pre-Shared Key (hex-encoded, 32 bytes)
	PreSharedKey string `yaml:"pre_shared_key"`

	// Путь к файлу с пользователями (email + пароль)
	UsersFile string `yaml:"users_file"`

	// Максимальное количество клиентов
	MaxClients int `yaml:"max_clients"`

	// Таймаут keepalive в секундах
	KeepaliveInterval int `yaml:"keepalive_interval"`

	// Таймаут сессии (сек), после которого клиент считается отключённым
	SessionTimeout int `yaml:"session_timeout"`

	// Включить NAT (masquerade) для клиентов
	EnableNAT bool `yaml:"enable_nat"`

	// Внешний сетевой интерфейс (для NAT)
	ExternalInterface string `yaml:"external_interface"`

	// Максимальное количество параллельных handshake (Argon2id, ~4МБ RAM каждый)
	MaxParallelHandshakes int `yaml:"max_parallel_handshakes"`

	// GRO/GSO для TUN-устройства: "auto", "true", "false"
	// auto — пробует включить, при неудаче отключает
	// true — пробует включить, при неудаче отключает
	// false — не пытается включать
	EnableGROGSO string `yaml:"enable_gro_gso"`

	// Логирование
	LogLevel string `yaml:"log_level"` // debug, info, warn, error
}

// DefaultConfig возвращает конфигурацию по умолчанию.
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:            "0.0.0.0",
		ListenPort:            443,
		VPNSubnet:             "10.8.0.0/16",
		ServerVPNIP:           "10.8.0.1",
		TunName:               "nova0",
		MTU:                   1380,
		DNS:                   []string{"1.1.1.1", "8.8.8.8"},
		PreSharedKey:          "",
		UsersFile:             "/etc/novavpn/users.yaml",
		MaxClients:            65534,
		KeepaliveInterval:     25,
		SessionTimeout:        120,
		EnableNAT:             true,
		ExternalInterface:     "eth0",
		MaxParallelHandshakes: 64,
		EnableGROGSO:          "auto",
		LogLevel:              "info",
	}
}

// LoadConfig загружает конфигурацию из YAML-файла.
func LoadConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать конфигурацию: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("ошибка разбора конфигурации: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("невалидная конфигурация: %w", err)
	}

	return cfg, nil
}

// Validate проверяет корректность конфигурации.
func (c *ServerConfig) Validate() error {
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("некорректный порт: %d", c.ListenPort)
	}
	if c.PreSharedKey == "" {
		return fmt.Errorf("pre_shared_key обязателен")
	}
	if len(c.PreSharedKey) != 64 {
		return fmt.Errorf("pre_shared_key должен быть 32 байта в hex (64 символа)")
	}
	if c.MTU < 1280 || c.MTU > 9000 {
		return fmt.Errorf("MTU должен быть от 1280 до 9000")
	}
	if c.MaxClients < 1 || c.MaxClients > 65534 {
		return fmt.Errorf("max_clients должен быть от 1 до 65534")
	}
	if c.MaxParallelHandshakes < 1 || c.MaxParallelHandshakes > 256 {
		return fmt.Errorf("max_parallel_handshakes должен быть от 1 до 256")
	}
	if c.EnableGROGSO != "auto" && c.EnableGROGSO != "true" && c.EnableGROGSO != "false" {
		return fmt.Errorf("enable_gro_gso должен быть auto, true или false (текущее: %q)", c.EnableGROGSO)
	}
	return nil
}

// SaveConfig сохраняет конфигурацию в YAML-файл.
func SaveConfig(path string, cfg *ServerConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("ошибка сериализации конфигурации: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("не удалось записать конфигурацию: %w", err)
	}

	return nil
}
