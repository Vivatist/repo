//go:build windows

// Package vpnservice предоставляет application-layer сервис для управления VPN.
package vpnservice

import (
	"fmt"
	"log"
	"sync"

	domainconfig "github.com/novavpn/vpn-client-windows/internal/domain/config"
	domainnet "github.com/novavpn/vpn-client-windows/internal/domain/network"
	domainvpn "github.com/novavpn/vpn-client-windows/internal/domain/vpn"
	infraconfig "github.com/novavpn/vpn-client-windows/internal/infrastructure/config"
	infranet "github.com/novavpn/vpn-client-windows/internal/infrastructure/network"
	infravpn "github.com/novavpn/vpn-client-windows/internal/infrastructure/vpn"
)

// Service — application-layer сервис для управления VPN.
type Service struct {
	client        domainvpn.Client
	configMgr     domainconfig.Manager
	tunnelDevice  domainnet.TunnelDevice
	netConfig     domainnet.NetworkConfigurator
	mu            sync.Mutex
	config        *domainconfig.Config
	connectParams domainvpn.ConnectParams // последние параметры подключения
}

// NewService создаёт новый VPN service.
func NewService() (*Service, error) {
	// Создаём network configurator
	netConfig := infranet.NewWindowsConfigurator()

	// Создаём config manager
	configMgr := infraconfig.NewJSONConfigManager()

	// Загружаем конфигурацию
	config, err := configMgr.Load()
	if err != nil {
		log.Printf("[SERVICE] Не удалось загрузить конфигурацию: %v", err)
		config = &domainconfig.Config{}
	}

	return &Service{
		configMgr: configMgr,
		netConfig: netConfig,
		config:    config,
	}, nil
}

// Connect подключается к VPN-серверу.
func (s *Service) Connect(params domainvpn.ConnectParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Сохраняем параметры для возможного переподключения (resume после sleep)
	s.connectParams = params

	// Создаём TUN device
	tunnelDevice, err := infranet.NewWinTUNDevice("NovaVPN", 1420)
	if err != nil {
		return fmt.Errorf("create TUN device: %w", err)
	}
	s.tunnelDevice = tunnelDevice

	// Создаём VPN клиент с зависимостями
	s.client = infravpn.NewNovaVPNClient(
		s.tunnelDevice,
		s.netConfig,
		func(state domainvpn.ConnectionState, info string) {
			log.Printf("[VPN] Состояние: %s (%s)", state, info)
		},
		func(pskHex string) {
			log.Printf("[VPN] Получен новый PSK (bootstrap)")
			// Сохраняем PSK в конфигурацию
			s.config.PreSharedKey = pskHex
			if err := s.configMgr.Save(s.config); err != nil {
				log.Printf("[VPN] Не удалось сохранить PSK: %v", err)
			}
		},
		func(health domainvpn.ConnectionHealth) {
			log.Printf("[VPN] Здоровье соединения: %s", health)
		},
	)

	// Подключаемся
	if err := s.client.Connect(params); err != nil {
		// Очищаем TUN device при ошибке
		if s.tunnelDevice != nil {
			s.tunnelDevice.Close()
			s.tunnelDevice = nil
		}
		return err
	}

	// Сохраняем конфигурацию
	s.config.ServerAddr = params.ServerAddr
	s.config.Email = params.Email
	s.config.Password = params.Password
	s.config.PreSharedKey = params.PSK
	s.config.WasConnected = true
	if err := s.configMgr.Save(s.config); err != nil {
		log.Printf("[VPN] Не удалось сохранить конфигурацию: %v", err)
	}

	return nil
}

// Disconnect отключается от VPN-сервера.
func (s *Service) Disconnect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client == nil {
		return fmt.Errorf("not connected")
	}

	// Отключаемся (client.Disconnect закрывает TUN)
	if err := s.client.Disconnect(); err != nil {
		return err
	}

	// TUN уже закрыт client.Disconnect(), обнуляем ссылку
	s.tunnelDevice = nil

	// Обновляем конфигурацию
	s.config.WasConnected = false
	if err := s.configMgr.Save(s.config); err != nil {
		log.Printf("[VPN] Не удалось сохранить конфигурацию: %v", err)
	}

	return nil
}

// GetState возвращает текущее состояние подключения.
func (s *Service) GetState() domainvpn.ConnectionState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client == nil {
		return domainvpn.StateDisconnected
	}

	return s.client.GetState()
}

// GetStatistics возвращает статистику.
func (s *Service) GetStatistics() domainvpn.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client == nil {
		return domainvpn.Statistics{}
	}

	return s.client.GetStatistics()
}

// GetInfo возвращает информацию о подключении.
func (s *Service) GetInfo() domainvpn.ConnectionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client == nil {
		return domainvpn.ConnectionInfo{
			State: domainvpn.StateDisconnected,
		}
	}

	return s.client.GetInfo()
}

// GetConfig возвращает текущую конфигурацию.
func (s *Service) GetConfig() *domainconfig.Config {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.config
}

// GetConnectParams возвращает последние параметры подключения (для переподключения после sleep/resume).
func (s *Service) GetConnectParams() domainvpn.ConnectParams {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.connectParams
}
