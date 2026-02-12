//go:build windows

package service

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Install устанавливает NovaVPN как Windows-сервис.
func Install(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не удалось подключиться к SCM: %w", err)
	}
	defer m.Disconnect()

	// Проверяем, не установлен ли уже
	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("сервис уже установлен")
	}

	s, err = m.CreateService(ServiceName, exePath, mgr.Config{
		DisplayName: ServiceDisplayName,
		Description: ServiceDescription,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("не удалось создать сервис: %w", err)
	}
	defer s.Close()

	// Настраиваем перезапуск при сбое
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	_ = s.SetRecoveryActions(recoveryActions, 86400) // сброс через 24ч

	return nil
}

// Uninstall удаляет Windows-сервис.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не удалось подключиться к SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("сервис не найден: %w", err)
	}
	defer s.Close()

	// Останавливаем если запущен
	s.Control(svc.Stop)
	time.Sleep(2 * time.Second)

	return s.Delete()
}

// Start запускает сервис.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не удалось подключиться к SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("сервис не найден: %w", err)
	}
	defer s.Close()

	return s.Start()
}

// Stop останавливает сервис.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("не удалось подключиться к SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("сервис не найден: %w", err)
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	return err
}

// IsInstalled проверяет, установлен ли сервис (работает без прав администратора).
func IsInstalled() bool {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(h)

	name, _ := windows.UTF16PtrFromString(ServiceName)
	s, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(s)
	return true
}

// IsRunning проверяет, запущен ли сервис (работает без прав администратора).
func IsRunning() bool {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(h)

	name, _ := windows.UTF16PtrFromString(ServiceName)
	s, err := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(s)

	var status windows.SERVICE_STATUS
	err = windows.QueryServiceStatus(s, &status)
	if err != nil {
		return false
	}
	return status.CurrentState == windows.SERVICE_RUNNING
}
