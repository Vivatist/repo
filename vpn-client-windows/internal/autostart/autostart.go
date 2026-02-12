//go:build windows

// Package autostart — управление автозапуском через реестр Windows.
package autostart

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

const (
	registryPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	appName      = "NovaVPN"
)

// Enable добавляет приложение в автозагрузку Windows.
func Enable() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("не удалось определить путь: %w", err)
	}

	key, _, err := registry.CreateKey(registry.CURRENT_USER, registryPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("ошибка реестра: %w", err)
	}
	defer key.Close()

	return key.SetStringValue(appName, fmt.Sprintf(`"%s" -autostart`, exePath))
}

// Disable убирает приложение из автозагрузки.
func Disable() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, registryPath, registry.SET_VALUE)
	if err != nil {
		return nil // ключ не существует — нечего удалять
	}
	defer key.Close()

	err = key.DeleteValue(appName)
	if err != nil {
		return nil // значение не существует
	}
	return nil
}

// IsEnabled проверяет, включён ли автозапуск.
func IsEnabled() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, registryPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	_, _, err = key.GetStringValue(appName)
	return err == nil
}
