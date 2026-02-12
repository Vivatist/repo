//go:build windows

// novavpn-service — Windows-сервис NovaVPN.
//
// Использование:
//
//	novavpn-service.exe             — запуск как Windows-сервис (вызывается SCM)
//	novavpn-service.exe install     — установить и запустить сервис (требует прав администратора)
//	novavpn-service.exe uninstall   — остановить и удалить сервис (требует прав администратора)
//	novavpn-service.exe start       — запустить уже установленный сервис
//	novavpn-service.exe stop        — остановить сервис
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/novavpn/vpn-client-windows/internal/service"
)

func main() {
	// Если запущены как Windows-сервис — работаем в режиме сервиса
	if service.IsRunningAsService() {
		if err := service.RunService(); err != nil {
			log.Fatalf("[SERVICE] Ошибка: %v", err)
		}
		return
	}

	// Интерактивный режим — обработка команд
	if len(os.Args) < 2 {
		fmt.Println("NovaVPN Service")
		fmt.Println()
		fmt.Println("Использование:")
		fmt.Println("  novavpn-service.exe install   — установить и запустить сервис")
		fmt.Println("  novavpn-service.exe uninstall — удалить сервис")
		fmt.Println("  novavpn-service.exe start     — запустить сервис")
		fmt.Println("  novavpn-service.exe stop      — остановить сервис")
		fmt.Println("  novavpn-service.exe status    — проверить статус сервиса")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "install":
		cmdInstall()
	case "uninstall":
		cmdUninstall()
	case "start":
		cmdStart()
	case "stop":
		cmdStop()
	case "status":
		cmdStatus()
	default:
		fmt.Printf("Неизвестная команда: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func cmdInstall() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Не удалось определить путь: %v", err)
	}
	exePath, _ = filepath.Abs(exePath)

	// Создаём директорию для логов
	logDir := filepath.Join(os.Getenv("ProgramData"), "NovaVPN")
	os.MkdirAll(logDir, 0755)

	fmt.Printf("Устанавливаем сервис NovaVPN (%s)...\n", exePath)

	if err := service.Install(exePath); err != nil {
		log.Fatalf("Ошибка установки: %v", err)
	}
	fmt.Println("Сервис установлен.")

	// Автоматически запускаем после установки
	fmt.Println("Запускаем сервис...")
	if err := service.Start(); err != nil {
		log.Fatalf("Ошибка запуска: %v", err)
	}
	fmt.Println("Сервис NovaVPN запущен!")
}

func cmdUninstall() {
	fmt.Println("Удаляем сервис NovaVPN...")
	if err := service.Uninstall(); err != nil {
		log.Fatalf("Ошибка удаления: %v", err)
	}
	fmt.Println("Сервис удалён.")
}

func cmdStart() {
	fmt.Println("Запускаем сервис NovaVPN...")
	if err := service.Start(); err != nil {
		log.Fatalf("Ошибка запуска: %v", err)
	}
	fmt.Println("Сервис запущен.")
}

func cmdStop() {
	fmt.Println("Останавливаем сервис NovaVPN...")
	if err := service.Stop(); err != nil {
		log.Fatalf("Ошибка остановки: %v", err)
	}
	fmt.Println("Сервис остановлен.")
}

func cmdStatus() {
	if !service.IsInstalled() {
		fmt.Println("Статус: НЕ УСТАНОВЛЕН")
		return
	}
	if service.IsRunning() {
		fmt.Println("Статус: ЗАПУЩЕН")
	} else {
		fmt.Println("Статус: ОСТАНОВЛЕН")
	}
}
