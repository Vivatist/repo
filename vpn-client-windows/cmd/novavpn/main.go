//go:build windows

// NovaVPN Client для Windows
// Точка входа приложения
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/novavpn/vpn-client-windows/internal/gui"
)

// appVersion перезаписывается через ldflags: -X main.appVersion=...
var appVersion = "dev"

const mutexName = "Global\\NovaVPN_SingleInstance"

func init() {
	runtime.LockOSThread()
}

func main() {
	autoStart := flag.Bool("autostart", false, "запуск из автозагрузки")
	flag.Parse()

	// Лог-файл
	logFile := setupLogging()
	if logFile != nil {
		defer logFile.Close()
	}

	log.Printf("[MAIN] NovaVPN Client v%s запускается...", appVersion)

	// Передаём версию в GUI
	gui.AppVersion = appVersion

	// Проверяем, что не запущена вторая копия
	handle, err := acquireSingleInstanceMutex()
	if err != nil {
		log.Printf("[MAIN] NovaVPN уже запущен: %v", err)
		showAlreadyRunningMessage()
		os.Exit(0)
	}
	defer syscall.CloseHandle(handle)

	app := gui.NewApp()
	if err := app.Run(*autoStart); err != nil {
		log.Fatalf("[MAIN] Ошибка: %v", err)
	}
}

// acquireSingleInstanceMutex создаёт именованный мьютекс Windows.
// Если другой экземпляр уже владеет мьютексом — возвращает ошибку.
func acquireSingleInstanceMutex() (syscall.Handle, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createMutex := kernel32.NewProc("CreateMutexW")

	name, _ := syscall.UTF16PtrFromString(mutexName)
	handle, _, err := createMutex.Call(0, 1, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return 0, fmt.Errorf("CreateMutexW failed: %v", err)
	}
	// ERROR_ALREADY_EXISTS = 183
	if err.(syscall.Errno) == 183 {
		syscall.CloseHandle(syscall.Handle(handle))
		return 0, fmt.Errorf("мьютекс уже существует")
	}
	return syscall.Handle(handle), nil
}

// showAlreadyRunningMessage показывает MessageBox о том, что клиент уже запущен.
func showAlreadyRunningMessage() {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")

	title, _ := syscall.UTF16PtrFromString("NovaVPN")
	text, _ := syscall.UTF16PtrFromString("NovaVPN уже запущен.")

	// MB_OK | MB_ICONINFORMATION = 0x00000040
	messageBox.Call(0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(title)),
		0x00000040,
	)
}

func setupLogging() *os.File {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return nil
	}
	logDir := appData + "\\NovaVPN"
	os.MkdirAll(logDir, 0700)

	f, err := os.OpenFile(logDir+"\\novavpn.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil
	}

	log.SetOutput(f)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	return f
}
