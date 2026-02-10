// NovaVPN Client для Windows
// Точка входа приложения
package main

import (
	"flag"
	"log"
	"os"
	"runtime"

	"github.com/novavpn/vpn-client-windows/internal/gui"
)

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

	log.Println("[MAIN] NovaVPN Client v1.0 запускается...")

	app := gui.NewApp()
	if err := app.Run(*autoStart); err != nil {
		log.Fatalf("[MAIN] Ошибка: %v", err)
	}
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
