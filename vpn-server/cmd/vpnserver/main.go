// NovaVPN Server — серверная часть VPN с собственным протоколом.
//
// Использование:
//
//	novavpn-server -config /etc/novavpn/server.yaml
//	novavpn-server -genkey
//	novavpn-server -genconfig
//	novavpn-server -adduser  -email user@example.com -password secret123
//	novavpn-server -deluser  -email user@example.com
//	novavpn-server -listusers
//	novavpn-server -passwd   -email user@example.com -password newpass123
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"github.com/novavpn/vpn-server/config"
	"github.com/novavpn/vpn-server/internal/auth"
	"github.com/novavpn/vpn-server/internal/protocol"
	"github.com/novavpn/vpn-server/internal/server"
	"gopkg.in/yaml.v3"
)

var (
	configPath = flag.String("config", "/etc/novavpn/server.yaml", "Путь к конфигурационному файлу")
	genPSK     = flag.Bool("genkey", false, "Сгенерировать Pre-Shared Key")
	genConfig  = flag.Bool("genconfig", false, "Сгенерировать конфигурационный файл по умолчанию")
	version    = flag.Bool("version", false, "Показать версию")

	// Управление пользователями
	addUser   = flag.Bool("adduser", false, "Добавить пользователя")
	delUser   = flag.Bool("deluser", false, "Удалить пользователя")
	listUsers = flag.Bool("listusers", false, "Показать список пользователей")
	passwd    = flag.Bool("passwd", false, "Сменить пароль пользователя")
	disUser   = flag.Bool("disable", false, "Отключить пользователя")
	enUser    = flag.Bool("enable", false, "Включить пользователя")

	// Параметры пользователя
	userEmail    = flag.String("email", "", "Email пользователя (логин)")
	userPassword = flag.String("password", "", "Пароль пользователя")
	userIP       = flag.String("ip", "", "Фиксированный VPN IP (опционально)")
	maxDevices   = flag.Int("maxdevices", 0, "Макс. одновременных подключений (0 = без лимита)")
)

// appVersion перезаписывается через ldflags: -X main.appVersion=...
var appVersion = "dev"

const appName = "NovaVPN Server"

func main() {
	flag.Parse()

	// Настраиваем логирование
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetPrefix("[NOVAVPN] ")

	if *version {
		fmt.Printf("%s v%s\n", appName, appVersion)
		os.Exit(0)
	}

	if *genPSK {
		generatePSK()
		return
	}

	if *genConfig {
		generateConfig()
		return
	}

	// Команды управления пользователями
	if *addUser {
		manageUsers("add")
		return
	}
	if *delUser {
		manageUsers("delete")
		return
	}
	if *listUsers {
		manageUsers("list")
		return
	}
	if *passwd {
		manageUsers("passwd")
		return
	}
	if *disUser {
		manageUsers("disable")
		return
	}
	if *enUser {
		manageUsers("enable")
		return
	}

	// Основной запуск сервера
	runServer()
}

// generatePSK генерирует новый Pre-Shared Key.
func generatePSK() {
	psk, err := protocol.GeneratePSK()
	if err != nil {
		log.Fatalf("Ошибка генерации PSK: %v", err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  NovaVPN — Pre-Shared Key")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  PSK: %s\n", psk)
	fmt.Println()
	fmt.Println("  Добавьте этот ключ в server.yaml:")
	fmt.Printf("  pre_shared_key: \"%s\"\n", psk)
	fmt.Println()
	fmt.Println("  Этот же ключ нужно указать на всех клиентах!")
	fmt.Println("═══════════════════════════════════════════════════════════")
}

// manageUsers — команды управления пользователями.
func manageUsers(action string) {
	// Загружаем конфигурацию (нужен путь к файлу пользователей)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		// Если конфигурация не загружается — используем путь по умолчанию
		cfg = config.DefaultConfig()
	}

	store := auth.NewUserStore(cfg.UsersFile)
	// Пробуем загрузить существующих пользователей
	_ = store.LoadUsers()

	switch action {
	case "add":
		if *userEmail == "" || *userPassword == "" {
			fmt.Println("Использование: novavpn-server -adduser -email user@example.com -password secret123 [-ip 10.8.0.2] [-maxdevices 3]")
			os.Exit(1)
		}

		if err := store.AddUser(*userEmail, *userPassword, *userIP, *maxDevices); err != nil {
			log.Fatalf("Ошибка добавления пользователя: %v", err)
		}

		if err := store.SaveUsers(); err != nil {
			log.Fatalf("Ошибка сохранения: %v", err)
		}

		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("  NovaVPN — Пользователь добавлен")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Printf("  Email:    %s\n", *userEmail)
		if *userIP != "" {
			fmt.Printf("  VPN IP:   %s (фиксированный)\n", *userIP)
		} else {
			fmt.Println("  VPN IP:   автоматический")
		}
		fmt.Println()
		fmt.Println("  Данные для клиента:")
		fmt.Printf("  - Сервер:  <ваш IP>:%d\n", cfg.ListenPort)
		fmt.Printf("  - Email:   %s\n", *userEmail)
		fmt.Printf("  - Пароль:  %s\n", *userPassword)
		fmt.Printf("  - PSK:     %s\n", cfg.PreSharedKey)
		fmt.Println("═══════════════════════════════════════════════════════════")

	case "delete":
		if *userEmail == "" {
			fmt.Println("Использование: novavpn-server -deluser -email user@example.com")
			os.Exit(1)
		}

		if err := store.RemoveUser(*userEmail); err != nil {
			log.Fatalf("Ошибка удаления: %v", err)
		}

		if err := store.SaveUsers(); err != nil {
			log.Fatalf("Ошибка сохранения: %v", err)
		}

		fmt.Printf("Пользователь '%s' удалён\n", *userEmail)

	case "list":
		users := store.ListUsers()
		if len(users) == 0 {
			fmt.Println("Пользователей нет. Добавьте: novavpn-server -adduser -email user@example.com -password secret123")
			return
		}

		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Printf("  NovaVPN — Пользователи (%d)\n", len(users))
		fmt.Println("═══════════════════════════════════════════════════════════")
		for i, u := range users {
			status := "✓"
			if !u.Enabled {
				status = "✗"
			}
			ip := "авто"
			if u.AssignedIP != "" {
				ip = u.AssignedIP
			}
			devices := "∞"
			if u.MaxDevices > 0 {
				devices = fmt.Sprintf("%d", u.MaxDevices)
			}
			fmt.Printf("  %d. [%s] %s  (IP: %s, устройств: %s)\n", i+1, status, u.Email, ip, devices)
		}
		fmt.Println("═══════════════════════════════════════════════════════════")

	case "passwd":
		if *userEmail == "" || *userPassword == "" {
			fmt.Println("Использование: novavpn-server -passwd -email user@example.com -password newpassword")
			os.Exit(1)
		}

		if err := store.ChangePassword(*userEmail, *userPassword); err != nil {
			log.Fatalf("Ошибка смены пароля: %v", err)
		}

		if err := store.SaveUsers(); err != nil {
			log.Fatalf("Ошибка сохранения: %v", err)
		}

		fmt.Printf("Пароль пользователя '%s' изменён\n", *userEmail)

	case "disable":
		if *userEmail == "" {
			fmt.Println("Использование: novavpn-server -disable -email user@example.com")
			os.Exit(1)
		}

		if err := store.SetEnabled(*userEmail, false); err != nil {
			log.Fatalf("Ошибка: %v", err)
		}

		if err := store.SaveUsers(); err != nil {
			log.Fatalf("Ошибка сохранения: %v", err)
		}

		fmt.Printf("Пользователь '%s' отключён\n", *userEmail)

	case "enable":
		if *userEmail == "" {
			fmt.Println("Использование: novavpn-server -enable -email user@example.com")
			os.Exit(1)
		}

		if err := store.SetEnabled(*userEmail, true); err != nil {
			log.Fatalf("Ошибка: %v", err)
		}

		if err := store.SaveUsers(); err != nil {
			log.Fatalf("Ошибка сохранения: %v", err)
		}

		fmt.Printf("Пользователь '%s' включён\n", *userEmail)
	}
}

// generateConfig генерирует конфигурационный файл по умолчанию.
func generateConfig() {
	psk, err := protocol.GeneratePSK()
	if err != nil {
		log.Fatalf("Ошибка генерации PSK: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.PreSharedKey = psk

	data, err := yaml.Marshal(cfg)
	if err != nil {
		log.Fatalf("Ошибка сериализации конфигурации: %v", err)
	}

	header := `# ═══════════════════════════════════════════
# NovaVPN Server — Конфигурация
# ═══════════════════════════════════════════
#
# Сгенерировано автоматически.
# Отредактируйте под ваши нужды.
#
# Генерация нового PSK: novavpn-server -genkey
# Добавить пользователя: novavpn-server -adduser -email user@mail.com -password secret123
# ═══════════════════════════════════════════

`

	fmt.Print(header)
	fmt.Print(string(data))
}

// runServer запускает VPN-сервер.
func runServer() {
	// Проверяем root права (нужны для TUN и iptables)
	if os.Geteuid() != 0 {
		log.Fatal("NovaVPN сервер требует запуска от root (sudo)")
	}

	// --- Runtime tuning для снижения хвостовых задержек (p99) ---
	//
	// GOGC=200: увеличиваем порог GC до 200% (по умолчанию 100%).
	// Это удваивает допустимый объём мусора перед GC-циклом,
	// снижая частоту STW-пауз (stop-the-world) в 2 раза.
	// Для VPN-сервера с pre-allocated буферами аллокаций мало,
	// поэтому GC-паузы — основной источник p99 спайков.
	prevGOGC := debug.SetGCPercent(200)
	log.Printf("[RUNTIME] GOGC: %d → 200 (снижение частоты GC для latency)", prevGOGC)

	// Логируем GOMAXPROCS для диагностики
	log.Printf("[RUNTIME] GOMAXPROCS: %d, NumCPU: %d", runtime.GOMAXPROCS(0), runtime.NumCPU())

	// Загружаем конфигурацию
	log.Printf("Загружаем конфигурацию из %s...", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	// Создаём сервер
	cfg.AppVersion = appVersion
	srv, err := server.NewVPNServer(cfg)
	if err != nil {
		log.Fatalf("Ошибка создания сервера: %v", err)
	}

	// Запускаем сервер
	if err := srv.Start(); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}

	// Ожидаем сигнал завершения
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("Получен сигнал %s, завершаем работу...", sig)
			srv.Stop()
			log.Println("До свидания!")
			os.Exit(0)

		case syscall.SIGHUP:
			log.Println("[SIGHUP] Перезагрузка списка пользователей...")
			srv.ReloadUsers()
		}
	}
}
