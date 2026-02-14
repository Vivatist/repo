// Package auth реализует аутентификацию пользователей по email + пароль.
//
// Пароли хешируются Argon2id (облегчённый: time=1, mem=4MB) — быстрый (~30мс),
// с умеренной GPU-стойкостью. Безопасность паролей вторична: канал защищён
// PSK (256-bit), без PSK невозможно начать handshake.
// Файл пользователей хранится в YAML.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

// Параметры Argon2id (облегчённый — ~30мс, 4МБ RAM, GPU-hardness сохранена)
// Обоснование: PSK защищает канал, brute-force хешей требует компрометации сервера.
// При 64 параллельных handshake: 64 × 4МБ = 256МБ (было 64МБ × 8 = 512МБ).
const (
	Argon2Time    = 1
	Argon2Memory  = 4 * 1024 // 4 MB (было 64 MB)
	Argon2Threads = 4
	Argon2KeyLen  = 32
	SaltLen       = 16
)

// User — запись пользователя.
type User struct {
	Email        string `yaml:"email"`
	PasswordHash string `yaml:"password_hash"` // hex(salt):hex(hash)
	AssignedIP   string `yaml:"assigned_ip"`   // фиксированный VPN IP (опционально)
	Enabled      bool   `yaml:"enabled"`
	MaxDevices   int    `yaml:"max_devices"` // макс. одновременных сессий (0 = без лимита)
}

// UsersConfig — файл пользователей.
type UsersConfig struct {
	Users []User `yaml:"users"`
}

// UserStore управляет хранилищем пользователей.
type UserStore struct {
	mu       sync.RWMutex
	users    map[string]*User // email -> User
	filePath string

	// Кеш аутентификации: пропускает Argon2id при повторном подключении.
	// Ключ — SHA-256(email + password), значение — email + время истечения.
	// TTL 5 минут — баланс между производительностью и безопасностью.
	authCacheMu sync.RWMutex
	authCache   map[[32]byte]*authCacheEntry
}

// authCacheEntry — запись кеша аутентификации.
type authCacheEntry struct {
	email  string
	expiry time.Time
}

// authCacheTTL — время жизни записи кеша аутентификации.
const authCacheTTL = 5 * time.Minute

// NewUserStore создаёт хранилище пользователей.
func NewUserStore(filePath string) *UserStore {
	return &UserStore{
		users:     make(map[string]*User),
		filePath:  filePath,
		authCache: make(map[[32]byte]*authCacheEntry),
	}
}

// LoadUsers загружает пользователей из YAML-файла.
func (us *UserStore) LoadUsers() error {
	us.mu.Lock()
	defer us.mu.Unlock()

	data, err := os.ReadFile(us.filePath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать файл пользователей: %w", err)
	}

	cfg := &UsersConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("ошибка разбора файла пользователей: %w", err)
	}

	us.users = make(map[string]*User, len(cfg.Users))
	for i := range cfg.Users {
		u := &cfg.Users[i]
		email := strings.ToLower(strings.TrimSpace(u.Email))
		us.users[email] = u
	}

	log.Printf("[AUTH] Загружено %d пользователей", len(us.users))
	return nil
}

// CleanupAuthCache удаляет устаревшие записи из кеша аутентификации.
// Вызывается периодически из maintenanceLoop сервера.
func (us *UserStore) CleanupAuthCache() int {
	us.authCacheMu.Lock()
	defer us.authCacheMu.Unlock()

	now := time.Now()
	removed := 0
	for key, entry := range us.authCache {
		if now.After(entry.expiry) {
			delete(us.authCache, key)
			removed++
		}
	}
	return removed
}

// SaveUsers сохраняет пользователей в YAML-файл.
func (us *UserStore) SaveUsers() error {
	us.mu.RLock()
	defer us.mu.RUnlock()

	cfg := &UsersConfig{
		Users: make([]User, 0, len(us.users)),
	}
	for _, u := range us.users {
		cfg.Users = append(cfg.Users, *u)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("ошибка сериализации пользователей: %w", err)
	}

	if err := os.WriteFile(us.filePath, data, 0600); err != nil {
		return fmt.Errorf("не удалось записать файл пользователей: %w", err)
	}

	return nil
}

// Authenticate проверяет email и пароль.
// Использует кеш для пропуска Argon2id при повторных подключениях (~500мс → ~100нс).
// Возвращает пользователя при успехе или ошибку.
func (us *UserStore) Authenticate(email, password string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	// Быстрая проверка кеша (SHA-256 ~100нс vs Argon2id ~500мс)
	cacheKey := sha256.Sum256([]byte(email + "\x00" + password))
	us.authCacheMu.RLock()
	if entry, ok := us.authCache[cacheKey]; ok && time.Now().Before(entry.expiry) && entry.email == email {
		us.authCacheMu.RUnlock()
		// Кеш валиден — проверяем только актуальность пользователя (без Argon2id)
		us.mu.RLock()
		user, exists := us.users[email]
		us.mu.RUnlock()
		if exists && user.Enabled {
			log.Printf("[AUTH] Кеш-аутентификация для '%s' (Argon2id пропущен)", email)
			return user, nil
		}
		// Пользователь удалён/отключён — удаляем из кеша, проходим полный путь
		us.authCacheMu.Lock()
		delete(us.authCache, cacheKey)
		us.authCacheMu.Unlock()
	} else {
		us.authCacheMu.RUnlock()
	}

	// Полная аутентификация с Argon2id
	us.mu.RLock()
	defer us.mu.RUnlock()

	user, ok := us.users[email]
	if !ok {
		// Делаем фиктивное хеширование чтобы timing attack не раскрыл наличие email
		_ = HashPassword("dummy-password-for-timing")
		return nil, fmt.Errorf("неверный email или пароль")
	}

	if !user.Enabled {
		return nil, fmt.Errorf("аккаунт отключён")
	}

	if !VerifyPassword(password, user.PasswordHash) {
		return nil, fmt.Errorf("неверный email или пароль")
	}

	// Успешная аутентификация — кешируем для пропуска Argon2id при повторном подключении
	us.authCacheMu.Lock()
	us.authCache[cacheKey] = &authCacheEntry{
		email:  email,
		expiry: time.Now().Add(authCacheTTL),
	}
	us.authCacheMu.Unlock()

	return user, nil
}

// AddUser добавляет нового пользователя.
func (us *UserStore) AddUser(email, password, assignedIP string, maxDevices int) error {
	email = strings.ToLower(strings.TrimSpace(email))

	if !isValidEmail(email) {
		return fmt.Errorf("невалидный email: %s", email)
	}

	if len(password) < 8 {
		return fmt.Errorf("пароль должен быть не менее 8 символов")
	}

	if assignedIP != "" {
		if ip := net.ParseIP(assignedIP); ip == nil {
			return fmt.Errorf("невалидный IP: %s", assignedIP)
		}
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	if _, exists := us.users[email]; exists {
		return fmt.Errorf("пользователь %s уже существует", email)
	}

	hash := HashPassword(password)

	us.users[email] = &User{
		Email:        email,
		PasswordHash: hash,
		AssignedIP:   assignedIP,
		Enabled:      true,
		MaxDevices:   maxDevices,
	}

	return nil
}

// RemoveUser удаляет пользователя.
func (us *UserStore) RemoveUser(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	us.mu.Lock()
	defer us.mu.Unlock()

	if _, exists := us.users[email]; !exists {
		return fmt.Errorf("пользователь %s не найден", email)
	}

	delete(us.users, email)
	return nil
}

// ChangePassword меняет пароль пользователя.
func (us *UserStore) ChangePassword(email, newPassword string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	if len(newPassword) < 8 {
		return fmt.Errorf("пароль должен быть не менее 8 символов")
	}

	us.mu.Lock()
	defer us.mu.Unlock()

	user, exists := us.users[email]
	if !exists {
		return fmt.Errorf("пользователь %s не найден", email)
	}

	user.PasswordHash = HashPassword(newPassword)
	return nil
}

// SetEnabled включает/отключает пользователя.
func (us *UserStore) SetEnabled(email string, enabled bool) error {
	email = strings.ToLower(strings.TrimSpace(email))

	us.mu.Lock()
	defer us.mu.Unlock()

	user, exists := us.users[email]
	if !exists {
		return fmt.Errorf("пользователь %s не найден", email)
	}

	user.Enabled = enabled
	return nil
}

// GetUser возвращает пользователя по email.
func (us *UserStore) GetUser(email string) *User {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return us.users[strings.ToLower(strings.TrimSpace(email))]
}

// ListUsers возвращает всех пользователей.
func (us *UserStore) ListUsers() []User {
	us.mu.RLock()
	defer us.mu.RUnlock()

	result := make([]User, 0, len(us.users))
	for _, u := range us.users {
		result = append(result, *u)
	}
	return result
}

// Count возвращает количество пользователей.
func (us *UserStore) Count() int {
	us.mu.RLock()
	defer us.mu.RUnlock()
	return len(us.users)
}

// HashPassword хеширует пароль с помощью Argon2id.
// Возвращает строку в формате hex(salt):hex(hash).
func HashPassword(password string) string {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("ошибка генерации соли: %v", err))
	}

	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash)
}

// VerifyPassword проверяет пароль по хешу.
func VerifyPassword(password, storedHash string) bool {
	parts := strings.SplitN(storedHash, ":", 2)
	if len(parts) != 2 {
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}

	computedHash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
}

// isValidEmail проверяет валидность email-адреса.
func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}
