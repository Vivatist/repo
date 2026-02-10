// Package crypto реализует криптографические операции для NovaVPN.
//
// Используемые алгоритмы:
// - Обмен ключами: ECDH на Curve25519
// - Шифрование: ChaCha20-Poly1305 (AEAD)
// - Вывод ключей: HKDF-SHA256
// - HMAC: HMAC-SHA256
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize — размер ключа (32 байта для ChaCha20-Poly1305 и Curve25519)
	KeySize = 32

	// NonceSize — размер nonce для ChaCha20-Poly1305
	NonceSize = chacha20poly1305.NonceSize // 12

	// AuthTagSize — размер authentication tag
	AuthTagSize = chacha20poly1305.Overhead // 16
)

// KeyPair представляет пару ключей Curve25519.
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// SessionKeys представляет ключи шифрования для конкретной сессии.
type SessionKeys struct {
	// SendKey — ключ для шифрования исходящих данных
	SendKey [KeySize]byte

	// RecvKey — ключ для расшифровки входящих данных
	RecvKey [KeySize]byte

	// HMACKey — ключ для HMAC
	HMACKey [KeySize]byte
}

// GenerateKeyPair генерирует новую пару ключей Curve25519.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	// Генерируем случайный приватный ключ
	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, fmt.Errorf("ошибка генерации приватного ключа: %w", err)
	}

	// Clamp private key для Curve25519
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	// Вычисляем публичный ключ
	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления публичного ключа: %w", err)
	}
	copy(kp.PublicKey[:], pub)

	return kp, nil
}

// ComputeSharedSecret вычисляет общий секрет ECDH.
func ComputeSharedSecret(privateKey [KeySize]byte, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var shared [KeySize]byte

	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return shared, fmt.Errorf("ошибка ECDH: %w", err)
	}
	copy(shared[:], result)

	return shared, nil
}

// DeriveSessionKeys выводит сессионные ключи из shared secret с помощью HKDF.
// salt — Pre-Shared Key, info — контекст (например, "novavpn-session-keys").
func DeriveSessionKeys(sharedSecret [KeySize]byte, psk [KeySize]byte, isServer bool) (*SessionKeys, error) {
	// HKDF: extract + expand
	info := []byte("novavpn-session-keys-v1")
	reader := hkdf.New(sha256.New, sharedSecret[:], psk[:], info)

	// Выводим 3 ключа по 32 байта
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	key3 := make([]byte, KeySize)

	if _, err := io.ReadFull(reader, key1); err != nil {
		return nil, fmt.Errorf("ошибка вывода ключа 1: %w", err)
	}
	if _, err := io.ReadFull(reader, key2); err != nil {
		return nil, fmt.Errorf("ошибка вывода ключа 2: %w", err)
	}
	if _, err := io.ReadFull(reader, key3); err != nil {
		return nil, fmt.Errorf("ошибка вывода ключа 3: %w", err)
	}

	sk := &SessionKeys{}

	// Сервер и клиент используют ключи в противоположном порядке
	if isServer {
		copy(sk.SendKey[:], key1)
		copy(sk.RecvKey[:], key2)
	} else {
		copy(sk.SendKey[:], key2)
		copy(sk.RecvKey[:], key1)
	}
	copy(sk.HMACKey[:], key3)

	return sk, nil
}

// Encrypt шифрует данные с помощью ChaCha20-Poly1305.
// Возвращает nonce и зашифрованные данные (включая auth tag).
func Encrypt(key [KeySize]byte, plaintext []byte, additionalData []byte) (nonce [NonceSize]byte, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nonce, nil, fmt.Errorf("ошибка создания AEAD: %w", err)
	}

	// Генерируем случайный nonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, nil, fmt.Errorf("ошибка генерации nonce: %w", err)
	}

	// Шифруем с AEAD (включает auth tag)
	ciphertext = aead.Seal(nil, nonce[:], plaintext, additionalData)
	return nonce, ciphertext, nil
}

// Decrypt расшифровывает данные с помощью ChaCha20-Poly1305.
func Decrypt(key [KeySize]byte, nonce [NonceSize]byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AEAD: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	return plaintext, nil
}

// ComputeHMAC вычисляет HMAC-SHA256.
func ComputeHMAC(key [KeySize]byte, data []byte) [KeySize]byte {
	var result [KeySize]byte
	mac := hmac.New(sha256.New, key[:])
	mac.Write(data)
	copy(result[:], mac.Sum(nil))
	return result
}

// VerifyHMAC проверяет HMAC-SHA256.
func VerifyHMAC(key [KeySize]byte, data []byte, expected [KeySize]byte) bool {
	computed := ComputeHMAC(key, data)
	return hmac.Equal(computed[:], expected[:])
}

// GenerateRandomBytes генерирует криптографически безопасные случайные байты.
func GenerateRandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("ошибка генерации случайных байтов: %w", err)
	}
	return buf, nil
}

// GeneratePSK генерирует новый Pre-Shared Key.
func GeneratePSK() (string, error) {
	var key [KeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("ошибка генерации PSK: %w", err)
	}
	return hex.EncodeToString(key[:]), nil
}

// DecodePSK декодирует PSK из hex-строки.
func DecodePSK(hexKey string) ([KeySize]byte, error) {
	var key [KeySize]byte
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return key, fmt.Errorf("ошибка декодирования PSK: %w", err)
	}
	if len(decoded) != KeySize {
		return key, fmt.Errorf("неверная длина PSK: %d (ожидается %d)", len(decoded), KeySize)
	}
	copy(key[:], decoded)
	return key, nil
}

// GenerateNonce генерирует случайный nonce.
func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, fmt.Errorf("ошибка генерации nonce: %w", err)
	}
	return nonce, nil
}

// Zero обнуляет срез байтов (для безопасного удаления ключей из памяти).
func Zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// ZeroKey обнуляет ключ.
func ZeroKey(key *[KeySize]byte) {
	for i := range key {
		key[i] = 0
	}
}
