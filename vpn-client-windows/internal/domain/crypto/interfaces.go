//go:build windows

// Package crypto определяет интерфейсы для криптографических операций.
package crypto

// KeySize — размер ключа в байтах (32 байта для Curve25519/ChaCha20).
const KeySize = 32

// SessionKeys — ключи для текущей сессии.
type SessionKeys struct {
	SendKey []byte // Ключ для шифрования исходящих пакетов
	RecvKey []byte // Ключ для дешифрования входящих пакетов
	HMACKey []byte // Ключ для HMAC
}

// Session — интерфейс криптографической сессии.
type Session interface {
	// Encrypt шифрует plaintext и возвращает ciphertext с nonce и auth tag.
	Encrypt(plaintext []byte, additionalData []byte) ([]byte, error)

	// Decrypt дешифрует ciphertext и проверяет auth tag.
	Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error)

	// DecryptWithNonce дешифрует ciphertext с отдельным nonce (без промежуточного буфера).
	DecryptWithNonce(nonce []byte, ciphertext []byte, additionalData []byte) ([]byte, error)

	// EncryptInto шифрует plaintext прямо в dst (nonce + ciphertext + tag).
	// Возвращает количество записанных байт. Zero-copy для hot path.
	EncryptInto(dst []byte, plaintext []byte, additionalData []byte) (int, error)

	// ComputeHMAC вычисляет HMAC для данных.
	ComputeHMAC(data []byte) []byte

	// VerifyHMAC проверяет HMAC для данных.
	VerifyHMAC(data []byte, expectedHMAC []byte) bool

	// Close очищает ключи из памяти.
	Close()
}

// KeyExchange — интерфейс для обмена ключами.
type KeyExchange interface {
	// GenerateKeyPair генерирует пару ключей (приватный, публичный).
	GenerateKeyPair() (privateKey, publicKey []byte, err error)

	// ComputeSharedSecret вычисляет общий секрет из приватного и публичного ключей.
	ComputeSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error)

	// DeriveSessionKeys создаёт ключи сессии из общего секрета.
	DeriveSessionKeys(sharedSecret []byte, salt []byte) (*SessionKeys, error)
}
