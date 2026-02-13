//go:build windows

// Package crypto реализует криптографические операции для NovaVPN-клиента.
package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/novavpn/vpn-client-windows/internal/domain/crypto"
)

const (
	NonceSize   = chacha20poly1305.NonceSize
	AuthTagSize = chacha20poly1305.Overhead
)

// ChaCha20Session реализует криптографическую сессию с ChaCha20-Poly1305.
type ChaCha20Session struct {
	keys     *crypto.SessionKeys
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	// Counter-nonce: prefix(4) + counter(8) = 12 байт nonce.
	// Prefix выводится из ключа (обе стороны вычисляют одинаково).
	// На wire передаётся только 4-байтный counter (без prefix).
	noncePrefix     [4]byte       // HMAC(sendKey, "nova-nonce-prefix")[:4]
	recvNoncePrefix [4]byte       // HMAC(recvKey, "nova-nonce-prefix")[:4]
	sendCounter     atomic.Uint64 // инкрементируется на каждый пакет

	// Пре-аллоцированные буферы для hot path (используются по одному на горутину)
	sendBuf []byte // буфер для шифрования (nonce + ciphertext + tag)
	recvBuf []byte // буфер для дешифрования
}

// NewChaCha20Session создаёт новую криптографическую сессию.
func NewChaCha20Session(keys *crypto.SessionKeys) (*ChaCha20Session, error) {
	sendAEAD, err := chacha20poly1305.New(keys.SendKey)
	if err != nil {
		return nil, fmt.Errorf("send AEAD init: %w", err)
	}

	recvAEAD, err := chacha20poly1305.New(keys.RecvKey)
	if err != nil {
		return nil, fmt.Errorf("recv AEAD init: %w", err)
	}

	return &ChaCha20Session{
		keys:            keys,
		sendAEAD:        sendAEAD,
		recvAEAD:        recvAEAD,
		noncePrefix:     deriveNoncePrefix(keys.SendKey),
		recvNoncePrefix: deriveNoncePrefix(keys.RecvKey),
		sendBuf:         make([]byte, 0, 2048),
		recvBuf:         make([]byte, 0, 2048),
	}, nil
}

// deriveNoncePrefix выводит 4-байтный nonce prefix из ключа.
// Обе стороны вычисляют одинаковый prefix из одного ключа.
func deriveNoncePrefix(key []byte) [4]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("nova-nonce-prefix"))
	sum := mac.Sum(nil)
	var prefix [4]byte
	copy(prefix[:], sum[:4])
	return prefix
}

// Encrypt шифрует plaintext и возвращает nonce + ciphertext + auth tag.
func (s *ChaCha20Session) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
	totalLen := NonceSize + len(plaintext) + AuthTagSize

	// Переиспользуем буфер, расширяя при необходимости
	if cap(s.sendBuf) < totalLen {
		s.sendBuf = make([]byte, totalLen)
	} else {
		s.sendBuf = s.sendBuf[:totalLen]
	}

	// Counter-nonce: prefix(4) + counter(8) вместо rand.Read
	ctr := s.sendCounter.Add(1)
	copy(s.sendBuf[0:4], s.noncePrefix[:])
	binary.BigEndian.PutUint64(s.sendBuf[4:12], ctr)

	// Шифруем прямо в буфер после nonce (Seal дописывает к dst)
	s.sendAEAD.Seal(s.sendBuf[NonceSize:NonceSize], s.sendBuf[:NonceSize], plaintext, additionalData)

	// Возвращаем копию — буфер будет переиспользован
	result := make([]byte, totalLen)
	copy(result, s.sendBuf)
	return result, nil
}

// Decrypt дешифрует ciphertext (nonce + ciphertext + auth tag).
func (s *ChaCha20Session) Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+AuthTagSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(ciphertext))
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]

	// Open с dst = recvBuf[:0] переиспользует нижележащий массив
	plaintextLen := len(encrypted) - AuthTagSize
	if cap(s.recvBuf) < plaintextLen {
		s.recvBuf = make([]byte, 0, plaintextLen)
	}

	plaintext, err := s.recvAEAD.Open(s.recvBuf[:0], nonce, encrypted, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// DecryptWithNonce дешифрует ciphertext, используя nonce отдельно (без промежуточного буфера).
func (s *ChaCha20Session) DecryptWithNonce(nonce []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(nonce))
	}
	if len(ciphertext) < AuthTagSize {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(ciphertext))
	}

	plaintextLen := len(ciphertext) - AuthTagSize
	if cap(s.recvBuf) < plaintextLen {
		s.recvBuf = make([]byte, 0, plaintextLen)
	}

	plaintext, err := s.recvAEAD.Open(s.recvBuf[:0], nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptInto шифрует plaintext прямо в dst буфер (counter(4) + ciphertext).
// Plain ChaCha20 (XOR) без Poly1305 — нет auth tag.
func (s *ChaCha20Session) EncryptInto(dst []byte, plaintext []byte, additionalData []byte) (int, error) {
	// counter(4) + ciphertext (same size as plaintext, no tag)
	totalLen := 4 + len(plaintext)
	if len(dst) < totalLen {
		return 0, fmt.Errorf("dst too small: %d < %d", len(dst), totalLen)
	}

	ctr := s.sendCounter.Add(1)
	wireCtr := uint32(ctr) // truncate to 32 bit — nonce и wire используют одно значение

	// Полный nonce (prefix + truncated counter)
	var nonce [NonceSize]byte
	copy(nonce[0:4], s.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], uint64(wireCtr))

	// На wire только counter (4 байта)
	binary.BigEndian.PutUint32(dst[0:4], wireCtr)

	// Plain ChaCha20 XOR
	cipher, err := chacha20.NewUnauthenticatedCipher(s.keys.SendKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("chacha20 init: %w", err)
	}
	cipher.XORKeyStream(dst[4:4+len(plaintext)], plaintext)

	return totalLen, nil
}

// DecryptWithCounter дешифрует ciphertext с plain ChaCha20 (XOR).
// Nonce = recvNoncePrefix(4) + uint64(counter) big-endian(8).
func (s *ChaCha20Session) DecryptWithCounter(counter uint32, ciphertext []byte, additionalData []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}

	var nonce [NonceSize]byte
	copy(nonce[0:4], s.recvNoncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], uint64(counter))

	plaintextLen := len(ciphertext)
	if cap(s.recvBuf) < plaintextLen {
		s.recvBuf = make([]byte, plaintextLen)
	} else {
		s.recvBuf = s.recvBuf[:plaintextLen]
	}

	cipher, err := chacha20.NewUnauthenticatedCipher(s.keys.RecvKey, nonce[:])
	if err != nil {
		return nil, fmt.Errorf("chacha20 init: %w", err)
	}
	cipher.XORKeyStream(s.recvBuf, ciphertext)

	return s.recvBuf, nil
}

// ComputeHMAC вычисляет HMAC для данных.
func (s *ChaCha20Session) ComputeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, s.keys.HMACKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyHMAC проверяет HMAC для данных.
func (s *ChaCha20Session) VerifyHMAC(data []byte, expectedHMAC []byte) bool {
	computed := s.ComputeHMAC(data)
	return hmac.Equal(computed, expectedHMAC)
}

// Close очищает ключи из памяти.
func (s *ChaCha20Session) Close() {
	if s.keys != nil {
		zeroBytes(s.keys.SendKey)
		zeroBytes(s.keys.RecvKey)
		zeroBytes(s.keys.HMACKey)
	}
}

// GetKeys возвращает указатель на ключи сессии (для 0-RTT resume).
func (s *ChaCha20Session) GetKeys() *crypto.SessionKeys {
	return s.keys
}

// GetSendCounter возвращает текущее значение счётчика отправки (для 0-RTT resume).
func (s *ChaCha20Session) GetSendCounter() uint64 {
	return s.sendCounter.Load()
}

// SetSendCounter устанавливает значение счётчика отправки (при 0-RTT resume).
func (s *ChaCha20Session) SetSendCounter(val uint64) {
	s.sendCounter.Store(val)
}

// Curve25519KeyExchange реализует обмен ключами по Curve25519.
type Curve25519KeyExchange struct{}

// NewCurve25519KeyExchange создаёт новый объект для обмена ключами.
func NewCurve25519KeyExchange() *Curve25519KeyExchange {
	return &Curve25519KeyExchange{}
}

// GenerateKeyPair генерирует пару ключей (приватный, публичный).
func (k *Curve25519KeyExchange) GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, crypto.KeySize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("key generation: %w", err)
	}

	// Curve25519 clamping
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("public key computation: %w", err)
	}

	return privateKey, publicKey, nil
}

// ComputeSharedSecret вычисляет общий секрет из приватного и публичного ключей.
func (k *Curve25519KeyExchange) ComputeSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != crypto.KeySize || len(peerPublicKey) != crypto.KeySize {
		return nil, fmt.Errorf("invalid key sizes: private=%d, peer=%d", len(privateKey), len(peerPublicKey))
	}

	sharedSecret, err := curve25519.X25519(privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	return sharedSecret, nil
}

// DeriveSessionKeys создаёт ключи сессии из общего секрета.
func (k *Curve25519KeyExchange) DeriveSessionKeys(sharedSecret []byte, salt []byte) (*crypto.SessionKeys, error) {
	info := []byte("novavpn-session-keys-v1")
	reader := hkdf.New(sha256.New, sharedSecret, salt, info)

	sendKey := make([]byte, crypto.KeySize)
	recvKey := make([]byte, crypto.KeySize)
	hmacKey := make([]byte, crypto.KeySize)

	if _, err := io.ReadFull(reader, sendKey); err != nil {
		return nil, fmt.Errorf("derive send key: %w", err)
	}
	if _, err := io.ReadFull(reader, recvKey); err != nil {
		return nil, fmt.Errorf("derive recv key: %w", err)
	}
	if _, err := io.ReadFull(reader, hmacKey); err != nil {
		return nil, fmt.Errorf("derive HMAC key: %w", err)
	}

	// Клиент: swap send/recv (сервер использует key1 для send, клиент - для recv)
	return &crypto.SessionKeys{
		SendKey: recvKey, // swap!
		RecvKey: sendKey,
		HMACKey: hmacKey,
	}, nil
}

// DecodePSK декодирует PSK из hex-строки.
func DecodePSK(hexKey string) ([]byte, error) {
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("PSK decode error: %w", err)
	}
	if len(decoded) != crypto.KeySize {
		return nil, fmt.Errorf("invalid PSK length: %d (expected %d)", len(decoded), crypto.KeySize)
	}
	return decoded, nil
}

// GenerateRandomPadding генерирует случайный padding 0-32 байта.
func GenerateRandomPadding() ([]byte, error) {
	var sizeByte [1]byte
	if _, err := rand.Read(sizeByte[:]); err != nil {
		return nil, fmt.Errorf("padding size gen: %w", err)
	}
	size := int(sizeByte[0]) % 33
	if size == 0 {
		return nil, nil
	}
	padding := make([]byte, size)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("padding gen: %w", err)
	}
	return padding, nil
}

// zeroBytes очищает байты в slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
