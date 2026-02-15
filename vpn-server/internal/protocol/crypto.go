// Криптографические операции протокола NovaVPN.
//
// Алгоритмы:
// - Обмен ключами: ECDH Curve25519
// - Шифрование: ChaCha20-Poly1305 (AEAD)
// - Вывод ключей: HKDF-SHA256
// - Целостность: HMAC-SHA256
package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand/v2"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize — размер ключа (32 байта для ChaCha20-Poly1305 и Curve25519).
	KeySize = 32
)

// KeyPair представляет пару ключей Curve25519.
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// SessionKeys — сессионные ключи шифрования.
type SessionKeys struct {
	SendKey [KeySize]byte // Шифрование исходящих
	RecvKey [KeySize]byte // Расшифровка входящих
	HMACKey [KeySize]byte // HMAC при handshake
}

// GenerateKeyPair генерирует ephemeral пару ключей Curve25519.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, fmt.Errorf("ошибка генерации приватного ключа: %w", err)
	}

	// Clamp для Curve25519
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

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

// DeriveSessionKeys выводит сессионные ключи из shared secret через HKDF-SHA256.
// salt = PSK, info = "novavpn-session-keys-v1".
// Сервер и клиент используют зеркальные Send/Recv ключи.
func DeriveSessionKeys(sharedSecret [KeySize]byte, psk [KeySize]byte, isServer bool) (*SessionKeys, error) {
	info := []byte("novavpn-session-keys-v1")
	reader := hkdf.New(sha256.New, sharedSecret[:], psk[:], info)

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

// Encrypt шифрует данные ChaCha20-Poly1305.
// Возвращает случайный nonce и ciphertext (включая auth tag).
func Encrypt(key [KeySize]byte, plaintext []byte, additionalData []byte) (nonce [NonceSize]byte, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nonce, nil, fmt.Errorf("ошибка создания AEAD: %w", err)
	}

	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, nil, fmt.Errorf("ошибка генерации nonce: %w", err)
	}

	ciphertext = aead.Seal(nil, nonce[:], plaintext, additionalData)
	return nonce, ciphertext, nil
}

// Decrypt расшифровывает данные ChaCha20-Poly1305.
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

// VerifyHMAC проверяет HMAC-SHA256 (constant-time).
func VerifyHMAC(key [KeySize]byte, data []byte, expected [KeySize]byte) bool {
	computed := ComputeHMAC(key, data)
	return hmac.Equal(computed[:], expected[:])
}

// GeneratePSK генерирует новый Pre-Shared Key (hex, 64 символа).
func GeneratePSK() (string, error) {
	var key [KeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("ошибка генерации PSK: %w", err)
	}
	return hex.EncodeToString(key[:]), nil
}

// DecodePSK декодирует PSK из hex-строки в [32]byte.
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

// HeaderMaskSize — размер маски обфускации заголовка: SID(4) + Type(1) + Counter(4) = 9 байт.
const HeaderMaskSize = 9

// DeriveHeaderMask выводит 9-байтную маску для обфускации заголовков пакетов.
// Маска XOR'ится с SessionID(4) + PacketType(1) + Counter(4) после QUIC header.
// Вычисляется ОДИН раз при инициализации (не на каждый пакет).
func DeriveHeaderMask(psk [KeySize]byte) [HeaderMaskSize]byte {
	mac := hmac.New(sha256.New, psk[:])
	mac.Write([]byte("nova-header-mask"))
	sum := mac.Sum(nil)
	var mask [HeaderMaskSize]byte
	copy(mask[:], sum[:HeaderMaskSize])
	return mask
}

// ObfuscateHeader применяет XOR-обфускацию к заголовку пакета (после QUIC header).
// buf начинается ПОСЛЕ QUIC header: [0:4]=SessionID, [4]=Type, [5:9]=Counter.
// isData=true — обфускация Counter (9 байт), иначе только SID+Type (5 байт).
func ObfuscateHeader(buf []byte, mask [HeaderMaskSize]byte, isData bool) {
	// SessionID(4) + Type(1) = 5 байт всегда
	buf[0] ^= mask[0]
	buf[1] ^= mask[1]
	buf[2] ^= mask[2]
	buf[3] ^= mask[3]
	buf[4] ^= mask[4]
	// Counter(4) — только для data-пакетов
	if isData && len(buf) >= 9 {
		buf[5] ^= mask[5]
		buf[6] ^= mask[6]
		buf[7] ^= mask[7]
		buf[8] ^= mask[8]
	}
}

// ZeroKey обнуляет ключ (безопасное удаление из памяти).
func ZeroKey(key *[KeySize]byte) {
	for i := range key {
		key[i] = 0
	}
}

// --- Padding (Этап 2 маскировки) ---

const (
	// KeepalivePadMin — минимальный padding для keepalive/disconnect (байт)
	KeepalivePadMin = 40
	// KeepalivePadMax — максимальный padding для keepalive/disconnect (байт)
	KeepalivePadMax = 150
	// DataPadAlign — выравнивание data-пакетов (байт)
	DataPadAlign = 64
	// DataPadRandomMax — максимальный случайный добавочный padding для data (байт)
	DataPadRandomMax = 32
	// HandshakePadMin — минимальный padding для handshake-пакетов (байт)
	HandshakePadMin = 100
	// HandshakePadMax — максимальный padding для handshake-пакетов (байт)
	HandshakePadMax = 400
)

// RandomPadLen возвращает случайную длину padding в диапазоне [min, max].
// Используем math/rand/v2 — длина padding не security-critical (маскировка для DPI).
// Без syscall — критично для keepalive hot path.
func RandomPadLen(min, max int) int {
	if max <= min {
		return min
	}
	return min + mathrand.IntN(max-min+1)
}

// ComputeDataPadLen вычисляет длину padding для data-пакета.
// Выравнивает paddedPlaintext (plaintext + padding + 1 byte padLen) до DataPadAlign + random(0, DataPadRandomMax).
// Возвращает padLen (0-255). PadLen=0 означает, что добавляется только 1 байт padLen.
func ComputeDataPadLen(plaintextLen int) int {
	// Минимальный paddedPlaintext: plaintext + 1 byte (padLen)
	minPadded := plaintextLen + 1
	// Выравнивание до DataPadAlign
	alignedTarget := ((minPadded + DataPadAlign - 1) / DataPadAlign) * DataPadAlign
	padLen := alignedTarget - minPadded

	// Добавляем случайное количество байт (0..DataPadRandomMax).
	// math/rand — достаточно для длины padding (не security-critical),
	// auto-seeded от crypto/rand. Без syscall — критично для hot path.
	extra := mathrand.IntN(DataPadRandomMax + 1) // 0..32
	padLen += extra

	// Ограничиваем размер (padLen хранится в 1 байте)
	if padLen > 255 {
		padLen = 255
	}
	return padLen
}
