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
	mathrand "math/rand/v2"
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

	// Маска обфускации заголовка (SID+Type+Counter), устанавливается через SetHeaderMask
	headerMask [HeaderMaskSize]byte
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

// EncryptInto шифрует plaintext прямо в dst буфер (counter(4) + ciphertext с padding).
// Plain ChaCha20 (XOR) без Poly1305 — нет auth tag.
// Padding: plaintext + zeros(padLen) + byte(padLen) — внутри шифротекста.
func (s *ChaCha20Session) EncryptInto(dst []byte, plaintext []byte, additionalData []byte) (int, error) {
	padLen := ComputeDataPadLen(len(plaintext))
	paddedLen := len(plaintext) + padLen + 1 // +1 для байта padLen
	totalLen := 4 + paddedLen                // counter(4) + paddedCT
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

	// Plain ChaCha20 XOR: шифруем plaintext, затем padding + padLen
	cipher, err := chacha20.NewUnauthenticatedCipher(s.keys.SendKey, nonce[:])
	if err != nil {
		return 0, fmt.Errorf("chacha20 init: %w", err)
	}
	// Шифруем plaintext
	cipher.XORKeyStream(dst[4:4+len(plaintext)], plaintext)
	// Шифруем padding (нули → raw keystream, выглядит случайно) + padLen байт
	for i := 0; i < padLen; i++ {
		dst[4+len(plaintext)+i] = 0
	}
	dst[4+len(plaintext)+padLen] = byte(padLen)
	cipher.XORKeyStream(dst[4+len(plaintext):4+paddedLen], dst[4+len(plaintext):4+paddedLen])

	return totalLen, nil
}

// DecryptWithCounter дешифрует ciphertext с plain ChaCha20 (XOR) и снимает padding.
// Nonce = recvNoncePrefix(4) + uint64(counter) big-endian(8).
// Padding формат: plaintext + zeros(padLen) + byte(padLen) — последний расшифрованный байт = padLen.
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

	// Снимаем padding: последний байт = padLen
	padLen := int(s.recvBuf[plaintextLen-1])
	actualLen := plaintextLen - 1 - padLen
	if actualLen < 20 { // минимальный IP-пакет
		return nil, fmt.Errorf("invalid padding: padLen=%d, totalLen=%d, actualLen=%d", padLen, plaintextLen, actualLen)
	}

	return s.recvBuf[:actualLen], nil
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

// HeaderMaskSize — размер маски обфускации заголовка (9 байт).
const HeaderMaskSize = 9

// Padding constants (Этап 2 маскировки)
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
// math/rand/v2 — длина padding не security-critical. Без syscall на hot path.
func RandomPadLen(min, max int) int {
	if max <= min {
		return min
	}
	return min + mathrand.IntN(max-min+1)
}

// ComputeDataPadLen вычисляет длину padding для data-пакета.
func ComputeDataPadLen(plaintextLen int) int {
	minPadded := plaintextLen + 1
	alignedTarget := ((minPadded + DataPadAlign - 1) / DataPadAlign) * DataPadAlign
	padLen := alignedTarget - minPadded

	// math/rand — достаточно для длины padding (не security-critical),
	// auto-seeded от crypto/rand. Без syscall — критично для hot path.
	extra := mathrand.IntN(DataPadRandomMax + 1) // 0..32
	padLen += extra

	if padLen > 255 {
		padLen = 255
	}
	return padLen
}

// DeriveHeaderMask выводит 9-байтную маску для обфускации заголовков пакетов из PSK.
func DeriveHeaderMask(psk []byte) [HeaderMaskSize]byte {
	mac := hmac.New(sha256.New, psk)
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
	buf[0] ^= mask[0]
	buf[1] ^= mask[1]
	buf[2] ^= mask[2]
	buf[3] ^= mask[3]
	buf[4] ^= mask[4]
	if isData && len(buf) >= 9 {
		buf[5] ^= mask[5]
		buf[6] ^= mask[6]
		buf[7] ^= mask[7]
		buf[8] ^= mask[8]
	}
}

// SetHeaderMask устанавливает маску обфускации заголовка для исходящих пакетов.
func (s *ChaCha20Session) SetHeaderMask(mask [HeaderMaskSize]byte) {
	s.headerMask = mask
}

// GetHeaderMask возвращает текущую маску обфускации заголовка.
func (s *ChaCha20Session) GetHeaderMask() [HeaderMaskSize]byte {
	return s.headerMask
}
