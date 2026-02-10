// Package crypto реализует криптографические операции для NovaVPN-клиента.
// Совместим с серверной реализацией.
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
	KeySize     = 32
	NonceSize   = chacha20poly1305.NonceSize
	AuthTagSize = chacha20poly1305.Overhead
)

type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

type SessionKeys struct {
	SendKey [KeySize]byte
	RecvKey [KeySize]byte
	HMACKey [KeySize]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, fmt.Errorf("key generation error: %w", err)
	}
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("public key computation error: %w", err)
	}
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

func ComputeSharedSecret(privateKey [KeySize]byte, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var shared [KeySize]byte
	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return shared, fmt.Errorf("ECDH error: %w", err)
	}
	copy(shared[:], result)
	return shared, nil
}

// DeriveSessionKeys — вывод ключей. isServer=false для клиента.
func DeriveSessionKeys(sharedSecret [KeySize]byte, psk [KeySize]byte, isServer bool) (*SessionKeys, error) {
	info := []byte("novavpn-session-keys-v1")
	reader := hkdf.New(sha256.New, sharedSecret[:], psk[:], info)

	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	key3 := make([]byte, KeySize)

	if _, err := io.ReadFull(reader, key1); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, key2); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, key3); err != nil {
		return nil, err
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

func Encrypt(key [KeySize]byte, plaintext []byte, additionalData []byte) (nonce [NonceSize]byte, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nonce, nil, err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, nil, err
	}
	ciphertext = aead.Seal(nil, nonce[:], plaintext, additionalData)
	return nonce, ciphertext, nil
}

func Decrypt(key [KeySize]byte, nonce [NonceSize]byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce[:], ciphertext, additionalData)
}

func ComputeHMAC(key [KeySize]byte, data []byte) [KeySize]byte {
	var result [KeySize]byte
	mac := hmac.New(sha256.New, key[:])
	mac.Write(data)
	copy(result[:], mac.Sum(nil))
	return result
}

func VerifyHMAC(key [KeySize]byte, data []byte, expected [KeySize]byte) bool {
	computed := ComputeHMAC(key, data)
	return hmac.Equal(computed[:], expected[:])
}

func DecodePSK(hexKey string) ([KeySize]byte, error) {
	var key [KeySize]byte
	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return key, fmt.Errorf("PSK decode error: %w", err)
	}
	if len(decoded) != KeySize {
		return key, fmt.Errorf("invalid PSK length: %d (expected %d)", len(decoded), KeySize)
	}
	copy(key[:], decoded)
	return key, nil
}

func ZeroKey(key *[KeySize]byte) {
	for i := range key {
		key[i] = 0
	}
}
