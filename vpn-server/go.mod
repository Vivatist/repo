module github.com/novavpn/vpn-server

go 1.25

require (
	golang.org/x/crypto v0.17.0
	golang.org/x/sys v0.15.0
	gopkg.in/yaml.v3 v3.0.1
)

// golang.org/x/crypto включает:
// - chacha20poly1305 (шифрование)
// - curve25519 (ECDH)
// - hkdf (вывод ключей)
// - argon2 (хеширование паролей)
