package com.novavpn.tv.data.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

/**
 * Обмен ключами по Curve25519 (X25519) + HKDF-SHA256.
 *
 * Использует BouncyCastle X25519 для ECDH и HKDF для вывода сессионных ключей.
 */
object NovaKeyExchange {

    private const val KEY_SIZE = 32
    private const val SESSION_KEYS_INFO = "novavpn-session-keys-v1"

    /**
     * Генерирует пару ключей Curve25519 (приватный + публичный).
     * Возвращает Pair(privateKey, publicKey).
     */
    fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val random = SecureRandom()
        val privParams = X25519PrivateKeyParameters(random)
        val pubParams = privParams.generatePublicKey()

        val privateKey = privParams.encoded
        val publicKey = pubParams.encoded

        return Pair(privateKey, publicKey)
    }

    /**
     * Вычисляет общий секрет ECDH: X25519(privateKey, peerPublicKey).
     */
    fun computeSharedSecret(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        val privParams = X25519PrivateKeyParameters(privateKey, 0)
        val pubParams = X25519PublicKeyParameters(peerPublicKey, 0)

        val agreement = X25519Agreement()
        agreement.init(privParams)

        val sharedSecret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pubParams, sharedSecret, 0)

        return sharedSecret
    }

    /**
     * Выводит сессионные ключи (SendKey, RecvKey, HMACKey) из общего секрета.
     * HKDF-SHA256(sharedSecret, salt=PSK, info="novavpn-session-keys-v1")
     *
     * Клиент swaps send/recv: RecvKey ← key1, SendKey ← key2.
     */
    fun deriveSessionKeys(sharedSecret: ByteArray, salt: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val info = SESSION_KEYS_INFO.toByteArray(Charsets.UTF_8)
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(sharedSecret, salt, info))

        val output = ByteArray(KEY_SIZE * 3) // 96 байт
        hkdf.generateBytes(output, 0, output.size)

        val key1 = output.copyOfRange(0, KEY_SIZE)            // Сервер: SendKey
        val key2 = output.copyOfRange(KEY_SIZE, KEY_SIZE * 2)  // Сервер: RecvKey
        val key3 = output.copyOfRange(KEY_SIZE * 2, KEY_SIZE * 3) // HMACKey

        // Клиент: swap send/recv (сервер использует key1 для send → клиент для recv)
        val sendKey = key2 // клиент отправляет = сервер получает
        val recvKey = key1 // клиент получает = сервер отправляет
        val hmacKey = key3

        return Triple(sendKey, recvKey, hmacKey)
    }

    /**
     * Декодирует PSK из hex-строки.
     */
    fun decodePsk(hexKey: String): ByteArray {
        require(hexKey.length == 64) { "Invalid PSK length: ${hexKey.length} (expected 64 hex chars)" }
        return hexKey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    /**
     * Кодирует PSK в hex-строку.
     */
    fun encodePsk(psk: ByteArray): String {
        return psk.joinToString("") { "%02x".format(it) }
    }
}
