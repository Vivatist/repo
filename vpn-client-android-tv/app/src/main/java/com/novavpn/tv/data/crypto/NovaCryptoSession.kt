package com.novavpn.tv.data.crypto

import com.novavpn.tv.data.protocol.NovaProtocol
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.digests.SHA256Digest
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Криптографическая сессия NovaVPN.
 *
 * Реализует:
 * - ChaCha20-Poly1305 AEAD (для handshake)
 * - Plain ChaCha20 XOR (для data-пакетов)
 * - HMAC-SHA256 (для аутентификации)
 * - Counter-based nonce (prefix(4) + counter(8) = 12 байт)
 */
class NovaCryptoSession(
    val sendKey: ByteArray,
    val recvKey: ByteArray,
    val hmacKey: ByteArray
) {
    private val sendNoncePrefix: ByteArray = deriveNoncePrefix(sendKey)
    private val recvNoncePrefix: ByteArray = deriveNoncePrefix(recvKey)
    private val sendCounter = AtomicLong(0)
    private val random = SecureRandom()

    /**
     * Шифрует данные ChaCha20-Poly1305 AEAD.
     * Возвращает: nonce(12) + ciphertext + tag(16).
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val counter = sendCounter.incrementAndGet()
        val nonce = buildNonce(sendNoncePrefix, counter)

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(sendKey, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        val ciphertext = cipher.doFinal(plaintext)

        // Результат: nonce(12) + ciphertext+tag
        val result = ByteArray(NovaProtocol.NONCE_SIZE + ciphertext.size)
        System.arraycopy(nonce, 0, result, 0, NovaProtocol.NONCE_SIZE)
        System.arraycopy(ciphertext, 0, result, NovaProtocol.NONCE_SIZE, ciphertext.size)
        return result
    }

    /**
     * Дешифрует данные ChaCha20-Poly1305 AEAD.
     * Входные данные: nonce(12) + ciphertext + tag(16).
     */
    fun decrypt(data: ByteArray): ByteArray {
        if (data.size < NovaProtocol.NONCE_SIZE + NovaProtocol.AUTH_TAG_SIZE) {
            throw IllegalArgumentException("Ciphertext too short: ${data.size}")
        }

        val nonce = data.copyOfRange(0, NovaProtocol.NONCE_SIZE)
        val ciphertext = data.copyOfRange(NovaProtocol.NONCE_SIZE, data.size)

        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(recvKey, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(ciphertext)
    }

    /**
     * Дешифрует с явным nonce (для handshake-пакетов).
     */
    fun decryptWithNonce(nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(recvKey, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(ciphertext)
    }

    /**
     * Шифрует IP-пакет plain ChaCha20 XOR (без Poly1305).
     * Записывает: counter(4) + ciphertext.
     * Возвращает количество записанных байт.
     */
    fun encryptData(dst: ByteArray, plaintext: ByteArray, offset: Int, length: Int): Int {
        val counter = sendCounter.incrementAndGet()
        val wireCtr = counter.toInt()
        val nonce = buildNonce(sendNoncePrefix, wireCtr.toLong() and 0xFFFFFFFFL)

        // Записываем counter (4 байта)
        ByteBuffer.wrap(dst, 0, 4).putInt(wireCtr)

        // Plain ChaCha20 XOR
        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(sendKey), nonce))
        engine.processBytes(plaintext, offset, length, dst, 4)

        return 4 + length
    }

    /**
     * Дешифрует data-пакет (plain ChaCha20 XOR).
     */
    fun decryptData(counter: Int, ciphertext: ByteArray): ByteArray {
        val nonce = buildNonce(recvNoncePrefix, counter.toLong() and 0xFFFFFFFFL)

        val plaintext = ByteArray(ciphertext.size)
        val engine = ChaCha7539Engine()
        engine.init(false, ParametersWithIV(KeyParameter(recvKey), nonce))
        engine.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)

        return plaintext
    }

    /**
     * Вычисляет HMAC-SHA256.
     */
    fun computeHmac(data: ByteArray): ByteArray {
        val hmac = HMac(SHA256Digest())
        hmac.init(KeyParameter(hmacKey))
        hmac.update(data, 0, data.size)
        val result = ByteArray(hmac.macSize)
        hmac.doFinal(result, 0)
        return result
    }

    /**
     * Проверяет HMAC-SHA256.
     */
    fun verifyHmac(data: ByteArray, expectedHmac: ByteArray): Boolean {
        val computed = computeHmac(data)
        return computed.contentEquals(expectedHmac)
    }

    /** Возвращает текущее значение счётчика. */
    fun getSendCounter(): Long = sendCounter.get()

    /** Устанавливает значение счётчика (для 0-RTT resume). */
    fun setSendCounter(value: Long) = sendCounter.set(value)

    /** Очищает ключи из памяти. */
    fun close() {
        sendKey.fill(0)
        recvKey.fill(0)
        hmacKey.fill(0)
    }

    companion object {
        /**
         * Выводит 4-байтный nonce prefix из ключа.
         * HMAC-SHA256(key, "nova-nonce-prefix")[:4]
         */
        fun deriveNoncePrefix(key: ByteArray): ByteArray {
            val hmac = HMac(SHA256Digest())
            hmac.init(KeyParameter(key))
            val info = "nova-nonce-prefix".toByteArray(Charsets.UTF_8)
            hmac.update(info, 0, info.size)
            val result = ByteArray(hmac.macSize)
            hmac.doFinal(result, 0)
            return result.copyOfRange(0, 4)
        }

        /**
         * Строит 12-байтный nonce: prefix(4) + counter(8, big-endian).
         */
        fun buildNonce(prefix: ByteArray, counter: Long): ByteArray {
            val nonce = ByteArray(12)
            System.arraycopy(prefix, 0, nonce, 0, 4)
            ByteBuffer.wrap(nonce, 4, 8).putLong(counter)
            return nonce
        }

        /**
         * Вычисляет HMAC-SHA256 с произвольным ключом.
         */
        fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val hmac = HMac(SHA256Digest())
            hmac.init(KeyParameter(key))
            hmac.update(data, 0, data.size)
            val result = ByteArray(hmac.macSize)
            hmac.doFinal(result, 0)
            return result
        }
    }
}
