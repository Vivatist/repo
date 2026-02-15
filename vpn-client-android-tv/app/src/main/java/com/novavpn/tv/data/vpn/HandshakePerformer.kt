package com.novavpn.tv.data.vpn

import android.util.Log
import com.novavpn.tv.data.crypto.NovaCryptoSession
import com.novavpn.tv.data.crypto.NovaKeyExchange
import com.novavpn.tv.data.protocol.NovaProtocol
import com.novavpn.tv.domain.model.HandshakeResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Выполняет рукопожатие с VPN-сервером по протоколу NovaVPN v3.
 *
 * Этапы:
 * 1. Генерация ephemeral Curve25519 ключевой пары
 * 2. Отправка HandshakeInit (credentials + HMAC + padding)
 * 3. Получение HandshakeResp (SessionID, IP, DNS, MTU, PSK)
 * 4. Отправка HandshakeComplete (fire-and-forget, 1-RTT)
 *
 * Все пакеты обёрнуты в QUIC Short Header и обфусцированы XOR-маской из PSK.
 */
class HandshakePerformer(
    private val socket: DatagramSocket,
    private val psk: ByteArray,
    private val email: String,
    private val password: String
) {
    companion object {
        private const val TAG = "NovaHandshake"
    }

    // Маска обфускации заголовка, производная от PSK
    private val headerMask: ByteArray = NovaCryptoSession.deriveHeaderMask(psk)
    private val random = SecureRandom()

    /**
     * Выполняет полное рукопожатие. Возвращает HandshakeResult.
     * @param timeoutMs таймаут ожидания ответа в миллисекундах.
     */
    fun perform(timeoutMs: Int): HandshakeResult {
        // 1. Генерируем ephemeral ключевую пару
        val (clientPrivKey, clientPubKey) = NovaKeyExchange.generateKeyPair()

        try {
            // 2. Отправляем HandshakeInit
            sendHandshakeInit(clientPubKey)

            // 3. Получаем HandshakeResp
            val oldTimeout = socket.soTimeout
            socket.soTimeout = timeoutMs
            val result = receiveHandshakeResp(clientPrivKey)
            socket.soTimeout = oldTimeout

            // 4. Отправляем HandshakeComplete (fire-and-forget)
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    sendHandshakeComplete(result)
                } catch (e: Exception) {
                    Log.w(TAG, "HandshakeComplete error (non-critical): ${e.message}")
                }
            }

            Log.i(TAG, "Handshake completed (1-RTT)")
            return result
        } finally {
            clientPrivKey.fill(0) // очистка приватного ключа
        }
    }

    private fun sendHandshakeInit(clientPubKey: ByteArray) {
        // Шифруем credentials PSK-ключом
        val credsPlaintext = NovaProtocol.marshalCredentials(email, password)

        // Временная сессия для шифрования
        val pskCopy = psk.copyOf()
        val tempSession = NovaCryptoSession(pskCopy.copyOf(), pskCopy.copyOf(), pskCopy.copyOf())
        try {
            val encCreds = tempSession.encrypt(credsPlaintext)

            // Формируем HandshakeInit
            val timestamp = System.currentTimeMillis() / 1000

            // HMAC = HMAC-SHA256(PSK, clientPubKey + timestamp + encryptedCredentials)
            val hmacData = ByteArray(32 + 8 + encCreds.size)
            System.arraycopy(clientPubKey, 0, hmacData, 0, 32)
            ByteBuffer.wrap(hmacData, 32, 8).putLong(timestamp)
            System.arraycopy(encCreds, 0, hmacData, 40, encCreds.size)
            val hmac = NovaCryptoSession.hmacSha256(psk, hmacData)

            val initPayload = NovaProtocol.marshalHandshakeInit(
                clientPubKey, timestamp, encCreds, hmac
            )

            // Добавляем random padding 100-400 байт (маскировка размера handshake)
            val padLen = NovaProtocol.randomPadLen(NovaProtocol.HANDSHAKE_PAD_MIN, NovaProtocol.HANDSHAKE_PAD_MAX)
            val paddedPayload = ByteArray(initPayload.size + padLen)
            System.arraycopy(initPayload, 0, paddedPayload, 0, initPayload.size)
            val padding = ByteArray(padLen)
            random.nextBytes(padding)
            System.arraycopy(padding, 0, paddedPayload, initPayload.size, padLen)

            val emptyNonce = ByteArray(NovaProtocol.NONCE_SIZE)
            val packet = NovaProtocol.marshalHandshakePacket(
                NovaProtocol.PACKET_HANDSHAKE_INIT, 0, emptyNonce, paddedPayload
            )

            // Обфускация заголовка (после QUIC header)
            NovaProtocol.obfuscateHeader(packet, NovaProtocol.QUIC_HEADER_SIZE, headerMask, false)

            socket.send(DatagramPacket(packet, packet.size))
            Log.i(TAG, "Sent HandshakeInit (${packet.size} bytes, padding $padLen)")
        } finally {
            tempSession.close()
        }
    }

    private fun receiveHandshakeResp(clientPrivKey: ByteArray): HandshakeResult {
        val buf = ByteArray(4096)
        val datagram = DatagramPacket(buf, buf.size)
        socket.receive(datagram)

        val parsed = NovaProtocol.parseIncoming(buf, datagram.length, headerMask)
            ?: throw Exception("Failed to parse HandshakeResp")

        if (parsed.type != NovaProtocol.PACKET_HANDSHAKE_RESP) {
            throw Exception("Expected HandshakeResp, got 0x${"%02x".format(parsed.type)}")
        }

        // Извлекаем ServerPublicKey (первые 32 байта payload)
        val payload = parsed.payload ?: throw Exception("Empty HandshakeResp payload")
        if (payload.size < 32) throw Exception("HandshakeResp payload too short")

        val serverPubKey = payload.copyOfRange(0, 32)

        // ECDH: вычисляем shared secret
        val sharedSecret = NovaKeyExchange.computeSharedSecret(clientPrivKey, serverPubKey)
        try {
            // Выводим ключи сессии
            val (sendKey, recvKey, hmacKey) = NovaKeyExchange.deriveSessionKeys(sharedSecret, psk)

            // Дешифровка ответа
            val session = NovaCryptoSession(sendKey, recvKey, hmacKey)
            val encryptedResp = payload.copyOfRange(32, payload.size)

            // nonce из заголовка пакета + encrypted payload
            val nonce = parsed.nonce ?: throw Exception("No nonce in HandshakeResp")
            val respPlaintext = session.decryptWithNonce(nonce, encryptedResp)

            val respData = NovaProtocol.parseHandshakeResp(respPlaintext)
                ?: throw Exception("Failed to parse HandshakeResp data")

            Log.i(TAG, "SessionID=${respData.sessionId}, IP=${ipToString(respData.assignedIp)}, MTU=${respData.mtu}")

            return HandshakeResult(
                sessionId = respData.sessionId,
                sendKey = sendKey,
                recvKey = recvKey,
                hmacKey = hmacKey,
                assignedIp = respData.assignedIp,
                subnetMask = respData.subnetMask,
                dns1 = respData.dns1,
                dns2 = respData.dns2,
                mtu = respData.mtu,
                newPsk = respData.psk
            )
        } finally {
            sharedSecret.fill(0)
        }
    }

    private fun sendHandshakeComplete(result: HandshakeResult) {
        val session = NovaCryptoSession(
            result.sendKey.copyOf(),
            result.recvKey.copyOf(),
            result.hmacKey.copyOf()
        )

        val confirmData = "novavpn-confirm-${result.sessionId}".toByteArray(Charsets.UTF_8)
        val confirmHmac = session.computeHmac(confirmData)

        val completePayload = NovaProtocol.marshalHandshakeComplete(confirmHmac)

        // Добавляем random padding 100-400 байт перед шифрованием
        val padLen = NovaProtocol.randomPadLen(NovaProtocol.HANDSHAKE_PAD_MIN, NovaProtocol.HANDSHAKE_PAD_MAX)
        val paddedPayload = ByteArray(completePayload.size + padLen)
        System.arraycopy(completePayload, 0, paddedPayload, 0, completePayload.size)
        val padding = ByteArray(padLen)
        random.nextBytes(padding)
        System.arraycopy(padding, 0, paddedPayload, completePayload.size, padLen)

        val encrypted = session.encrypt(paddedPayload)

        val nonce = encrypted.copyOfRange(0, NovaProtocol.NONCE_SIZE)
        val ciphertext = encrypted.copyOfRange(NovaProtocol.NONCE_SIZE, encrypted.size)

        val packet = NovaProtocol.marshalHandshakePacket(
            NovaProtocol.PACKET_HANDSHAKE_COMPLETE,
            result.sessionId,
            nonce,
            ciphertext
        )

        // Обфускация заголовка — используем маску из PSK выведенного для новой сессии
        // Но HandshakeComplete использует ту же маску что и Init (PSK не менялся на этом этапе)
        NovaProtocol.obfuscateHeader(packet, NovaProtocol.QUIC_HEADER_SIZE, headerMask, false)

        socket.send(DatagramPacket(packet, packet.size))
        Log.i(TAG, "Sent HandshakeComplete (${packet.size} bytes)")
    }

    private fun ipToString(ip: ByteArray): String {
        return ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }
}
