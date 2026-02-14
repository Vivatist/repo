package com.novavpn.tv.data.vpn

import android.util.Log
import com.novavpn.tv.data.crypto.NovaCryptoSession
import com.novavpn.tv.data.crypto.NovaKeyExchange
import com.novavpn.tv.data.protocol.NovaProtocol
import com.novavpn.tv.domain.model.HandshakeResult
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.nio.ByteBuffer

/**
 * Выполняет рукопожатие с VPN-сервером по протоколу NovaVPN v2.
 *
 * Этапы:
 * 1. Генерация ephemeral Curve25519 ключевой пары
 * 2. Отправка HandshakeInit (credentials + HMAC)
 * 3. Получение HandshakeResp (SessionID, IP, DNS, MTU, PSK)
 * 4. Отправка HandshakeComplete (fire-and-forget, 1-RTT)
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
            Thread {
                try {
                    sendHandshakeComplete(result)
                } catch (e: Exception) {
                    Log.w(TAG, "HandshakeComplete error (non-critical): ${e.message}")
                }
            }.start()

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

            val emptyNonce = ByteArray(NovaProtocol.NONCE_SIZE)
            val packet = NovaProtocol.marshalHandshakePacket(
                NovaProtocol.PACKET_HANDSHAKE_INIT, 0, emptyNonce, initPayload
            )

            socket.send(DatagramPacket(packet, packet.size))
            Log.i(TAG, "Sent HandshakeInit")
        } finally {
            tempSession.close()
        }
    }

    private fun receiveHandshakeResp(clientPrivKey: ByteArray): HandshakeResult {
        val buf = ByteArray(4096)
        val datagram = DatagramPacket(buf, buf.size)
        socket.receive(datagram)

        val parsed = NovaProtocol.parseIncoming(buf, datagram.length)
            ?: throw Exception("Failed to parse HandshakeResp")

        if (parsed.type == NovaProtocol.PACKET_ERROR) {
            throw Exception("Server rejected connection (invalid credentials)")
        }

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
        val encrypted = session.encrypt(completePayload)

        val nonce = encrypted.copyOfRange(0, NovaProtocol.NONCE_SIZE)
        val ciphertext = encrypted.copyOfRange(NovaProtocol.NONCE_SIZE, encrypted.size)

        val packet = NovaProtocol.marshalHandshakePacket(
            NovaProtocol.PACKET_HANDSHAKE_COMPLETE,
            result.sessionId,
            nonce,
            ciphertext
        )

        socket.send(DatagramPacket(packet, packet.size))
        Log.i(TAG, "Sent HandshakeComplete")
    }

    private fun ipToString(ip: ByteArray): String {
        return ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }
}
