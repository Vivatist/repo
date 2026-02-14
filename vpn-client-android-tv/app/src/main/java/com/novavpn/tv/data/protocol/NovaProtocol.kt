package com.novavpn.tv.data.protocol

import java.nio.ByteBuffer

/**
 * Протокол NovaVPN v2 — маскировка под TLS 1.2.
 *
 * Формат пакетов:
 * - TLS Header (5 байт): [0x17, 0x03, 0x03, length_hi, length_lo]
 * - SessionID (4 байта, big-endian)
 * - Type (1 байт)
 * - Nonce/Counter + Payload (зависит от типа)
 */
object NovaProtocol {

    const val PROTOCOL_VERSION: Byte = 0x02

    // TLS Record Header
    const val TLS_CONTENT_TYPE: Byte = 0x17
    const val TLS_VERSION_MAJOR: Byte = 0x03
    const val TLS_VERSION_MINOR: Byte = 0x03
    const val TLS_HEADER_SIZE = 5

    // Размеры полей
    const val SESSION_ID_SIZE = 4
    const val NONCE_SIZE = 12
    const val AUTH_TAG_SIZE = 16
    const val COUNTER_SIZE = 4
    const val PACKET_TYPE_SIZE = 1
    const val KEY_SIZE = 32

    // Оверхеды
    const val DATA_OVERHEAD = TLS_HEADER_SIZE + SESSION_ID_SIZE + PACKET_TYPE_SIZE + COUNTER_SIZE // 14
    const val MIN_PACKET_SIZE = TLS_HEADER_SIZE + SESSION_ID_SIZE + PACKET_TYPE_SIZE // 10

    // Типы пакетов
    const val PACKET_HANDSHAKE_INIT: Byte = 0x01
    const val PACKET_HANDSHAKE_RESP: Byte = 0x02
    const val PACKET_HANDSHAKE_COMPLETE: Byte = 0x03
    const val PACKET_DATA: Byte = 0x10
    const val PACKET_KEEPALIVE: Byte = 0x20
    const val PACKET_DISCONNECT: Byte = 0x30
    @Suppress("unused")
    const val PACKET_ERROR: Byte = 0xF0.toByte()

    /**
     * Оборачивает данные в TLS 1.2 Application Data заголовок.
     */
    fun addTlsHeader(data: ByteArray): ByteArray {
        val result = ByteArray(TLS_HEADER_SIZE + data.size)
        result[0] = TLS_CONTENT_TYPE
        result[1] = TLS_VERSION_MAJOR
        result[2] = TLS_VERSION_MINOR
        val len = data.size
        result[3] = ((len shr 8) and 0xFF).toByte()
        result[4] = (len and 0xFF).toByte()
        System.arraycopy(data, 0, result, TLS_HEADER_SIZE, data.size)
        return result
    }

    /**
     * Извлекает payload из TLS-обёртки.
     */
    fun parseTlsHeader(data: ByteArray): ByteArray? {
        if (data.size < TLS_HEADER_SIZE) return null
        if (data[0] != TLS_CONTENT_TYPE) return null
        val length = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        if (data.size < TLS_HEADER_SIZE + length) return null
        return data.copyOfRange(TLS_HEADER_SIZE, TLS_HEADER_SIZE + length)
    }

    /**
     * Формирует handshake пакет: SessionID(4) + Type(1) + Nonce(12) + Payload.
     */
    fun marshalHandshakePacket(
        packetType: Byte,
        sessionId: Long,
        nonce: ByteArray,
        payload: ByteArray
    ): ByteArray {
        val raw = ByteArray(SESSION_ID_SIZE + PACKET_TYPE_SIZE + NONCE_SIZE + payload.size)
        val buf = ByteBuffer.wrap(raw)
        buf.putInt(sessionId.toInt())
        buf.put(packetType)
        buf.put(nonce, 0, NONCE_SIZE.coerceAtMost(nonce.size))
        buf.put(payload)
        return addTlsHeader(raw)
    }

    /**
     * Формирует Keepalive/Disconnect пакет (10 байт).
     */
    fun marshalSimplePacket(packetType: Byte, sessionId: Long): ByteArray {
        val raw = ByteArray(SESSION_ID_SIZE + PACKET_TYPE_SIZE)
        val buf = ByteBuffer.wrap(raw)
        buf.putInt(sessionId.toInt())
        buf.put(packetType)
        return addTlsHeader(raw)
    }

    /**
     * Формирует Data-пакет: SessionID(4) + Type(1) + Counter(4) + Ciphertext.
     */
    fun marshalDataPacket(
        sessionId: Long,
        counter: Int,
        ciphertext: ByteArray
    ): ByteArray {
        val raw = ByteArray(SESSION_ID_SIZE + PACKET_TYPE_SIZE + COUNTER_SIZE + ciphertext.size)
        val buf = ByteBuffer.wrap(raw)
        buf.putInt(sessionId.toInt())
        buf.put(PACKET_DATA)
        buf.putInt(counter)
        buf.put(ciphertext)
        return addTlsHeader(raw)
    }

    /**
     * Формирует HandshakeInit payload.
     *
     * pubkey(32) + timestamp(8) + credsLen(2) + encCreds(variable) + hmac(32)
     */
    fun marshalHandshakeInit(
        clientPublicKey: ByteArray,
        timestamp: Long,
        encryptedCredentials: ByteArray,
        hmac: ByteArray
    ): ByteArray {
        val totalLen = 32 + 8 + 2 + encryptedCredentials.size + 32
        val buf = ByteBuffer.allocate(totalLen)
        buf.put(clientPublicKey, 0, 32)
        buf.putLong(timestamp)
        buf.putShort(encryptedCredentials.size.toShort())
        buf.put(encryptedCredentials)
        buf.put(hmac, 0, 32)
        return buf.array()
    }

    /**
     * Формирует credentials: emailLen(2) + email + passLen(2) + password.
     */
    fun marshalCredentials(email: String, password: String): ByteArray {
        val emailBytes = email.toByteArray(Charsets.UTF_8)
        val passBytes = password.toByteArray(Charsets.UTF_8)
        val buf = ByteBuffer.allocate(2 + emailBytes.size + 2 + passBytes.size)
        buf.putShort(emailBytes.size.toShort())
        buf.put(emailBytes)
        buf.putShort(passBytes.size.toShort())
        buf.put(passBytes)
        return buf.array()
    }

    /**
     * Формирует HandshakeComplete payload.
     */
    fun marshalHandshakeComplete(confirmHmac: ByteArray): ByteArray {
        val buf = ByteArray(32)
        System.arraycopy(confirmHmac, 0, buf, 0, 32.coerceAtMost(confirmHmac.size))
        return buf
    }

    /**
     * Парсит входящий пакет.
     * Возвращает ParsedPacket или null при ошибке.
     */
    fun parseIncoming(data: ByteArray, length: Int): ParsedPacket? {
        if (length < MIN_PACKET_SIZE) return null

        val raw: ByteArray
        val rawLen: Int

        // Проверяем TLS-обёртку
        if (data[0] == TLS_CONTENT_TYPE) {
            if (length < TLS_HEADER_SIZE) return null
            val payloadLen = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
            if (length < TLS_HEADER_SIZE + payloadLen) return null
            raw = data.copyOfRange(TLS_HEADER_SIZE, TLS_HEADER_SIZE + payloadLen)
            rawLen = payloadLen
        } else {
            raw = data.copyOfRange(0, length)
            rawLen = length
        }

        if (rawLen < SESSION_ID_SIZE + PACKET_TYPE_SIZE) return null

        val buf = ByteBuffer.wrap(raw)
        val sessionId = buf.int.toLong() and 0xFFFFFFFFL
        val packetType = buf.get()

        return when (packetType) {
            PACKET_DATA -> {
                if (rawLen < SESSION_ID_SIZE + PACKET_TYPE_SIZE + COUNTER_SIZE) return null
                val counter = buf.int
                val ciphertext = ByteArray(rawLen - SESSION_ID_SIZE - PACKET_TYPE_SIZE - COUNTER_SIZE)
                buf.get(ciphertext)
                ParsedPacket(sessionId, packetType, counter = counter, payload = ciphertext)
            }
            PACKET_HANDSHAKE_RESP -> {
                // SessionID(4) + Type(1) + Nonce(12) + EncPayload
                if (rawLen < SESSION_ID_SIZE + PACKET_TYPE_SIZE + NONCE_SIZE) return null
                val nonce = ByteArray(NONCE_SIZE)
                buf.get(nonce)
                val payload = ByteArray(rawLen - SESSION_ID_SIZE - PACKET_TYPE_SIZE - NONCE_SIZE)
                buf.get(payload)
                ParsedPacket(sessionId, packetType, nonce = nonce, payload = payload)
            }
            PACKET_KEEPALIVE, PACKET_DISCONNECT -> {
                ParsedPacket(sessionId, packetType)
            }
            PACKET_ERROR -> {
                val payload = if (rawLen > SESSION_ID_SIZE + PACKET_TYPE_SIZE) {
                    ByteArray(rawLen - SESSION_ID_SIZE - PACKET_TYPE_SIZE).also { buf.get(it) }
                } else null
                ParsedPacket(sessionId, packetType, payload = payload)
            }
            else -> null
        }
    }

    /**
     * Парсит HandshakeResp (расшифрованный payload).
     *
     * ServerPublicKey(32) + SessionID(4) + IP(4) + Mask(1) +
     * DNS1(4) + DNS2(4) + MTU(2) + ServerHMAC(32) + HasPSK(1) [+ PSK(32)]
     */
    fun parseHandshakeResp(data: ByteArray): HandshakeRespData? {
        if (data.size < 84) return null
        val buf = ByteBuffer.wrap(data)

        val sessionId = buf.getInt(32).toLong() and 0xFFFFFFFFL
        val ip = ByteArray(4)
        System.arraycopy(data, 36, ip, 0, 4)
        val mask = data[40].toInt() and 0xFF
        val dns1 = ByteArray(4)
        System.arraycopy(data, 41, dns1, 0, 4)
        val dns2 = ByteArray(4)
        System.arraycopy(data, 45, dns2, 0, 4)
        val mtu = ((data[49].toInt() and 0xFF) shl 8) or (data[50].toInt() and 0xFF)

        val serverHmac = ByteArray(32)
        System.arraycopy(data, 51, serverHmac, 0, 32)

        var psk: ByteArray? = null
        if (data[83].toInt() == 1 && data.size >= 116) {
            psk = ByteArray(32)
            System.arraycopy(data, 84, psk, 0, 32)
        }

        return HandshakeRespData(
            sessionId = sessionId,
            assignedIp = ip,
            subnetMask = mask,
            dns1 = dns1,
            dns2 = dns2,
            mtu = mtu,
            serverHmac = serverHmac,
            psk = psk
        )
    }
}

/**
 * Разобранный входящий пакет.
 */
data class ParsedPacket(
    val sessionId: Long,
    val type: Byte,
    val counter: Int = 0,
    val nonce: ByteArray? = null,
    val payload: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ParsedPacket) return false
        return sessionId == other.sessionId && type == other.type
    }

    override fun hashCode(): Int = (sessionId xor type.toLong()).toInt()
}

/**
 * Данные из HandshakeResp (после расшифровки).
 */
data class HandshakeRespData(
    val sessionId: Long,
    val assignedIp: ByteArray,
    val subnetMask: Int,
    val dns1: ByteArray,
    val dns2: ByteArray,
    val mtu: Int,
    val serverHmac: ByteArray,
    val psk: ByteArray?
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HandshakeRespData) return false
        return sessionId == other.sessionId
    }

    override fun hashCode(): Int = sessionId.hashCode()
}
