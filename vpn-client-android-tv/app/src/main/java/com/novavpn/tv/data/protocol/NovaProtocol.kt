package com.novavpn.tv.data.protocol

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Протокол NovaVPN v3 — маскировка под QUIC Short Header.
 *
 * Формат пакетов:
 * - QUIC Short Header (5 байт): Flags(1) + Random(4)
 * - SessionID (4 байта, big-endian) — обфусцирован XOR-маской из PSK
 * - Type (1 байт) — обфусцирован XOR-маской из PSK
 * - Nonce/Counter + Payload (зависит от типа)
 *
 * Все поля после QUIC Header обфусцированы XOR-маской, производной от PSK.
 */
object NovaProtocol {

    const val PROTOCOL_VERSION: Byte = 0x03

    // QUIC Short Header constants (маскировка под QUIC)
    // Flags byte: Header Form=0 (Short), Fixed Bit=1, остальное — random
    const val QUIC_FIXED_BIT_MASK: Byte = 0x40 // bit 6 = 1 (QUIC Fixed Bit, обязателен)
    const val QUIC_HEADER_SIZE = 5              // flags(1) + random_pad(4)

    // Обратная совместимость имён
    const val TLS_HEADER_SIZE = QUIC_HEADER_SIZE

    // Размеры полей
    const val SESSION_ID_SIZE = 4
    const val NONCE_SIZE = 12
    const val AUTH_TAG_SIZE = 16
    const val COUNTER_SIZE = 4
    const val PACKET_TYPE_SIZE = 1
    const val KEY_SIZE = 32
    const val HEADER_MASK_SIZE = 9 // SID(4) + Type(1) + Counter(4)

    // Оверхеды
    const val DATA_OVERHEAD = QUIC_HEADER_SIZE + SESSION_ID_SIZE + PACKET_TYPE_SIZE + COUNTER_SIZE // 14
    const val MIN_PACKET_SIZE = QUIC_HEADER_SIZE + SESSION_ID_SIZE + PACKET_TYPE_SIZE // 10

    // Padding constants (Этап 2 маскировки)
    const val KEEPALIVE_PAD_MIN = 40
    const val KEEPALIVE_PAD_MAX = 150
    const val DATA_PAD_ALIGN = 64
    const val DATA_PAD_RANDOM_MAX = 32
    const val HANDSHAKE_PAD_MIN = 100
    const val HANDSHAKE_PAD_MAX = 400

    // Типы пакетов
    const val PACKET_HANDSHAKE_INIT: Byte = 0x01
    const val PACKET_HANDSHAKE_RESP: Byte = 0x02
    const val PACKET_HANDSHAKE_COMPLETE: Byte = 0x03
    const val PACKET_DATA: Byte = 0x10
    const val PACKET_KEEPALIVE: Byte = 0x20
    const val PACKET_DISCONNECT: Byte = 0x30

    private val random = SecureRandom()

    /**
     * Записывает QUIC Short Header (5 байт) в начало buf.
     * Flags byte: 0x40 | random_6bits.
     * Bytes 1-4: случайные (обфусцированная DCID-подобная область).
     */
    fun writeQUICHeader(buf: ByteArray, offset: Int = 0) {
        val rnd = ByteArray(5)
        random.nextBytes(rnd)
        buf[offset] = (QUIC_FIXED_BIT_MASK.toInt() or (rnd[0].toInt() and 0x3F)).toByte()
        buf[offset + 1] = rnd[1]
        buf[offset + 2] = rnd[2]
        buf[offset + 3] = rnd[3]
        buf[offset + 4] = rnd[4]
    }

    /**
     * Добавляет QUIC Short Header (5 байт) к данным.
     */
    fun addQUICHeader(data: ByteArray): ByteArray {
        val result = ByteArray(QUIC_HEADER_SIZE + data.size)
        writeQUICHeader(result)
        System.arraycopy(data, 0, result, QUIC_HEADER_SIZE, data.size)
        return result
    }

    /**
     * Пропускает QUIC Short Header (5 байт).
     * Не проверяет содержимое заголовка (валидация через header mask).
     */
    fun skipHeader(data: ByteArray, length: Int): ByteArray? {
        if (length < QUIC_HEADER_SIZE) return null
        return data.copyOfRange(QUIC_HEADER_SIZE, length)
    }

    /**
     * Применяет XOR-обфускацию к заголовку пакета (после QUIC header).
     * buf начинается ПОСЛЕ QUIC header: [0:4]=SessionID, [4]=Type, [5:9]=Counter.
     * isData=true — обфускация Counter (9 байт), иначе только SID+Type (5 байт).
     */
    fun obfuscateHeader(buf: ByteArray, offset: Int, mask: ByteArray, isData: Boolean) {
        buf[offset] = (buf[offset].toInt() xor mask[0].toInt()).toByte()
        buf[offset + 1] = (buf[offset + 1].toInt() xor mask[1].toInt()).toByte()
        buf[offset + 2] = (buf[offset + 2].toInt() xor mask[2].toInt()).toByte()
        buf[offset + 3] = (buf[offset + 3].toInt() xor mask[3].toInt()).toByte()
        buf[offset + 4] = (buf[offset + 4].toInt() xor mask[4].toInt()).toByte()
        if (isData && buf.size - offset >= 9) {
            buf[offset + 5] = (buf[offset + 5].toInt() xor mask[5].toInt()).toByte()
            buf[offset + 6] = (buf[offset + 6].toInt() xor mask[6].toInt()).toByte()
            buf[offset + 7] = (buf[offset + 7].toInt() xor mask[7].toInt()).toByte()
            buf[offset + 8] = (buf[offset + 8].toInt() xor mask[8].toInt()).toByte()
        }
    }

    /**
     * Возвращает случайную длину padding в диапазоне [min, max].
     */
    fun randomPadLen(min: Int, max: Int): Int {
        if (max <= min) return min
        return min + random.nextInt(max - min + 1)
    }

    /**
     * Вычисляет длину padding для data-пакета.
     * Выравнивает до DATA_PAD_ALIGN + random(0, DATA_PAD_RANDOM_MAX).
     */
    fun computeDataPadLen(plaintextLen: Int): Int {
        val minPadded = plaintextLen + 1
        val alignedTarget = ((minPadded + DATA_PAD_ALIGN - 1) / DATA_PAD_ALIGN) * DATA_PAD_ALIGN
        var padLen = alignedTarget - minPadded

        padLen += random.nextInt(DATA_PAD_RANDOM_MAX + 1)

        if (padLen > 255) padLen = 255
        return padLen
    }

    /**
     * Формирует handshake пакет: SessionID(4) + Type(1) + Nonce(12) + Payload.
     * Обёрнут в QUIC Short Header.
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
        return addQUICHeader(raw)
    }

    /**
     * Формирует Keepalive/Disconnect пакет с random padding.
     * Формат: QUIC(5) + SID(4) + Type(1) + RandomPad(40-150).
     */
    fun marshalSimplePacket(packetType: Byte, sessionId: Long): ByteArray {
        val padLen = randomPadLen(KEEPALIVE_PAD_MIN, KEEPALIVE_PAD_MAX)
        val raw = ByteArray(SESSION_ID_SIZE + PACKET_TYPE_SIZE + padLen)
        val buf = ByteBuffer.wrap(raw)
        buf.putInt(sessionId.toInt())
        buf.put(packetType)
        // Заполняем padding случайными байтами
        val padding = ByteArray(padLen)
        random.nextBytes(padding)
        buf.put(padding)
        return addQUICHeader(raw)
    }

    /**
     * Формирует Data-пакет: SessionID(4) + Type(1) + Counter(4) + Ciphertext.
     * Обёрнут в QUIC Short Header.
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
        return addQUICHeader(raw)
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
     * Пропускает QUIC Short Header, деобфусцирует заголовок.
     * Возвращает ParsedPacket или null при ошибке.
     */
    fun parseIncoming(data: ByteArray, length: Int, headerMask: ByteArray): ParsedPacket? {
        if (length < MIN_PACKET_SIZE) return null

        // Пропускаем QUIC Short Header (5 байт)
        val raw = skipHeader(data, length) ?: return null
        val rawLen = raw.size

        if (rawLen < SESSION_ID_SIZE + PACKET_TYPE_SIZE) return null

        // Деобфускация заголовка: сначала только SID(4) + Type(1) = 5 байт.
        // Counter (ещё 4 байта) деобфусцируем ТОЛЬКО для data-пакетов (как Windows-клиент).
        val deobf = raw.copyOf()
        obfuscateHeader(deobf, 0, headerMask, false) // только SID + Type

        val buf = ByteBuffer.wrap(deobf)
        val sessionId = buf.int.toLong() and 0xFFFFFFFFL
        val packetType = buf.get()

        return when (packetType) {
            PACKET_DATA -> {
                if (rawLen < SESSION_ID_SIZE + PACKET_TYPE_SIZE + COUNTER_SIZE) return null
                // Деобфускация Counter для data-пакетов (ещё 4 байта)
                deobf[5] = (deobf[5].toInt() xor headerMask[5].toInt()).toByte()
                deobf[6] = (deobf[6].toInt() xor headerMask[6].toInt()).toByte()
                deobf[7] = (deobf[7].toInt() xor headerMask[7].toInt()).toByte()
                deobf[8] = (deobf[8].toInt() xor headerMask[8].toInt()).toByte()
                val counter = ByteBuffer.wrap(deobf, 5, 4).int
                val payloadOffset = SESSION_ID_SIZE + PACKET_TYPE_SIZE + COUNTER_SIZE
                val ciphertext = deobf.copyOfRange(payloadOffset, rawLen)
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
                // Padding после SID+Type игнорируется
                ParsedPacket(sessionId, packetType)
            }
            else -> null
        }
    }

    /**
     * Парсит HandshakeResp (расшифрованный payload).
     *
     * ServerPublicKey(32) + SessionID(4) + IP(4) + Mask(1) +
     * DNS1(4) + DNS2(4) + MTU(2) + ServerHMAC(32) + HasPSK(1) [+ PSK(32)]
     * + возможный padding (игнорируется — парсер читает по фиксированным смещениям)
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
