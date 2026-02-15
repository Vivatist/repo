package com.novavpn.tv.domain.model

/**
 * Результат успешного рукопожатия с сервером.
 */
data class HandshakeResult(
    val sessionId: Long,
    val sendKey: ByteArray,
    val recvKey: ByteArray,
    val hmacKey: ByteArray,
    val assignedIp: ByteArray,
    val subnetMask: Int,
    val dns1: ByteArray,
    val dns2: ByteArray,
    val mtu: Int,
    val newPsk: ByteArray?   // PSK от сервера при bootstrap (32 байта или null)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HandshakeResult) return false
        return sessionId == other.sessionId
    }

    override fun hashCode(): Int = sessionId.hashCode()
}
