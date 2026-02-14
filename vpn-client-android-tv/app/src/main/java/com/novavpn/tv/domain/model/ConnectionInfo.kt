package com.novavpn.tv.domain.model

/**
 * Информация о текущем VPN-подключении.
 */
data class ConnectionInfo(
    val state: ConnectionState = ConnectionState.DISCONNECTED,
    val serverAddr: String = "",
    val assignedIp: String = "",
    val dns: List<String> = emptyList(),
    val mtu: Int = 1400,
    val subnetMask: Int = 24,
    val bytesSent: Long = 0,
    val bytesRecv: Long = 0,
    val packetsSent: Long = 0,
    val packetsRecv: Long = 0
)
