package com.novavpn.tv.domain.model

/**
 * Параметры подключения к VPN-серверу.
 */
data class ConnectParams(
    val serverAddr: String,   // host:port
    val psk: String,          // hex-encoded PSK (пустой = bootstrap)
    val email: String,
    val password: String
)
