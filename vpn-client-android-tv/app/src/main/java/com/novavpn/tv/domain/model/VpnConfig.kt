package com.novavpn.tv.domain.model

/**
 * Конфигурация приложения NovaVPN.
 */
data class VpnConfig(
    val serverAddr: String = "",
    val email: String = "",
    val password: String = "",
    val preSharedKey: String = "",    // hex-encoded PSK
    val wasConnected: Boolean = false // был ли подключён при выключении ТВ
)
