package com.novavpn.tv.domain.model

/**
 * Состояние VPN-подключения.
 */
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING;

    fun displayName(): String = when (this) {
        DISCONNECTED -> "Отключён"
        CONNECTING -> "Подключение…"
        CONNECTED -> "Подключён"
        DISCONNECTING -> "Отключение…"
    }
}
