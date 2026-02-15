package com.novavpn.tv.domain.model

/**
 * Уровень здоровья VPN-соединения.
 * Определяется тремя механизмами:
 * 1. Пассивный: сколько прошло с последнего полученного пакета (20/30 сек)
 * 2. Active Probe: keepalive отправлен, ответ не пришёл за 15 сек
 * 3. Wake Detection: wall clock прыгнул (устройство спало)
 */
enum class ConnectionHealth {
    /** Связь стабильна (< 20 сек без пакетов). */
    GOOD,
    /** Возможна потеря пакетов (20-30 сек). */
    DEGRADED,
    /** Связь потеряна (> 30 сек или probe timeout 15 сек), инициируется reconnect. */
    LOST;

    fun displayName(): String = when (this) {
        GOOD -> "Стабильно"
        DEGRADED -> "Нестабильно"
        LOST -> "Потеряно"
    }
}
