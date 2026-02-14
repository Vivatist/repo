package com.novavpn.tv.domain.service

import com.novavpn.tv.domain.model.ConnectionHealth
import com.novavpn.tv.domain.model.ConnectionInfo
import com.novavpn.tv.domain.model.ConnectionState
import com.novavpn.tv.domain.model.ConnectParams
import kotlinx.coroutines.flow.StateFlow

/**
 * Интерфейс VPN-клиента.
 */
interface VpnClient {
    /** Текущее состояние подключения (reactive). */
    val stateFlow: StateFlow<ConnectionState>

    /** Информация о подключении (reactive). */
    val infoFlow: StateFlow<ConnectionInfo>

    /** Здоровье соединения (reactive). */
    val healthFlow: StateFlow<ConnectionHealth>

    /** Подключение к VPN-серверу. */
    suspend fun connect(params: ConnectParams)

    /** Отключение от VPN-сервера. */
    suspend fun disconnect()

    /** Текущее состояние. */
    fun getState(): ConnectionState
}
