package com.novavpn.tv.domain.repository

import com.novavpn.tv.domain.model.VpnConfig

/**
 * Репозиторий конфигурации VPN.
 */
interface ConfigRepository {
    suspend fun load(): VpnConfig
    suspend fun save(config: VpnConfig)
    suspend fun updatePsk(pskHex: String)
    suspend fun setWasConnected(wasConnected: Boolean)
}
