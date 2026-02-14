package com.novavpn.tv.data.repository

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import com.novavpn.tv.domain.model.VpnConfig
import com.novavpn.tv.domain.repository.ConfigRepository
import kotlinx.coroutines.flow.first

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "novavpn_config")

/**
 * Репозиторий конфигурации на основе DataStore Preferences.
 */
class DataStoreConfigRepository(private val context: Context) : ConfigRepository {

    companion object {
        private val KEY_SERVER_ADDR = stringPreferencesKey("server_addr")
        private val KEY_EMAIL = stringPreferencesKey("email")
        private val KEY_PASSWORD = stringPreferencesKey("password")
        private val KEY_PSK = stringPreferencesKey("pre_shared_key")
        private val KEY_WAS_CONNECTED = booleanPreferencesKey("was_connected")
    }

    override suspend fun load(): VpnConfig {
        val prefs = context.dataStore.data.first()
        return VpnConfig(
            serverAddr = prefs[KEY_SERVER_ADDR] ?: "",
            email = prefs[KEY_EMAIL] ?: "",
            password = prefs[KEY_PASSWORD] ?: "",
            preSharedKey = prefs[KEY_PSK] ?: "",
            wasConnected = prefs[KEY_WAS_CONNECTED] ?: false
        )
    }

    override suspend fun save(config: VpnConfig) {
        context.dataStore.edit { prefs ->
            prefs[KEY_SERVER_ADDR] = config.serverAddr
            prefs[KEY_EMAIL] = config.email
            prefs[KEY_PASSWORD] = config.password
            prefs[KEY_PSK] = config.preSharedKey
            prefs[KEY_WAS_CONNECTED] = config.wasConnected
        }
    }

    override suspend fun updatePsk(pskHex: String) {
        context.dataStore.edit { prefs ->
            prefs[KEY_PSK] = pskHex
        }
    }

    override suspend fun setWasConnected(wasConnected: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[KEY_WAS_CONNECTED] = wasConnected
        }
    }
}
