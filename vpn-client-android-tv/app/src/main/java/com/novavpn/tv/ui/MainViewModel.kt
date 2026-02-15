package com.novavpn.tv.ui

import android.app.Application
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.novavpn.tv.data.repository.DataStoreConfigRepository
import com.novavpn.tv.domain.model.*
import com.novavpn.tv.domain.repository.ConfigRepository
import com.novavpn.tv.service.NovaVpnService
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

/**
 * ViewModel для главного экрана NovaVPN TV.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val configRepository: ConfigRepository = DataStoreConfigRepository(application)

    // UI State
    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    // VPN State (от сервиса)
    val vpnState: StateFlow<ConnectionState> get() =
        NovaVpnService.instance?.vpnClient?.stateFlow
            ?: MutableStateFlow(ConnectionState.DISCONNECTED)

    val connectionInfo: StateFlow<ConnectionInfo> get() =
        NovaVpnService.instance?.vpnClient?.infoFlow
            ?: MutableStateFlow(ConnectionInfo())

    val connectionHealth: StateFlow<ConnectionHealth> get() =
        NovaVpnService.instance?.vpnClient?.healthFlow
            ?: MutableStateFlow(ConnectionHealth.GOOD)

    init {
        // Загружаем конфигурацию
        viewModelScope.launch {
            val config = configRepository.load()
            _uiState.update {
                it.copy(
                    serverAddr = config.serverAddr,
                    email = config.email,
                    password = config.password,
                    configLoaded = true,
                    wasConnected = config.wasConnected
                )
            }
        }

        // Наблюдаем за состоянием VPN
        viewModelScope.launch {
            NovaVpnService.instance?.vpnClient?.stateFlow?.collectLatest { state ->
                _uiState.update { it.copy(connectionState = state) }
            }
        }
    }

    fun updateServerAddr(value: String) {
        _uiState.update { it.copy(serverAddr = value) }
    }

    fun updateEmail(value: String) {
        _uiState.update { it.copy(email = value) }
    }

    fun updatePassword(value: String) {
        _uiState.update { it.copy(password = value) }
    }

    fun toggleSettings() {
        _uiState.update { it.copy(showSettings = !it.showSettings) }
    }

    fun saveSettings() {
        val state = _uiState.value
        viewModelScope.launch {
            configRepository.save(
                VpnConfig(
                    serverAddr = state.serverAddr,
                    email = state.email,
                    password = state.password,
                    preSharedKey = state.psk,
                    wasConnected = state.wasConnected
                )
            )
        }
    }

    fun connect() {
        val state = _uiState.value
        if (state.serverAddr.isEmpty() || state.email.isEmpty() || state.password.isEmpty()) {
            _uiState.update { it.copy(errorMessage = "Заполните все поля") }
            return
        }

        saveSettings()
        _uiState.update { it.copy(connectionState = ConnectionState.CONNECTING, errorMessage = null) }

        val context = getApplication<Application>()
        val intent = android.content.Intent(context, NovaVpnService::class.java).apply {
            action = NovaVpnService.ACTION_CONNECT
            putExtra(NovaVpnService.EXTRA_SERVER, state.serverAddr)
            putExtra(NovaVpnService.EXTRA_EMAIL, state.email)
            putExtra(NovaVpnService.EXTRA_PASSWORD, state.password)
            putExtra(NovaVpnService.EXTRA_PSK, state.psk)
        }
        context.startForegroundService(intent)
    }

    fun disconnect() {
        _uiState.update { it.copy(connectionState = ConnectionState.DISCONNECTING) }

        viewModelScope.launch {
            configRepository.setWasConnected(false)
        }

        val context = getApplication<Application>()
        val intent = android.content.Intent(context, NovaVpnService::class.java).apply {
            action = NovaVpnService.ACTION_DISCONNECT
        }
        context.startForegroundService(intent)
    }

    fun clearError() {
        _uiState.update { it.copy(errorMessage = null) }
    }

    /**
     * Проверяет, нужно ли разрешение VPN.
     * Возвращает Intent для запроса или null если разрешение есть.
     */
    fun checkVpnPermission(): android.content.Intent? {
        return VpnService.prepare(getApplication())
    }
}

/**
 * Состояние UI главного экрана.
 */
data class MainUiState(
    val serverAddr: String = "",
    val email: String = "",
    val password: String = "",
    val psk: String = "",
    val connectionState: ConnectionState = ConnectionState.DISCONNECTED,
    val showSettings: Boolean = false,
    val configLoaded: Boolean = false,
    val wasConnected: Boolean = false,
    val errorMessage: String? = null
)
