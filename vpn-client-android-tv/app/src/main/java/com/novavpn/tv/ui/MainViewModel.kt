package com.novavpn.tv.ui

import android.app.Application
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.novavpn.tv.data.repository.DataStoreConfigRepository
import com.novavpn.tv.domain.model.*
import com.novavpn.tv.domain.repository.ConfigRepository
import com.novavpn.tv.service.NovaVpnService
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.isActive
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
        // Загружаем конфигурацию (включая PSK)
        viewModelScope.launch {
            val config = configRepository.load()
            _uiState.update {
                it.copy(
                    serverAddr = config.serverAddr,
                    email = config.email,
                    password = config.password,
                    psk = config.preSharedKey,
                    configLoaded = true,
                    wasConnected = config.wasConnected
                )
            }
        }

        // Наблюдаем за состоянием VPN (с ожиданием появления сервиса)
        observeVpnState()
    }

    /**
     * Непрерывное наблюдение за состоянием VPN-сервиса.
     * Ждёт появления NovaVpnService.instance (сервис запускается позже ViewModel),
     * затем подписывается на stateFlow клиента.
     */
    private fun observeVpnState() {
        viewModelScope.launch {
            while (isActive) {
                val service = NovaVpnService.instance
                if (service != null) {
                    service.vpnClient.stateFlow.collectLatest { state ->
                        _uiState.update { it.copy(connectionState = state) }
                    }
                }
                delay(200) // Проверяем каждые 200мс пока сервис не появится
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

        // Валидация адреса сервера: host:port
        val addrRegex = Regex("^[\\w.\\-]+:\\d{1,5}$")
        if (!addrRegex.matches(state.serverAddr.trim())) {
            _uiState.update { it.copy(validationError = "Неверный формат адреса. Укажите host:port (например, 212.118.43.43:443)") }
            return
        }

        // Валидация email: минимальная проверка наличия @
        if (!state.email.trim().contains("@") || state.email.trim().length < 3) {
            _uiState.update { it.copy(validationError = "Неверный формат email") }
            return
        }

        // Валидация пароля: не пустой
        if (state.password.isBlank()) {
            _uiState.update { it.copy(validationError = "Пароль не может быть пустым") }
            return
        }

        // Валидация прошла — сохраняем и закрываем панель
        _uiState.update { it.copy(validationError = null, showSettings = false) }

        viewModelScope.launch {
            configRepository.save(
                VpnConfig(
                    serverAddr = state.serverAddr.trim(),
                    email = state.email.trim(),
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

        _uiState.update { it.copy(connectionState = ConnectionState.CONNECTING, errorMessage = null) }

        viewModelScope.launch {
            // Загружаем актуальный PSK (мог быть обновлён через bootstrap)
            val config = configRepository.load()
            val psk = config.preSharedKey
            if (psk.isNotEmpty() && state.psk != psk) {
                _uiState.update { it.copy(psk = psk) }
            }

            // Сохраняем текущие настройки
            configRepository.save(
                VpnConfig(
                    serverAddr = state.serverAddr.trim(),
                    email = state.email.trim(),
                    password = state.password,
                    preSharedKey = psk,
                    wasConnected = state.wasConnected
                )
            )

            val context = getApplication<Application>()
            val intent = android.content.Intent(context, NovaVpnService::class.java).apply {
                action = NovaVpnService.ACTION_CONNECT
                putExtra(NovaVpnService.EXTRA_SERVER, state.serverAddr.trim())
                putExtra(NovaVpnService.EXTRA_EMAIL, state.email.trim())
                putExtra(NovaVpnService.EXTRA_PASSWORD, state.password)
                putExtra(NovaVpnService.EXTRA_PSK, psk)
            }
            context.startForegroundService(intent)
        }
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
    val errorMessage: String? = null,
    val validationError: String? = null
)
