package com.novavpn.tv.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue

/**
 * Главная Activity для Android TV.
 * Использует Jetpack Compose для отрисовки UI.
 */
class MainActivity : ComponentActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private val viewModel: MainViewModel by viewModels()
    private var pendingConnect = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Log.i(TAG, "VPN permission granted")
            if (pendingConnect) {
                pendingConnect = false
                viewModel.connect()
            }
        } else {
            Log.w(TAG, "VPN permission denied")
            pendingConnect = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            val uiState by viewModel.uiState.collectAsState()

            NovaVpnScreen(
                uiState = uiState,
                onConnect = ::handleConnect,
                onDisconnect = { viewModel.disconnect() },
                onServerAddrChange = { viewModel.updateServerAddr(it) },
                onEmailChange = { viewModel.updateEmail(it) },
                onPasswordChange = { viewModel.updatePassword(it) },
                onToggleSettings = { viewModel.toggleSettings() },
                onSaveSettings = { viewModel.saveSettings() },
                onClearError = { viewModel.clearError() }
            )
        }
    }

    private fun handleConnect() {
        // Проверяем разрешение VPN
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            pendingConnect = true
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            viewModel.connect()
        }
    }
}
