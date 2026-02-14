package com.novavpn.tv.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import com.novavpn.tv.data.repository.DataStoreConfigRepository
import com.novavpn.tv.service.NovaVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Автозапуск VPN при включении телевизора.
 *
 * Проверяет:
 * 1. Был ли VPN подключён при выключении (wasConnected)
 * 2. Есть ли все необходимые настройки
 * 3. Есть ли разрешение на VPN
 *
 * Если всё готово — автоматически запускает VPN-подключение.
 */
class BootReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != "android.intent.action.QUICKBOOT_POWERON") {
            return
        }

        Log.i(TAG, "Boot completed, checking VPN auto-connect...")

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val configRepository = DataStoreConfigRepository(context)
                val config = configRepository.load()

                if (!config.wasConnected) {
                    Log.i(TAG, "VPN was not connected at shutdown, skipping")
                    return@launch
                }

                if (config.serverAddr.isEmpty() || config.email.isEmpty() || config.password.isEmpty()) {
                    Log.w(TAG, "Incomplete VPN config, skipping auto-connect")
                    return@launch
                }

                // Проверяем разрешение VPN
                val vpnIntent = VpnService.prepare(context)
                if (vpnIntent != null) {
                    Log.w(TAG, "VPN permission not granted, skipping auto-connect")
                    return@launch
                }

                // Запускаем VPN-сервис
                val serviceIntent = Intent(context, NovaVpnService::class.java).apply {
                    action = NovaVpnService.ACTION_CONNECT
                    putExtra(NovaVpnService.EXTRA_SERVER, config.serverAddr)
                    putExtra(NovaVpnService.EXTRA_EMAIL, config.email)
                    putExtra(NovaVpnService.EXTRA_PASSWORD, config.password)
                    putExtra(NovaVpnService.EXTRA_PSK, config.preSharedKey)
                }

                context.startForegroundService(serviceIntent)
                Log.i(TAG, "VPN auto-connect initiated")

            } catch (e: Exception) {
                Log.e(TAG, "Auto-connect failed: ${e.message}")
            } finally {
                pendingResult.finish()
            }
        }
    }
}
