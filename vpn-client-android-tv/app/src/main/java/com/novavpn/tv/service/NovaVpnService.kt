package com.novavpn.tv.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.novavpn.tv.R
import com.novavpn.tv.data.repository.DataStoreConfigRepository
import com.novavpn.tv.data.vpn.NovaVpnClientImpl
import com.novavpn.tv.domain.model.ConnectParams
import com.novavpn.tv.domain.model.ConnectionState
import com.novavpn.tv.domain.model.HandshakeResult
import com.novavpn.tv.domain.repository.ConfigRepository
import com.novavpn.tv.ui.MainActivity
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest
import java.io.FileDescriptor

/**
 * Android VpnService для NovaVPN.
 *
 * Управляет TUN-интерфейсом и VPN-подключением.
 * Работает как foreground service с уведомлением.
 */
class NovaVpnService : VpnService() {

    companion object {
        private const val TAG = "NovaVpnService"
        private const val CHANNEL_ID = "novavpn_channel"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "com.novavpn.tv.CONNECT"
        const val ACTION_DISCONNECT = "com.novavpn.tv.DISCONNECT"

        const val EXTRA_SERVER = "server"
        const val EXTRA_EMAIL = "email"
        const val EXTRA_PASSWORD = "password"
        const val EXTRA_PSK = "psk"

        // Singleton для UI
        @Volatile
        var instance: NovaVpnService? = null
            private set
    }

    val vpnClient = NovaVpnClientImpl()
    private lateinit var configRepository: ConfigRepository
    private var vpnInterface: ParcelFileDescriptor? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Мониторинг сети через ConnectivityManager
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    // Флаг: сеть доступна (атомарный для безопасного доступа из разных потоков)
    @Volatile private var hasNetwork = true

    override fun onCreate() {
        super.onCreate()
        instance = this
        configRepository = DataStoreConfigRepository(this)

        createNotificationChannel()

        // Настраиваем колбэки VPN-клиента
        vpnClient.onNewPsk = { pskHex ->
            scope.launch {
                configRepository.updatePsk(pskHex)
                Log.i(TAG, "PSK saved (bootstrap)")
            }
        }

        vpnClient.onTunRequired = { result ->
            setupTunInterface(result)
        }

        vpnClient.onProtectSocket = { socket ->
            val ok = protect(socket)
            if (!ok) {
                Log.e(TAG, "protect() FAILED — VPN routing loop!")
            } else {
                Log.i(TAG, "Socket protected from VPN routing")
            }
            ok
        }

        // Следим за состоянием для обновления уведомления
        scope.launch {
            vpnClient.stateFlow.collectLatest { state ->
                updateNotification(state)
                if (state == ConnectionState.CONNECTED) {
                    configRepository.setWasConnected(true)
                }
            }
        }

        // Регистрируем мониторинг сети — мгновенный callback при потере/появлении сети
        registerNetworkMonitor()

        Log.i(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification(ConnectionState.DISCONNECTED))

        when (intent?.action) {
            ACTION_CONNECT -> {
                val server = intent.getStringExtra(EXTRA_SERVER) ?: return START_STICKY
                val email = intent.getStringExtra(EXTRA_EMAIL) ?: return START_STICKY
                val password = intent.getStringExtra(EXTRA_PASSWORD) ?: return START_STICKY
                val psk = intent.getStringExtra(EXTRA_PSK) ?: ""

                scope.launch {
                    try {
                        vpnClient.connect(ConnectParams(server, psk, email, password))
                    } catch (e: Exception) {
                        Log.e(TAG, "Connect failed: ${e.message}")
                    }
                }
            }
            ACTION_DISCONNECT -> {
                scope.launch {
                    try {
                        configRepository.setWasConnected(false)
                        vpnClient.disconnect()
                    } catch (e: Exception) {
                        Log.e(TAG, "Disconnect failed: ${e.message}")
                    }
                    stopSelf()
                }
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        instance = null
        unregisterNetworkMonitor()
        scope.cancel()
        runBlocking {
            try { vpnClient.disconnect() } catch (_: Exception) {}
        }
        vpnInterface?.close()
        vpnInterface = null
        Log.i(TAG, "Service destroyed")
        super.onDestroy()
    }

    override fun onRevoke() {
        Log.e(TAG, "VPN REVOKED by system! (routing loop or another VPN took over)")
        // BUG4 fix: сбрасываем wasConnected и корректно завершаем сервис
        scope.launch {
            try { configRepository.setWasConnected(false) } catch (_: Exception) {}
            try { vpnClient.disconnect() } catch (_: Exception) {}
            stopSelf()
        }
        super.onRevoke()
    }

    /**
     * Создаёт TUN-интерфейс через VpnService.Builder.
     */
    private fun setupTunInterface(result: HandshakeResult): FileDescriptor? {
        try {
            // Закрываем предыдущий интерфейс
            vpnInterface?.close()

            val assignedIp = ipToString(result.assignedIp)
            val dns1 = ipToString(result.dns1)
            val dns2 = ipToString(result.dns2)
            val mtu = result.mtu

            val builder = Builder()
                .setSession("NovaVPN")
                .setMtu(mtu)
                .addAddress(assignedIp, result.subnetMask)
                .addDnsServer(dns1)
                .addDnsServer(dns2)
                // Маршрутизация всего трафика через VPN
                .addRoute("0.0.0.0", 0)
                .setBlocking(true)

            // Исключаем своё приложение из VPN-туннеля (защита от routing loop
            // на Android TV, где protect() может не работать для UDP-сокетов)
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "Excluded $packageName from VPN tunnel")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude app from VPN: ${e.message}")
            }

            val pfd = builder.establish()
                ?: throw Exception("Failed to establish VPN interface")

            vpnInterface = pfd
            Log.i(TAG, "TUN established: IP=$assignedIp/${ result.subnetMask}, MTU=$mtu, DNS=$dns1/$dns2")

            return pfd.fileDescriptor
        } catch (e: Exception) {
            Log.e(TAG, "TUN setup failed: ${e.message}")
            return null
        }
    }

    // ============ Уведомления ============

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "NovaVPN connection status"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(state: ConnectionState): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val text = when (state) {
            ConnectionState.CONNECTED -> getString(R.string.notification_connected)
            ConnectionState.CONNECTING -> getString(R.string.notification_connecting)
            else -> getString(R.string.notification_disconnected)
        }

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("NovaVPN")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_shield)
            .setContentIntent(pendingIntent)
            .setOngoing(state == ConnectionState.CONNECTED || state == ConnectionState.CONNECTING)
            .build()
    }

    private fun updateNotification(state: ConnectionState) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, buildNotification(state))
    }

    private fun ipToString(ip: ByteArray): String {
        return ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }

    // ============ Мониторинг сети ============

    /**
     * Регистрирует ConnectivityManager callback.
     * Мгновенный callback при потере/появлении сети:
     * - onLost: сеть потеряна → закрываем сокет → reconnect
     * - onAvailable: сеть появилась → логируем (ускоряет reconnect)
     * Не нарушает маскировку — никакого трафика не генерирует.
     */
    private fun registerNetworkMonitor() {
        try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return
            connectivityManager = cm

            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    Log.i(TAG, "Network available")
                    hasNetwork = true
                }

                override fun onLost(network: Network) {
                    Log.w(TAG, "Network lost!")
                    hasNetwork = false

                    // Если VPN подключён — закрываем сокет для мгновенного reconnect
                    if (vpnClient.stateFlow.value == ConnectionState.CONNECTED) {
                        Log.w(TAG, "Forcing reconnect due to network loss")
                        vpnClient.forceReconnect()
                    }
                }
            }

            networkCallback = callback

            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            cm.registerNetworkCallback(request, callback)
            Log.i(TAG, "Network monitor registered")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network monitor: ${e.message}")
        }
    }

    /**
     * Отменяет мониторинг сети.
     */
    private fun unregisterNetworkMonitor() {
        try {
            networkCallback?.let { cb ->
                connectivityManager?.unregisterNetworkCallback(cb)
                Log.i(TAG, "Network monitor unregistered")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister network monitor: ${e.message}")
        }
        networkCallback = null
        connectivityManager = null
    }
}
