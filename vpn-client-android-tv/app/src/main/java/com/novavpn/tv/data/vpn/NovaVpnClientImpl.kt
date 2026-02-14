package com.novavpn.tv.data.vpn

import android.util.Log
import com.novavpn.tv.data.crypto.NovaCryptoSession
import com.novavpn.tv.data.crypto.NovaKeyExchange
import com.novavpn.tv.data.protocol.NovaProtocol
import com.novavpn.tv.domain.model.*
import com.novavpn.tv.domain.service.VpnClient
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Реализация VPN-клиента NovaVPN для Android.
 *
 * Управляет:
 * - Рукопожатием (Curve25519 ECDH + ChaCha20-Poly1305)
 * - Шифрованием/дешифрованием data-пакетов (plain ChaCha20 XOR)
 * - Keepalive (рандомизированный, 10-20 сек)
 * - Мониторингом здоровья (пассивный, 3-7 сек)
 * - Автопереподключением (экспоненциальный backoff)
 */
class NovaVpnClientImpl : VpnClient {

    companion object {
        private const val TAG = "NovaVpnClient"
        private const val HEALTH_DEGRADED_MS = 35_000L
        private const val HEALTH_LOST_MS = 60_000L
        private const val MAX_RECONNECT_ATTEMPTS = 60
        private const val MAX_BACKOFF_MS = 30_000L
    }

    // Reactive state
    private val _stateFlow = MutableStateFlow(ConnectionState.DISCONNECTED)
    override val stateFlow: StateFlow<ConnectionState> = _stateFlow.asStateFlow()

    private val _infoFlow = MutableStateFlow(ConnectionInfo())
    override val infoFlow: StateFlow<ConnectionInfo> = _infoFlow.asStateFlow()

    private val _healthFlow = MutableStateFlow(ConnectionHealth.GOOD)
    override val healthFlow: StateFlow<ConnectionHealth> = _healthFlow.asStateFlow()

    // Соединение
    private var socket: DatagramSocket? = null
    private var tunFd: FileDescriptor? = null
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private var session: NovaCryptoSession? = null
    private var sessionId: Long = 0

    // Активность
    private val lastActivity = AtomicLong(System.nanoTime())
    private val stopped = AtomicBoolean(false)
    private val reconnecting = AtomicBoolean(false)
    private val random = SecureRandom()

    // Coroutine scope
    private var scope: CoroutineScope? = null
    private var connectParams: ConnectParams? = null
    private var pskBytes: ByteArray? = null

    // Статистика
    private val bytesSent = AtomicLong(0)
    private val bytesRecv = AtomicLong(0)
    private val packetsSent = AtomicLong(0)
    private val packetsRecv = AtomicLong(0)

    // 0-RTT resume
    private var resumeSessionId: Long = 0
    private var resumeKeys: Triple<ByteArray, ByteArray, ByteArray>? = null
    private var resumeSendCounter: Long = 0
    private var resumeAssignedIp: ByteArray? = null
    private var resumeDns1: ByteArray? = null
    private var resumeDns2: ByteArray? = null
    private var resumeMtu: Int = 0
    private var resumeSubnetMask: Int = 0

    // Колбэки
    var onNewPsk: ((String) -> Unit)? = null
    var onTunRequired: ((HandshakeResult) -> FileDescriptor?)? = null
    var onProtectSocket: ((DatagramSocket) -> Boolean)? = null

    override fun getState(): ConnectionState = _stateFlow.value

    override suspend fun connect(params: ConnectParams) {
        if (_stateFlow.value != ConnectionState.DISCONNECTED) {
            throw IllegalStateException("Already connected or connecting")
        }

        _stateFlow.value = ConnectionState.CONNECTING
        connectParams = params
        stopped.set(false)

        // Декодируем PSK
        val psk = if (params.psk.isNotEmpty()) {
            try {
                NovaKeyExchange.decodePsk(params.psk)
            } catch (e: Exception) {
                _stateFlow.value = ConnectionState.DISCONNECTED
                throw Exception("Invalid PSK: ${e.message}")
            }
        } else {
            Log.i(TAG, "Bootstrap mode (no PSK)")
            ByteArray(32) // нулевой PSK
        }
        pskBytes = psk.copyOf()

        try {
            // Создаём UDP-сокет
            val sock = DatagramSocket()
            sock.connect(InetSocketAddress(
                params.serverAddr.substringBefore(":"),
                params.serverAddr.substringAfter(":").toIntOrNull() ?: 443
            ))
            sock.receiveBufferSize = 4 * 1024 * 1024
            sock.sendBufferSize = 4 * 1024 * 1024
            socket = sock

            // Защищаем сокет от маршрутизации через TUN
            onProtectSocket?.invoke(sock)

            Log.i(TAG, "UDP: ${sock.localAddress}:${sock.localPort} -> ${params.serverAddr}")

            // Выполняем рукопожатие
            val performer = HandshakePerformer(sock, psk, params.email, params.password)

            val timeout = if (params.psk.isEmpty()) 10_000 else 2_000
            val result: HandshakeResult
            try {
                result = performer.perform(timeout)
            } catch (e: Exception) {
                // Если есть PSK, пробуем bootstrap
                if (params.psk.isNotEmpty()) {
                    Log.w(TAG, "Saved PSK failed, trying bootstrap: ${e.message}")
                    val zeroPsk = ByteArray(32)
                    val bootstrapPerformer = HandshakePerformer(sock, zeroPsk, params.email, params.password)
                    try {
                        val bootstrapResult = bootstrapPerformer.perform(10_000)
                        setupSession(bootstrapResult)
                        return
                    } catch (e2: Exception) {
                        throw Exception("Handshake failed: ${e2.message}")
                    }
                }
                throw Exception("Handshake failed: ${e.message}")
            }

            setupSession(result)

        } catch (e: Exception) {
            socket?.close()
            socket = null
            _stateFlow.value = ConnectionState.DISCONNECTED
            throw e
        }
    }

    private fun setupSession(result: HandshakeResult) {
        sessionId = result.sessionId
        session = NovaCryptoSession(result.sendKey, result.recvKey, result.hmacKey)

        // Сохраняем PSK если bootstrap
        if (result.newPsk != null) {
            val pskHex = NovaKeyExchange.encodePsk(result.newPsk)
            Log.i(TAG, "Received PSK from server (bootstrap)")
            onNewPsk?.invoke(pskHex)
        }

        // Запрашиваем TUN через колбэк (VpnService)
        val fd = onTunRequired?.invoke(result)
            ?: throw Exception("TUN interface not available")
        tunFd = fd
        tunIn = FileInputStream(fd)
        tunOut = FileOutputStream(fd)

        // Обновляем информацию о подключении
        _infoFlow.value = ConnectionInfo(
            state = ConnectionState.CONNECTED,
            serverAddr = connectParams?.serverAddr ?: "",
            assignedIp = ipToString(result.assignedIp),
            dns = listOf(ipToString(result.dns1), ipToString(result.dns2)),
            mtu = result.mtu,
            subnetMask = result.subnetMask
        )

        // Запускаем рабочие корутины
        lastActivity.set(System.nanoTime())
        _healthFlow.value = ConnectionHealth.GOOD

        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        scope?.launch { udpReadLoop() }
        scope?.launch { tunReadLoop() }
        scope?.launch { keepaliveLoop() }
        scope?.launch { healthMonitorLoop() }

        _stateFlow.value = ConnectionState.CONNECTED
        Log.i(TAG, "Connected to VPN")
    }

    override suspend fun disconnect() {
        if (_stateFlow.value == ConnectionState.DISCONNECTED) return

        _stateFlow.value = ConnectionState.DISCONNECTING
        stopped.set(true)
        Log.i(TAG, "Disconnecting...")

        // Сохраняем resume data
        saveResumeData()

        // Отправляем Disconnect пакет
        sendDisconnect()

        cleanup()

        _stateFlow.value = ConnectionState.DISCONNECTED
        _infoFlow.value = ConnectionInfo()
        Log.i(TAG, "Disconnected")
    }

    private fun sendDisconnect() {
        try {
            val sid = sessionId
            if (sid != 0L) {
                val packet = NovaProtocol.marshalSimplePacket(NovaProtocol.PACKET_DISCONNECT, sid)
                socket?.send(DatagramPacket(packet, packet.size))
            }
        } catch (e: Exception) {
            Log.w(TAG, "Disconnect packet error: ${e.message}")
        }
    }

    private fun cleanup() {
        scope?.cancel()
        scope = null

        try { tunIn?.close() } catch (_: Exception) {}
        try { tunOut?.close() } catch (_: Exception) {}
        try { socket?.close() } catch (_: Exception) {}

        tunIn = null
        tunOut = null
        tunFd = null
        socket = null

        session?.close()
        session = null
        sessionId = 0

        bytesSent.set(0)
        bytesRecv.set(0)
        packetsSent.set(0)
        packetsRecv.set(0)
    }

    // ============ Рабочие циклы ============

    private suspend fun udpReadLoop() {
        val buf = ByteArray(65536)
        val datagram = DatagramPacket(buf, buf.size)

        while (!stopped.get()) {
            try {
                val sock = socket ?: break
                sock.receive(datagram)

                lastActivity.set(System.nanoTime())
                val parsed = NovaProtocol.parseIncoming(buf, datagram.length) ?: continue

                when (parsed.type) {
                    NovaProtocol.PACKET_DATA -> {
                        val ciphertext = parsed.payload ?: continue
                        val plaintext = session?.decryptData(parsed.counter, ciphertext) ?: continue
                        try {
                            tunOut?.write(plaintext)
                            bytesRecv.addAndGet(plaintext.size.toLong())
                            packetsRecv.incrementAndGet()
                            updateStats()
                        } catch (e: Exception) {
                            if (!stopped.get()) Log.w(TAG, "TUN write error: ${e.message}")
                        }
                    }
                    NovaProtocol.PACKET_KEEPALIVE -> {
                        // Активность уже записана
                    }
                    NovaProtocol.PACKET_DISCONNECT -> {
                        Log.i(TAG, "Server sent disconnect")
                        clearResumeData()
                        if (!stopped.get()) {
                            withContext(Dispatchers.Default) { reconnect() }
                        }
                        return
                    }
                    NovaProtocol.PACKET_ERROR -> {
                        Log.e(TAG, "Server error received")
                        break
                    }
                }
            } catch (e: Exception) {
                if (!stopped.get()) {
                    Log.w(TAG, "UDP read error: ${e.message}")
                    withContext(Dispatchers.Default) { reconnect() }
                    return
                }
            }
        }
    }

    private suspend fun tunReadLoop() {
        val buf = ByteArray(65536)
        val sendBuf = ByteArray(NovaProtocol.DATA_OVERHEAD + 65536)

        while (!stopped.get()) {
            try {
                val input = tunIn ?: break
                val n = input.read(buf)
                if (n <= 0) continue
                if (reconnecting.get()) continue

                val sess = session ?: continue
                val encLen = sess.encryptData(sendBuf, buf, 0, n)

                // Формируем data-пакет
                val counter = ByteBuffer.wrap(sendBuf, 0, 4).int
                val ciphertext = sendBuf.copyOfRange(4, encLen)
                val packet = NovaProtocol.marshalDataPacket(sessionId, counter, ciphertext)

                try {
                    socket?.send(DatagramPacket(packet, packet.size))
                    bytesSent.addAndGet(n.toLong())
                    packetsSent.incrementAndGet()
                    updateStats()
                } catch (e: Exception) {
                    if (!stopped.get()) Log.w(TAG, "UDP write error: ${e.message}")
                }
            } catch (e: Exception) {
                if (!stopped.get()) {
                    Log.w(TAG, "TUN read error: ${e.message}")
                }
                break
            }
        }
    }

    private suspend fun keepaliveLoop() {
        while (!stopped.get()) {
            val interval = 10_000L + (random.nextInt(11) * 1000L) // 10-20 сек
            delay(interval)

            if (stopped.get() || reconnecting.get()) continue

            try {
                val sid = sessionId
                if (sid != 0L) {
                    val packet = NovaProtocol.marshalSimplePacket(NovaProtocol.PACKET_KEEPALIVE, sid)
                    socket?.send(DatagramPacket(packet, packet.size))
                }
            } catch (e: Exception) {
                if (!stopped.get()) Log.w(TAG, "Keepalive error: ${e.message}")
            }
        }
    }

    private suspend fun healthMonitorLoop() {
        while (!stopped.get()) {
            val interval = 3_000L + (random.nextInt(5) * 1000L) // 3-7 сек
            delay(interval)

            val elapsed = (System.nanoTime() - lastActivity.get()) / 1_000_000 // ms

            val newHealth = when {
                elapsed >= HEALTH_LOST_MS -> ConnectionHealth.LOST
                elapsed >= HEALTH_DEGRADED_MS -> ConnectionHealth.DEGRADED
                else -> ConnectionHealth.GOOD
            }

            val oldHealth = _healthFlow.value
            if (oldHealth != newHealth) {
                _healthFlow.value = newHealth
                Log.i(TAG, "Health: $oldHealth → $newHealth (${elapsed}ms without packets)")

                if (newHealth == ConnectionHealth.LOST && !stopped.get()) {
                    Log.w(TAG, "Connection lost, initiating reconnect...")
                    socket?.close()
                    return
                }
            }
        }
    }

    // ============ Автопереподключение ============

    private suspend fun reconnect() {
        if (!reconnecting.compareAndSet(false, true)) return
        if (stopped.get()) {
            reconnecting.set(false)
            return
        }

        _stateFlow.value = ConnectionState.CONNECTING
        Log.i(TAG, "Reconnecting...")

        val params = connectParams ?: run {
            reconnecting.set(false)
            _stateFlow.value = ConnectionState.DISCONNECTED
            return
        }

        saveResumeData()

        // Закрываем старый сокет
        try { socket?.close() } catch (_: Exception) {}

        var backoff = 1000L

        for (attempt in 1..MAX_RECONNECT_ATTEMPTS) {
            if (stopped.get()) break

            delay(backoff)

            try {
                // Новый сокет
                val sock = DatagramSocket()
                sock.connect(InetSocketAddress(
                    params.serverAddr.substringBefore(":"),
                    params.serverAddr.substringAfter(":").toIntOrNull() ?: 443
                ))
                socket = sock

                // Защищаем сокет от маршрутизации через TUN
                onProtectSocket?.invoke(sock)

                // Пробуем 0-RTT resume
                if (resumeSessionId != 0L && resumeKeys != null) {
                    if (tryResume(sock)) {
                        Log.i(TAG, "0-RTT resume successful")
                        lastActivity.set(System.nanoTime())
                        _healthFlow.value = ConnectionHealth.GOOD
                        _stateFlow.value = ConnectionState.CONNECTED

                        // Перезапускаем циклы
                        scope?.cancel()
                        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
                        scope?.launch { udpReadLoop() }
                        scope?.launch { tunReadLoop() }
                        scope?.launch { keepaliveLoop() }
                        scope?.launch { healthMonitorLoop() }

                        reconnecting.set(false)
                        return
                    }
                    clearResumeData()
                }

                // Полное рукопожатие
                val psk = pskBytes ?: ByteArray(32)
                val performer = HandshakePerformer(sock, psk, params.email, params.password)
                val result = performer.perform(5000)

                sessionId = result.sessionId
                session = NovaCryptoSession(result.sendKey, result.recvKey, result.hmacKey)

                if (result.newPsk != null) {
                    onNewPsk?.invoke(NovaKeyExchange.encodePsk(result.newPsk))
                }

                _infoFlow.value = ConnectionInfo(
                    state = ConnectionState.CONNECTED,
                    serverAddr = params.serverAddr,
                    assignedIp = ipToString(result.assignedIp),
                    dns = listOf(ipToString(result.dns1), ipToString(result.dns2)),
                    mtu = result.mtu,
                    subnetMask = result.subnetMask
                )

                lastActivity.set(System.nanoTime())
                _healthFlow.value = ConnectionHealth.GOOD
                _stateFlow.value = ConnectionState.CONNECTED

                // Перезапускаем циклы
                scope?.cancel()
                scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
                scope?.launch { udpReadLoop() }
                scope?.launch { tunReadLoop() }
                scope?.launch { keepaliveLoop() }
                scope?.launch { healthMonitorLoop() }

                reconnecting.set(false)
                Log.i(TAG, "Reconnected successfully")
                return
            } catch (e: Exception) {
                Log.w(TAG, "Reconnect attempt $attempt failed: ${e.message}")
                try { socket?.close() } catch (_: Exception) {}
                backoff = (backoff * 2).coerceAtMost(MAX_BACKOFF_MS)
            }
        }

        reconnecting.set(false)
        _stateFlow.value = ConnectionState.DISCONNECTED
        Log.e(TAG, "All reconnect attempts failed")
    }

    private fun tryResume(sock: DatagramSocket): Boolean {
        try {
            val resumeSid = resumeSessionId
            val packet = NovaProtocol.marshalSimplePacket(NovaProtocol.PACKET_KEEPALIVE, resumeSid)
            sock.send(DatagramPacket(packet, packet.size))

            sock.soTimeout = 1000
            val buf = ByteArray(64)
            val response = DatagramPacket(buf, buf.size)
            sock.receive(response)
            sock.soTimeout = 0

            val parsed = NovaProtocol.parseIncoming(buf, response.length) ?: return false
            if (parsed.type != NovaProtocol.PACKET_KEEPALIVE) return false

            // Восстанавливаем сессию
            val keys = resumeKeys ?: return false
            sessionId = resumeSid
            session = NovaCryptoSession(keys.first, keys.second, keys.third)
            session?.setSendCounter(resumeSendCounter)

            return true
        } catch (_: Exception) {
            return false
        }
    }

    private fun saveResumeData() {
        val sess = session ?: return
        resumeSessionId = sessionId
        resumeKeys = Triple(sess.sendKey.copyOf(), sess.recvKey.copyOf(), sess.hmacKey.copyOf())
        resumeSendCounter = sess.getSendCounter()
    }

    private fun clearResumeData() {
        resumeSessionId = 0
        resumeKeys = null
        resumeSendCounter = 0
    }

    private fun updateStats() {
        val current = _infoFlow.value
        _infoFlow.value = current.copy(
            bytesSent = bytesSent.get(),
            bytesRecv = bytesRecv.get(),
            packetsSent = packetsSent.get(),
            packetsRecv = packetsRecv.get()
        )
    }

    private fun ipToString(ip: ByteArray): String {
        return ip.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }
}
