package com.phonelink.transport

import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.TlsVersion
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * AND-5: Android Core Network Transport Layer.
 *
 * Manages WebSocket connections over TLS 1.3 to the VPS relay,
 * maintaining an explicit, unambiguous connection state machine.
 */
class NetworkTransport(
    private val okHttpClient: OkHttpClient = defaultOkHttpClient(),
    private val config: TransportConfig = TransportConfig()
) {
    data class TransportConfig(
        val connectTimeoutSeconds: Long = 10,
        val pingIntervalSeconds: Long = 15,
        val maxRetryAttempts: Int = 3,
        val retryBackoffBaseMillis: Long = 1000
    )

    sealed class ConnectionState {
        object Disconnected : ConnectionState()
        object Connecting : ConnectionState()
        data class Connected(val url: String, val connectedAtMillis: Long) : ConnectionState()
        data class Reconnecting(val attempt: Int, val maxAttempts: Int, val nextRetryDelayMillis: Long) : ConnectionState()
        data class Error(val cause: Throwable, val isRecoverable: Boolean) : ConnectionState()

        override fun toString(): String = when (this) {
            is Disconnected -> "DISCONNECTED"
            is Connecting -> "CONNECTING"
            is Connected -> "CONNECTED(url=$url, connectedAt=$connectedAtMillis)"
            is Reconnecting -> "RECONNECTING(attempt=$attempt/$maxAttempts, delay=${nextRetryDelayMillis}ms)"
            is Error -> "ERROR(cause=${cause.message}, recoverable=$isRecoverable)"
        }
    }

    interface Listener {
        fun onStateChanged(newState: ConnectionState) {}
        fun onMessageReceived(bytes: ByteArray) {}
        fun onMessageReceived(text: String) {}
        fun onError(error: Throwable) {}
    }

    companion object {
        fun defaultOkHttpClient(): OkHttpClient {
            // Enforce modern TLS (TLS 1.3 preferred, TLS 1.2 minimum)
            val connectionSpec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2)
                .build()

            return OkHttpClient.Builder()
                .connectionSpecs(listOf(connectionSpec, ConnectionSpec.CLEARTEXT))
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS) // Indefinite for WebSocket
                .pingInterval(15, TimeUnit.SECONDS)
                .build()
        }
    }

    private val currentState = AtomicReference<ConnectionState>(ConnectionState.Disconnected)
    private val listeners = CopyOnWriteArrayList<Listener>()
    private val connectionGeneration = java.util.concurrent.atomic.AtomicLong(0)
    private var activeWebSocket: WebSocket? = null
    private var activeUrl: String? = null
    private var currentRetryAttempt = 0

    fun isQueueBackpressured(maxQueuedBytes: Long = 2L * 1024L * 1024L): Boolean {
        val ws = activeWebSocket ?: return false
        return ws.queueSize() >= maxQueuedBytes
    }

    fun addListener(listener: Listener) {
        listeners.addIfAbsent(listener)
    }

    fun removeListener(listener: Listener) {
        listeners.remove(listener)
    }

    fun getState(): ConnectionState = currentState.get()

    private fun setState(newState: ConnectionState) {
        val oldState = currentState.getAndSet(newState)
        if (oldState != newState) {
            listeners.forEach { listener ->
                try {
                    listener.onStateChanged(newState)
                } catch (t: Throwable) {
                    // Suppress listener exceptions
                }
            }
        }
    }

    /**
     * Connects to the given WebSocket endpoint (e.g. wss://relay:8443/ws/v1/connect).
     */
    @Synchronized
    fun connect(url: String) {
        val state = currentState.get()
        if ((state is ConnectionState.Connecting || state is ConnectionState.Connected) && activeUrl == url) {
            return
        }

        // If reconnecting with a new URL or session token, tear down the prior socket cleanly first
        activeWebSocket?.let { oldWs ->
            activeWebSocket = null
            try {
                oldWs.close(1000, "Superseded by new connection")
            } catch (_: Throwable) {}
            try {
                oldWs.cancel()
            } catch (_: Throwable) {}
        }

        val gen = connectionGeneration.incrementAndGet()
        activeUrl = url
        setState(ConnectionState.Connecting)

        val request = Request.Builder()
            .url(url)
            .build()

        activeWebSocket = okHttpClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (connectionGeneration.get() != gen) return
                currentRetryAttempt = 0
                setState(ConnectionState.Connected(url, System.currentTimeMillis()))
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (connectionGeneration.get() != gen) return
                val data = bytes.toByteArray()
                listeners.forEach { listener ->
                    try {
                        listener.onMessageReceived(data)
                    } catch (t: Throwable) {
                        // Suppress listener exceptions
                    }
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (connectionGeneration.get() != gen) return
                listeners.forEach { listener ->
                    try {
                        listener.onMessageReceived(text)
                    } catch (t: Throwable) {
                        // Suppress listener exceptions
                    }
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (connectionGeneration.get() != gen) return
                if (activeWebSocket === webSocket) {
                    activeWebSocket = null
                }
                setState(ConnectionState.Disconnected)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (connectionGeneration.get() != gen) return
                if (activeWebSocket !== webSocket && activeWebSocket != null) {
                    return
                }
                activeWebSocket = null
                setState(ConnectionState.Error(t, isRecoverable = true))
                listeners.forEach { listener ->
                    try {
                        listener.onError(t)
                    } catch (_: Throwable) {}
                }
            }
        })
    }

    /**
     * Gracefully disconnects the WebSocket session.
     */
    @Synchronized
    fun disconnect(code: Int = 1000, reason: String = "Client disconnect") {
        connectionGeneration.incrementAndGet()
        currentRetryAttempt = config.maxRetryAttempts // Cancel further auto-retries
        activeWebSocket?.let { ws ->
            try {
                ws.close(code, reason)
            } catch (_: Throwable) {}
            try {
                ws.cancel()
            } catch (_: Throwable) {}
        }
        activeWebSocket = null
        activeUrl = null
        setState(ConnectionState.Disconnected)
    }

    /**
     * Sends binary payload over the WebSocket connection.
     */
    fun send(bytes: ByteArray): Boolean {
        val ws = activeWebSocket ?: return false
        return ws.send(bytes.toByteString())
    }

    /**
     * Sends text payload over the WebSocket connection.
     */
    fun send(text: String): Boolean {
        val ws = activeWebSocket ?: return false
        return ws.send(text)
    }
}
