package com.phonelink.transport

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.phonelink.auth.AuthClient
import com.phonelink.crypto.KeyManager
import com.phonelink.identity.DeviceIdentityManager
import com.phonelink.storage.SecureStorage
import java.util.Random
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.min

/**
 * AND-8: Android Reconnection & Network-Change Handling.
 *
 * Implements automated, jittered exponential backoff and network change monitoring:
 * 1. Monitors Wi-Fi and Cellular connectivity transitions via ConnectivityManager.
 * 2. Employs exponential backoff with full jitter to eliminate reconnect storms against restarting VPS.
 * 3. Coordinates with VPS-6 to attempt fast session resumption before falling back to full ECDSA re-auth.
 */
class ReconnectionManager(
    private val authClient: AuthClient,
    private val secureStorage: SecureStorage,
    private val identityManager: DeviceIdentityManager,
    private val keyManager: KeyManager,
    private val networkStateProvider: NetworkStateProvider,
    private val config: ReconnectConfig = ReconnectConfig(),
    private val random: Random = Random(),
    private val scheduler: ScheduledExecutorService? = null
) {
    data class ReconnectConfig(
        val baseDelayMillis: Long = 1000L,
        val maxDelayMillis: Long = 30000L,
        val backoffFactor: Double = 2.0,
        val maxConsecutiveAttempts: Int = 10
    )

    sealed class State {
        object Idle : State()
        object WaitingForNetwork : State()
        data class BackingOff(val attempt: Int, val delayMillis: Long, val nextAttemptAt: Long) : State()
        data class Connecting(val attempt: Int, val isResuming: Boolean) : State()
        data class Connected(val sessionToken: String) : State()
        data class Failed(val cause: Throwable) : State()

        override fun toString(): String = when (this) {
            is Idle -> "IDLE"
            is WaitingForNetwork -> "WAITING_FOR_NETWORK"
            is BackingOff -> "BACKING_OFF(attempt=$attempt, delay=${delayMillis}ms)"
            is Connecting -> "CONNECTING(attempt=$attempt, isResuming=$isResuming)"
            is Connected -> "CONNECTED"
            is Failed -> "FAILED(cause=${cause.message})"
        }
    }

    interface Listener {
        fun onReconnectionStateChanged(newState: State) {}
        fun onReconnectionSucceeded(sessionToken: String, wasResumed: Boolean) {}
        fun onReconnectionFailed(cause: Throwable) {}
    }

    interface NetworkStateProvider {
        fun isNetworkAvailable(): Boolean
        fun registerCallback(onAvailable: () -> Unit, onLost: () -> Unit)
        fun unregisterCallback()
    }

    class AndroidNetworkStateProvider(private val context: Context) : NetworkStateProvider {
        private val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        private var networkCallback: ConnectivityManager.NetworkCallback? = null

        override fun isNetworkAvailable(): Boolean {
            val cm = connectivityManager ?: return false
            val activeNetwork = cm.activeNetwork ?: return false
            val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
            return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }

        override fun registerCallback(onAvailable: () -> Unit, onLost: () -> Unit) {
            val cm = connectivityManager ?: return
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()

            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    onAvailable()
                }

                override fun onLost(network: Network) {
                    onLost()
                }
            }
            cm.registerNetworkCallback(request, networkCallback!!)
        }

        override fun unregisterCallback() {
            networkCallback?.let {
                try {
                    connectivityManager?.unregisterNetworkCallback(it)
                } catch (_: Exception) {}
            }
            networkCallback = null
        }
    }

    private val currentState = AtomicReference<State>(State.Idle)
    private val listeners = CopyOnWriteArrayList<Listener>()
    private val consecutiveFailures = AtomicInteger(0)
    private val isStarted = AtomicBoolean(false)
    private var scheduledTask: ScheduledFuture<*>? = null
    private var ownedScheduler: ScheduledExecutorService? = null
    private var vpsBaseUrl: String = ""

    private fun getOrCreateScheduler(): ScheduledExecutorService {
        scheduler?.let { return it }
        val existing = ownedScheduler
        if (existing != null && !existing.isShutdown && !existing.isTerminated) {
            return existing
        }
        return Executors.newSingleThreadScheduledExecutor().also { ownedScheduler = it }
    }

    fun addListener(listener: Listener) {
        listeners.addIfAbsent(listener)
    }

    fun removeListener(listener: Listener) {
        listeners.remove(listener)
    }

    fun getState(): State = currentState.get()

    private fun setState(newState: State) {
        val old = currentState.getAndSet(newState)
        if (old != newState) {
            listeners.forEach {
                try {
                    it.onReconnectionStateChanged(newState)
                } catch (_: Exception) {}
            }
        }
    }

    /**
     * Starts monitoring connectivity and manages automatic reconnection.
     */
    @Synchronized
    fun start(relayBaseUrl: String) {
        if (isStarted.getAndSet(true)) return
        this.vpsBaseUrl = relayBaseUrl

        networkStateProvider.registerCallback(
            onAvailable = { handleNetworkAvailable() },
            onLost = { handleNetworkLost() }
        )

        if (!networkStateProvider.isNetworkAvailable()) {
            setState(State.WaitingForNetwork)
        } else {
            attemptReconnect(immediate = true)
        }
    }

    /**
     * Stops reconnection manager and cancels active tasks.
     */
    @Synchronized
    fun stop() {
        if (!isStarted.getAndSet(false)) return
        cancelScheduledRetry()
        ownedScheduler?.shutdownNow()
        ownedScheduler = null
        networkStateProvider.unregisterCallback()
        setState(State.Idle)
    }

    /**
     * Called when the active transport connection is lost.
     */
    fun onConnectionLost(cause: Throwable? = null) {
        if (!isStarted.get()) return

        if (!networkStateProvider.isNetworkAvailable()) {
            setState(State.WaitingForNetwork)
            return
        }

        attemptReconnect(immediate = false)
    }

    /**
     * Called when transport connection is successfully established.
     */
    fun onConnectionEstablished(sessionToken: String) {
        consecutiveFailures.set(0)
        cancelScheduledRetry()
        setState(State.Connected(sessionToken))
    }

    /**
     * Calculates exponential backoff with full jitter to avoid reconnect storms.
     * AWS Full Jitter Formula: Random(0, min(maxDelay, baseDelay * factor^(attempt-1)))
     */
    fun calculateBackoffDelay(attempt: Int): Long {
        if (attempt <= 0) return 0L

        val shift = min(attempt - 1, 30)
        val calculatedMax = (config.baseDelayMillis * (1L shl shift)).coerceAtMost(config.maxDelayMillis)
        if (calculatedMax <= 0L) return 0L

        // Full jitter ensures evenly distributed spread across [calculatedMax/2, calculatedMax]
        // to prevent synchronized thundering herds against VPS
        val minJitter = calculatedMax / 2
        val range = calculatedMax - minJitter
        val jitter = if (range > 0) random.nextInt(range.toInt()).toLong() else 0L
        return minJitter + jitter
    }

    private fun handleNetworkAvailable() {
        if (!isStarted.get()) return
        // Network restored (e.g. airplane mode toggled off or Wi-Fi connected)
        // Trigger immediate reconnection without waiting for long backoff
        consecutiveFailures.set(0)
        attemptReconnect(immediate = true)
    }

    private fun handleNetworkLost() {
        if (!isStarted.get()) return
        cancelScheduledRetry()
        setState(State.WaitingForNetwork)
    }

    private fun cancelScheduledRetry() {
        scheduledTask?.cancel(true)
        scheduledTask = null
    }

    @Synchronized
    private fun attemptReconnect(immediate: Boolean) {
        if (!isStarted.get()) return
        cancelScheduledRetry()

        if (!networkStateProvider.isNetworkAvailable()) {
            setState(State.WaitingForNetwork)
            return
        }

        val attempt = consecutiveFailures.incrementAndGet()
        val delayMillis = if (immediate) 0L else calculateBackoffDelay(attempt)

        if (delayMillis > 0L) {
            val nextAttemptAt = System.currentTimeMillis() + delayMillis
            setState(State.BackingOff(attempt, delayMillis, nextAttemptAt))
        }
        scheduledTask = getOrCreateScheduler().schedule(
            { executeReconnect(attempt) },
            delayMillis,
            TimeUnit.MILLISECONDS
        )
    }

    private fun executeReconnect(attempt: Int) {
        if (!isStarted.get() || !networkStateProvider.isNetworkAvailable()) {
            setState(State.WaitingForNetwork)
            return
        }

        val resumptionToken = secureStorage.getResumptionToken()
        setState(State.Connecting(attempt, isResuming = resumptionToken != null))

        // Step 1: Attempt session resumption (VPS-6) if token held
        if (resumptionToken != null) {
            val deviceId = identityManager.getDeviceId()
            val resumeResult = authClient.resumeSession(vpsBaseUrl, deviceId, resumptionToken)
            if (resumeResult.isSuccess) {
                val sessionToken = resumeResult.getOrThrow()
                consecutiveFailures.set(0)
                setState(State.Connected(sessionToken))
                listeners.forEach {
                    try {
                        it.onReconnectionSucceeded(sessionToken, wasResumed = true)
                    } catch (_: Exception) {}
                }
                return
            }
            // Resumption failed (e.g. token expired, 401) -> Fall through to full re-auth
        }

        // Step 2: Fall back to full cryptographic challenge-response authentication (AND-6)
        val authResult = authClient.authenticate(vpsBaseUrl, identityManager, keyManager)
        if (authResult.isSuccess) {
            val sessionToken = authResult.getOrThrow()
            consecutiveFailures.set(0)
            setState(State.Connected(sessionToken))
            listeners.forEach {
                try {
                    it.onReconnectionSucceeded(sessionToken, wasResumed = false)
                } catch (_: Exception) {}
            }
        } else {
            val error = authResult.exceptionOrNull() ?: Exception("Unknown authentication failure")
            listeners.forEach {
                try {
                    it.onReconnectionFailed(error)
                } catch (_: Exception) {}
            }

            // Schedule next attempt with jittered backoff
            if (isStarted.get()) {
                attemptReconnect(immediate = false)
            } else {
                setState(State.Failed(error))
            }
        }
    }
}
