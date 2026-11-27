package com.phonelink.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.phonelink.files.FileOperationHandler
import com.phonelink.files.StorageAccessLayer
import com.phonelink.storage.SecureStorage
import com.phonelink.transport.NetworkTransport
import com.phonelink.transport.RelayUrlHelper
import com.phonelink.ui.MainActivity

/**
 * AND-7: Android Background Execution & Foreground Service.
 *
 * Maintains the secure network connection in the background using a compliant
 * foreground service with a persistent, user-visible, non-suppressible notification.
 *
 * Security Invariant (ARCH-4 / AND-7):
 * The notification is the user's unambiguous guarantee that the connection is active.
 * It is marked ongoing and cannot be dismissed while the service runs.
 */
class ConnectionForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "phonelink_connection_channel"
        const val MEDIA_PROMPT_CHANNEL_ID = "phonelink_media_prompts"
        const val NOTIFICATION_ID = 1001
        const val MEDIA_PROMPT_NOTIFICATION_ID = 1004

        const val ACTION_START = "com.phonelink.service.ACTION_START"
        const val ACTION_STOP = "com.phonelink.service.ACTION_STOP"
        const val ACTION_STOP_CAMERA = "com.phonelink.service.ACTION_STOP_CAMERA"
        const val ACTION_STOP_MIC = "com.phonelink.service.ACTION_STOP_MIC"
        const val ACTION_RELOAD_CONFIG = "com.phonelink.service.ACTION_RELOAD_CONFIG"

        @Volatile
        var isServiceRunningGlobal: Boolean = false
            internal set

        @Volatile
        var lastRelayStatusText: String? = null
            internal set

        @Volatile
        var lastPeerOnline: Boolean? = null
            internal set

        internal fun computeForegroundNotificationText(cameraActive: Boolean, micActive: Boolean): String {
            return when {
                cameraActive && micActive -> "PhoneLink: Camera & Microphone streaming"
                cameraActive -> "PhoneLink: Camera streaming active"
                micActive -> "PhoneLink: Microphone streaming active"
                else -> "Connected to VPS relay"
            }
        }

        internal fun computeForegroundServiceTypes(cameraActive: Boolean, micActive: Boolean): Int {
            var flags = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            if (cameraActive) {
                flags = flags or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
            }
            if (micActive) {
                flags = flags or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            }
            return flags
        }

        @Volatile
        var peerStatusListener: ((peerId: String, isOnline: Boolean) -> Unit)? = null

        @Volatile
        var relayStatusListener: ((statusText: String, isConnected: Boolean) -> Unit)? = null

        fun start(context: Context) {
            val intent = Intent(context, ConnectionForegroundService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun reloadConfig(context: Context) {
            if (!isServiceRunningGlobal) {
                start(context)
                return
            }
            try {
                context.startService(Intent(context, ConnectionForegroundService::class.java).apply {
                    action = ACTION_RELOAD_CONFIG
                })
            } catch (_: Exception) {
                try { start(context) } catch (_: Exception) {}
            }
        }

        fun stopCamera(context: Context) {
            if (!isServiceRunningGlobal) return
            try {
                context.startService(Intent(context, ConnectionForegroundService::class.java).apply {
                    action = ACTION_STOP_CAMERA
                })
            } catch (_: Exception) {}
        }

        fun stopMic(context: Context) {
            if (!isServiceRunningGlobal) return
            try {
                context.startService(Intent(context, ConnectionForegroundService::class.java).apply {
                    action = ACTION_STOP_MIC
                })
            } catch (_: Exception) {}
        }

        fun clearMediaPromptNotification(context: Context) {
            try {
                val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
                nm?.cancel(MEDIA_PROMPT_NOTIFICATION_ID)
            } catch (_: Exception) {}
        }

        fun stop(context: Context) {
            try {
                context.stopService(Intent(context, ConnectionForegroundService::class.java))
            } catch (_: Exception) {}
        }
    }

    private var transport: NetworkTransport? = null
    private var reconnectionManager: com.phonelink.transport.ReconnectionManager? = null
    private lateinit var secureStorage: SecureStorage
    private lateinit var storageAccessLayer: StorageAccessLayer
    private lateinit var fileOperationHandler: FileOperationHandler
    private lateinit var remoteActionRegistry: com.phonelink.actions.RemoteActionRegistry
    private lateinit var cameraAuthGate: com.phonelink.camera.CameraAuthorizationGate
    private lateinit var cameraCaptureModule: com.phonelink.camera.CameraCaptureModule
    private lateinit var micAuthGate: com.phonelink.mic.MicAuthorizationGate
    private lateinit var micCaptureModule: com.phonelink.mic.MicCaptureModule
    private var replayFilter = com.phonelink.security.ReplayProtectionFilter()
    private var peerSession: com.phonelink.crypto.E2EPeerSession? = null
    @Volatile private var isRunning = false
    @Volatile private var cameraCaptureActive = false
    @Volatile private var micCaptureActive = false
    @Volatile private var cameraForegroundReady = true
    @Volatile private var micForegroundReady = true
    @Volatile private var blockedMediaPrompt: String? = null
    private val mediaLockSync = Any()
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    override fun onCreate() {
        super.onCreate()
        secureStorage = SecureStorage.fromContext(this)
        storageAccessLayer = StorageAccessLayer.fromContext(this)
        fileOperationHandler = FileOperationHandler(storageAccessLayer)
        remoteActionRegistry = com.phonelink.actions.RemoteActionRegistry.fromContext(this)
        cameraAuthGate = com.phonelink.camera.CameraAuthorizationGate.fromContext(this, secureStorage)
        micAuthGate = com.phonelink.mic.MicAuthorizationGate.fromContext(this, secureStorage)

        val serviceController = object : com.phonelink.camera.CameraCaptureModule.ForegroundServiceController {
            override fun isCameraForegroundReady(): Boolean = cameraForegroundReady

            override fun onCameraCaptureStarted() {
                cameraCaptureActive = true
                blockedMediaPrompt = null
                cameraForegroundReady = applyActiveForegroundCapabilities(triggerType = "camera")
                if (!cameraForegroundReady) {
                    cameraCaptureActive = false
                    blockedMediaPrompt = "Camera blocked in background"
                    postMediaPromptNotification(
                        title = "PhoneLink: Camera Blocked",
                        text = "Unlock your phone & open PhoneLink on screen before starting remote camera."
                    )
                }
                updateMediaPowerLocks(cameraCaptureActive || micCaptureActive)
            }

            override fun onCameraCaptureStopped() {
                val wasBlocked = !cameraForegroundReady
                cameraCaptureActive = false
                cameraForegroundReady = true
                updateMediaPowerLocks(cameraCaptureActive || micCaptureActive)
                if (!wasBlocked) {
                    applyActiveForegroundCapabilities(triggerType = null)
                }
            }
        }

        val micServiceController = object : com.phonelink.mic.MicCaptureModule.ForegroundServiceController {
            override fun isMicForegroundReady(): Boolean = micForegroundReady

            override fun onMicCaptureStarted() {
                micCaptureActive = true
                blockedMediaPrompt = null
                micForegroundReady = applyActiveForegroundCapabilities(triggerType = "microphone")
                if (!micForegroundReady) {
                    micCaptureActive = false
                    blockedMediaPrompt = "Microphone blocked in background"
                    postMediaPromptNotification(
                        title = "PhoneLink: Microphone Blocked",
                        text = "Unlock your phone & open PhoneLink on screen before starting remote microphone."
                    )
                }
                updateMediaPowerLocks(cameraCaptureActive || micCaptureActive)
            }

            override fun onMicCaptureStopped() {
                val wasBlocked = !micForegroundReady
                micCaptureActive = false
                micForegroundReady = true
                updateMediaPowerLocks(cameraCaptureActive || micCaptureActive)
                if (!wasBlocked) {
                    applyActiveForegroundCapabilities(triggerType = null)
                }
            }
        }

        cameraCaptureModule = com.phonelink.camera.CameraCaptureModule(
            cameraAuthGate = cameraAuthGate,
            cameraSource = com.phonelink.camera.AndroidCameraSource(this),
            serviceController = serviceController
        )

        micCaptureModule = com.phonelink.mic.MicCaptureModule(
            micAuthGate = micAuthGate,
            micSource = com.phonelink.mic.AndroidMicSource(this),
            serviceController = micServiceController
        )

        createNotificationChannel()
    }

    @Synchronized
    private fun applyActiveForegroundCapabilities(triggerType: String?): Boolean {
        val text = computeForegroundNotificationText(cameraCaptureActive, micCaptureActive)
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val flags = computeForegroundServiceTypes(cameraCaptureActive, micCaptureActive)
            return try {
                startForeground(NOTIFICATION_ID, notification, flags)
                true
            } catch (_: SecurityException) {
                val permLabel = triggerType ?: "media"
                updateNotification("PhoneLink: $permLabel permission required for stream")
                false
            } catch (_: IllegalStateException) {
                val targetLabel = triggerType ?: "media"
                updateNotification("PhoneLink: Unlock & open app to stream $targetLabel")
                false
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val qFlags = if (cameraCaptureActive || micCaptureActive) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            } else {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            }
            try {
                startForeground(NOTIFICATION_ID, notification, qFlags)
            } catch (_: Exception) {
                updateNotification(text)
            }
            return true
        } else {
            updateNotification(text)
            return true
        }
    }

    private fun stopActiveMediaCapture(reason: String) {
        if (::cameraCaptureModule.isInitialized && cameraCaptureModule.isCapturing()) {
            try {
                cameraCaptureModule.stopCapture(cameraCaptureModule.getActiveSessionId() ?: "disconnect", reason)
            } catch (_: Exception) {}
        }
        if (::micCaptureModule.isInitialized && micCaptureModule.isCapturing()) {
            try {
                micCaptureModule.stopCapture(micCaptureModule.getActiveSessionId() ?: "disconnect", reason)
            } catch (_: Exception) {}
        }
        updateMediaPowerLocks(false)
    }

    private fun updateMediaPowerLocks(needLocks: Boolean) = synchronized(mediaLockSync) {
        if (needLocks) {
            try {
                if (wakeLock == null) {
                    val pm = getSystemService(Context.POWER_SERVICE) as? PowerManager
                    wakeLock = pm?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "PhoneLink::MediaWakeLock")?.apply {
                        setReferenceCounted(false)
                    }
                }
                if (wakeLock?.isHeld == false) {
                    wakeLock?.acquire(10 * 60 * 1000L)
                }
            } catch (_: Exception) {}
            try {
                if (wifiLock == null) {
                    val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                    @Suppress("DEPRECATION")
                    val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                    } else {
                        WifiManager.WIFI_MODE_FULL_HIGH_PERF
                    }
                    wifiLock = wm?.createWifiLock(mode, "PhoneLink::MediaWifiLock")?.apply {
                        setReferenceCounted(false)
                    }
                }
                if (wifiLock?.isHeld == false) {
                    wifiLock?.acquire()
                }
            } catch (_: Exception) {}
        } else {
            try {
                if (wakeLock?.isHeld == true) wakeLock?.release()
            } catch (_: Exception) {}
            try {
                if (wifiLock?.isHeld == true) wifiLock?.release()
            } catch (_: Exception) {}
        }
    }

    private fun postMediaPromptNotification(title: String, text: String) {
        try {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
            val launchIntent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val pendingIntent = PendingIntent.getActivity(
                this,
                1,
                launchIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            val notification = NotificationCompat.Builder(this, MEDIA_PROMPT_CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .build()
            nm.notify(MEDIA_PROMPT_NOTIFICATION_ID, notification)
        } catch (_: Exception) {}
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForegroundService(stopSelfAfter = true)
                return START_NOT_STICKY
            }
            ACTION_STOP_CAMERA -> {
                blockedMediaPrompt = null
                if (::cameraCaptureModule.isInitialized && cameraCaptureModule.isCapturing()) {
                    val sid = cameraCaptureModule.getActiveSessionId() ?: "owner_disabled"
                    val stopResp = cameraCaptureModule.stopCapture(sid, "owner_disabled")
                    peerSession?.sendApplicationMessage(cameraCaptureModule.serializeCameraStopResponse(stopResp))
                }
            }
            ACTION_STOP_MIC -> {
                blockedMediaPrompt = null
                if (::micCaptureModule.isInitialized && micCaptureModule.isCapturing()) {
                    val sid = micCaptureModule.getActiveSessionId() ?: "owner_disabled"
                    val stopResp = micCaptureModule.stopCapture(sid, "owner_disabled")
                    peerSession?.sendApplicationMessage(micCaptureModule.serializeMicStopResponse(stopResp))
                }
            }
            ACTION_RELOAD_CONFIG -> {
                stopForegroundService(stopSelfAfter = false)
                startForegroundService()
            }
            ACTION_START, null -> {
                startForegroundService()
            }
        }
        return START_STICKY
    }

    private fun startForegroundService() {
        val initialNotification = buildNotification("Starting PhoneLink service...")
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, initialNotification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIFICATION_ID, initialNotification)
            }
        } catch (_: Throwable) {
            stopSelf()
            return
        }

        if (isRunning) return

        val relayUrl = secureStorage.getRelayUrl()
        val vpsBaseHttpUrl = RelayUrlHelper.normalizeHttpBaseUrl(relayUrl)
        if (vpsBaseHttpUrl.isEmpty()) {
            try {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } catch (_: Exception) {}
            stopSelf()
            return
        }

        blockedMediaPrompt = null
        isRunning = true
        isServiceRunningGlobal = true

        val currentTransport = NetworkTransport().also { transport = it }
        val keyMgr = com.phonelink.crypto.KeyManager.fromContext(this, secureStorage)
        val identityMgr = com.phonelink.identity.DeviceIdentityManager.fromContext(this, keyMgr)
        val serviceAuthClient = com.phonelink.auth.AuthClient(secureStorage = secureStorage)

        peerSession = com.phonelink.crypto.E2EPeerSession(
            sendFunction = { bytes -> currentTransport.send(bytes) },
            messageDispatcher = { plaintext, sendAppMsg ->
                val validation = replayFilter.validateMessage(plaintext)
                if (validation is com.phonelink.security.ReplayProtectionFilter.ValidationResult.Rejected) {
                    replayFilter.buildErrorResponse(validation.status, validation.message)
                } else {
                    val backpressuredSend: (ByteArray) -> Boolean = { payload ->
                        if (Thread.currentThread().name.startsWith("PhoneLink-FileTransfer")) {
                            var waited = 0
                            while (currentTransport.isQueueBackpressured() && isRunning && waited < 100) {
                                try {
                                    Thread.sleep(20)
                                } catch (_: InterruptedException) {
                                    break
                                }
                                waited++
                            }
                        }
                        sendAppMsg(payload)
                    }
                    cameraCaptureModule.processApplicationMessage(plaintext, sendAppMsg)
                        ?: micCaptureModule.processApplicationMessage(plaintext, sendAppMsg)
                        ?: fileOperationHandler.processApplicationMessage(plaintext, backpressuredSend)
                        ?: remoteActionRegistry.processApplicationMessage(plaintext)
                }
            },
            signer = keyMgr.signer,
            peerPublicKeyProvider = {
                val pubB64 = secureStorage.getPairedPublicKey()
                if (!pubB64.isNullOrEmpty()) {
                    try {
                        java.util.Base64.getDecoder().decode(pubB64)
                    } catch (_: Exception) {
                        null
                    }
                } else {
                    null
                }
            },
            requirePeerAuth = true
        )

        // Initialize AND-8 ReconnectionManager with unified identity/signing keypair
        val mgr = com.phonelink.transport.ReconnectionManager(
            authClient = serviceAuthClient,
            secureStorage = secureStorage,
            identityManager = identityMgr,
            keyManager = keyMgr,
            networkStateProvider = com.phonelink.transport.ReconnectionManager.AndroidNetworkStateProvider(this)
        ).also { reconnectionManager = it }

        mgr.addListener(object : com.phonelink.transport.ReconnectionManager.Listener {
            override fun onReconnectionStateChanged(newState: com.phonelink.transport.ReconnectionManager.State) {
                val statusText = when (newState) {
                    is com.phonelink.transport.ReconnectionManager.State.WaitingForNetwork -> "Waiting for network connectivity..."
                    is com.phonelink.transport.ReconnectionManager.State.BackingOff -> "Reconnecting in ${newState.delayMillis / 1000}s (attempt ${newState.attempt})..."
                    is com.phonelink.transport.ReconnectionManager.State.Connecting -> if (newState.isResuming) "Resuming VPS session..." else "Authenticating with VPS..."
                    is com.phonelink.transport.ReconnectionManager.State.Connected -> "Connected to VPS relay"
                    is com.phonelink.transport.ReconnectionManager.State.Failed -> "Connection failed: ${newState.cause.message}"
                    is com.phonelink.transport.ReconnectionManager.State.Idle -> "Disconnected"
                }
                lastRelayStatusText = statusText
                relayStatusListener?.invoke(statusText, newState is com.phonelink.transport.ReconnectionManager.State.Connected)
                updateNotification(statusText)
            }

            override fun onReconnectionSucceeded(sessionToken: String, wasResumed: Boolean) {
                // Pre-fetch paired peer public key on this background thread before opening WebSocket
                if (secureStorage.getPairedPublicKey().isNullOrEmpty()) {
                    try {
                        serviceAuthClient.getDeviceStatus(vpsBaseHttpUrl, sessionToken)
                    } catch (_: Exception) {}
                }
                val wsUrl = RelayUrlHelper.toWebSocketUrl(relayUrl, sessionToken)
                currentTransport.connect(wsUrl)
            }
        })

        currentTransport.addListener(object : NetworkTransport.Listener {
            override fun onStateChanged(newState: NetworkTransport.ConnectionState) {
                when (newState) {
                    is NetworkTransport.ConnectionState.Connected -> {
                        lastRelayStatusText = "Connected to VPS relay"
                        relayStatusListener?.invoke("Connected to VPS relay", true)
                        updateNotification("Connected to VPS relay")
                    }
                    is NetworkTransport.ConnectionState.Disconnected -> {
                        stopActiveMediaCapture("transport_disconnected")
                        replayFilter.reset()
                        peerSession?.reset()
                        lastPeerOnline = false
                        if (isRunning) {
                            lastRelayStatusText = "Disconnected. Reconnecting..."
                            relayStatusListener?.invoke("Disconnected. Reconnecting...", false)
                            updateNotification("Disconnected. Reconnecting...")
                            reconnectionManager?.onConnectionLost()
                        }
                    }
                    is NetworkTransport.ConnectionState.Error -> {
                        stopActiveMediaCapture("transport_error")
                        replayFilter.reset()
                        peerSession?.reset()
                        lastPeerOnline = false
                        if (isRunning) {
                            val msg = "Connection error: ${newState.cause.message}"
                            lastRelayStatusText = msg
                            relayStatusListener?.invoke(msg, false)
                            updateNotification(msg)
                            reconnectionManager?.onConnectionLost(newState.cause)
                        }
                    }
                    else -> {}
                }
            }

            override fun onMessageReceived(text: String) {
                if (handleControlMessage(text)) return
                peerSession?.handleIncomingMessage(text.toByteArray(Charsets.UTF_8))
            }

            override fun onMessageReceived(bytes: ByteArray) {
                val handled = try {
                    val text = String(bytes, Charsets.UTF_8)
                    handleControlMessage(text)
                } catch (_: Exception) {
                    false
                }
                if (!handled) {
                    peerSession?.handleIncomingMessage(bytes)
                }
            }
        })

        // Start ReconnectionManager (dispatches asynchronously on background scheduler)
        mgr.start(vpsBaseHttpUrl)
    }

    internal fun handleControlMessage(text: String): Boolean {
        return try {
            val trimmed = text.trim()
            if (!trimmed.startsWith("{")) return false
            val json = org.json.JSONObject(trimmed)
            if (json.optString("type") == "PEER_STATUS") {
                val isOnline = json.optBoolean("is_online", false)
                val peerId = json.optString("peer_device_id", "")
                lastPeerOnline = isOnline
                val statusText = if (isOnline) {
                    "Connected to VPS • Mac is ONLINE"
                } else {
                    stopActiveMediaCapture("peer_offline")
                    "Connected to VPS • Paired Mac is OFFLINE"
                }
                lastRelayStatusText = statusText
                peerStatusListener?.invoke(peerId, isOnline)
                relayStatusListener?.invoke(statusText, true)
                try {
                    updateNotification(statusText)
                } catch (_: Exception) {}
                return true
            }
            if (json.has("error") && !json.has("ciphertext")) {
                val errMsg = json.optString("error", "relay error")
                try {
                    updateNotification("Relay error: $errMsg")
                } catch (_: Exception) {}
                return true
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun stopForegroundService(stopSelfAfter: Boolean) {
        if (!isRunning && reconnectionManager == null && transport == null) {
            isServiceRunningGlobal = false
            updateMediaPowerLocks(false)
            if (stopSelfAfter) stopSelf()
            return
        }
        isRunning = false
        isServiceRunningGlobal = false
        lastPeerOnline = null
        lastRelayStatusText = "Disconnected"
        blockedMediaPrompt = null
        try {
            if (::cameraCaptureModule.isInitialized) {
                cameraCaptureModule.shutdown()
            }
            if (::micCaptureModule.isInitialized) {
                micCaptureModule.shutdown()
            }
            if (::fileOperationHandler.isInitialized) {
                fileOperationHandler.shutdown()
            }
            if (::remoteActionRegistry.isInitialized) {
                remoteActionRegistry.shutdown()
            }
        } catch (_: Exception) {}
        updateMediaPowerLocks(false)
        reconnectionManager?.stop()
        reconnectionManager = null
        transport?.disconnect()
        transport = null
        replayFilter.reset()
        peerSession?.reset()
        peerSession = null
        relayStatusListener?.invoke("Disconnected", false)
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {}
        if (stopSelfAfter) {
            stopSelf()
        }
    }

    override fun onDestroy() {
        stopForegroundService(stopSelfAfter = false)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PhoneLink Connection Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows real-time connection status to the PhoneLink relay"
                setShowBadge(false)
            }
            val mediaChannel = NotificationChannel(
                MEDIA_PROMPT_CHANNEL_ID,
                "PhoneLink Hardware Prompts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts when Android requires unlocking or opening PhoneLink for camera/mic access"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
            manager?.createNotificationChannel(mediaChannel)
        }
    }

    fun buildNotification(statusText: String): Notification {
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("PhoneLink Active")
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true) // Non-dismissible
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val notification = buildNotification(statusText)
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        manager?.notify(NOTIFICATION_ID, notification)
    }
}
