package com.phonelink.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.phonelink.files.FileOperationHandler
import com.phonelink.files.StorageAccessLayer
import com.phonelink.storage.SecureStorage
import com.phonelink.transport.NetworkTransport
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
        const val NOTIFICATION_ID = 1001

        const val ACTION_START = "com.phonelink.service.ACTION_START"
        const val ACTION_STOP = "com.phonelink.service.ACTION_STOP"

        var peerStatusListener: ((peerId: String, isOnline: Boolean) -> Unit)? = null

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

        fun stop(context: Context) {
            val intent = Intent(context, ConnectionForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
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
    private var replayFilter = com.phonelink.security.ReplayProtectionFilter()
    private var peerSession: com.phonelink.crypto.E2EPeerSession? = null
    private var isRunning = false

    override fun onCreate() {
        super.onCreate()
        secureStorage = SecureStorage.fromContext(this)
        storageAccessLayer = StorageAccessLayer.fromContext(this)
        fileOperationHandler = FileOperationHandler(storageAccessLayer)
        remoteActionRegistry = com.phonelink.actions.RemoteActionRegistry.fromContext(this)
        cameraAuthGate = com.phonelink.camera.CameraAuthorizationGate.fromContext(this, secureStorage)

        val serviceController = object : com.phonelink.camera.CameraCaptureModule.ForegroundServiceController {
            override fun onCameraCaptureStarted() {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val cameraServiceType = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA
                    val notification = buildNotification("PhoneLink: Camera streaming active")
                    startForeground(NOTIFICATION_ID, notification, cameraServiceType)
                } else {
                    updateNotification("PhoneLink: Camera streaming active")
                }
            }

            override fun onCameraCaptureStopped() {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val defaultServiceType = ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    val notification = buildNotification("Connected to VPS relay")
                    startForeground(NOTIFICATION_ID, notification, defaultServiceType)
                } else {
                    updateNotification("Connected to VPS relay")
                }
            }
        }

        cameraCaptureModule = com.phonelink.camera.CameraCaptureModule(
            cameraAuthGate = cameraAuthGate,
            cameraSource = com.phonelink.camera.AndroidCameraSource(this),
            serviceController = serviceController
        )

        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForegroundService()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                startForegroundService()
            }
        }
        return START_STICKY
    }

    private fun startForegroundService() {
        if (isRunning) return
        isRunning = true

        val initialNotification = buildNotification("Starting PhoneLink service...")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val serviceType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            } else {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            }
            startForeground(NOTIFICATION_ID, initialNotification, serviceType)
        } else {
            startForeground(NOTIFICATION_ID, initialNotification)
        }

        // Initialize and connect transport
        val relayUrl = secureStorage.getRelayUrl()
        val currentTransport = NetworkTransport().also { transport = it }

        peerSession = com.phonelink.crypto.E2EPeerSession(
            sendFunction = { bytes -> currentTransport.send(bytes) },
            messageDispatcher = { plaintext, sendAppMsg ->
                val validation = replayFilter.validateMessage(plaintext)
                if (validation is com.phonelink.security.ReplayProtectionFilter.ValidationResult.Rejected) {
                    replayFilter.buildErrorResponse(validation.status, validation.message)
                } else {
                    cameraCaptureModule.processApplicationMessage(plaintext, sendAppMsg)
                        ?: fileOperationHandler.processApplicationMessage(plaintext, sendAppMsg)
                        ?: remoteActionRegistry.processApplicationMessage(plaintext)
                }
            }
        )

        // Initialize AND-8 ReconnectionManager
        val vpsBaseHttpUrl = relayUrl.substringBefore("/ws/").replace("wss://", "https://").replace("ws://", "http://")
        val identityMgr = com.phonelink.identity.DeviceIdentityManager.fromContext(this)
        val keyMgr = try {
            com.phonelink.crypto.KeyManager(com.phonelink.crypto.AndroidKeyStoreSigner())
        } catch (_: Throwable) {
            com.phonelink.crypto.KeyManager.createSoftware()
        }

        val mgr = com.phonelink.transport.ReconnectionManager(
            authClient = com.phonelink.auth.AuthClient(secureStorage = secureStorage),
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
                updateNotification(statusText)
            }

            override fun onReconnectionSucceeded(sessionToken: String, wasResumed: Boolean) {
                val wsUrl = if (relayUrl.contains("?")) "$relayUrl&token=$sessionToken" else "$relayUrl?token=$sessionToken"
                currentTransport.connect(wsUrl)
            }
        })

        currentTransport.addListener(object : NetworkTransport.Listener {
            override fun onStateChanged(newState: NetworkTransport.ConnectionState) {
                when (newState) {
                    is NetworkTransport.ConnectionState.Connected -> {
                        updateNotification("Connected to VPS relay")
                    }
                    is NetworkTransport.ConnectionState.Disconnected -> {
                        cameraCaptureModule.stopCapture("disconnected", "transport_disconnected")
                        replayFilter.reset()
                        peerSession?.reset()
                        updateNotification("Disconnected. Reconnecting...")
                        reconnectionManager?.onConnectionLost()
                    }
                    is NetworkTransport.ConnectionState.Error -> {
                        cameraCaptureModule.stopCapture("error", "transport_error")
                        updateNotification("Connection error: ${newState.cause.message}")
                        reconnectionManager?.onConnectionLost(newState.cause)
                    }
                    else -> {}
                }
            }

            override fun onMessageReceived(text: String) {
                handleControlMessage(text)
                peerSession?.handleIncomingMessage(text.toByteArray(Charsets.UTF_8))
            }

            override fun onMessageReceived(bytes: ByteArray) {
                try {
                    val text = String(bytes, Charsets.UTF_8)
                    handleControlMessage(text)
                } catch (_: Exception) {}
                peerSession?.handleIncomingMessage(bytes)
            }
        })

        // Start ReconnectionManager (handles initial connect and subsequent resilience)
        mgr.start(vpsBaseHttpUrl)
    }

    internal fun handleControlMessage(text: String) {
        try {
            val json = org.json.JSONObject(text)
            if (json.optString("type") == "PEER_STATUS") {
                val isOnline = json.optBoolean("is_online", false)
                val peerId = json.optString("peer_device_id", "")
                val statusText = if (isOnline) {
                    "Connected to VPS • Mac is ONLINE"
                } else {
                    "Connected to VPS • Paired Mac is OFFLINE"
                }
                peerStatusListener?.invoke(peerId, isOnline)
                try {
                    updateNotification(statusText)
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
    }

    private fun stopForegroundService() {
        isRunning = false
        try {
            cameraCaptureModule.stopCapture("service_stopped", "service_stopped")
        } catch (_: Exception) {}
        reconnectionManager?.stop()
        reconnectionManager = null
        transport?.disconnect()
        transport = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopForegroundService()
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
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
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
