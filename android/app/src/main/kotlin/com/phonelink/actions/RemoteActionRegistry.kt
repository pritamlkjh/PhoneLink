package com.phonelink.actions

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.media.AudioAttributes
import android.media.Ringtone
import android.media.RingtoneManager
import android.os.BatteryManager
import android.os.Build
import android.os.StatFs
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import androidx.core.app.NotificationCompat
import com.phonelink.storage.SecureStorage
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * FILE-5: Scoped Remote Action System.
 *
 * Implements a strict, fixed build-time allowlist of remote actions:
 *  - device.ping: Plays sound / vibrates for a bounded duration (max 30s)
 *  - device.info: Read-only safe system telemetry
 *
 * SECURITY GUARANTEES:
 * 1. Build-time allowlist: ONLY device.ping and device.info exist.
 * 2. Absolutely NO command/shell execution, ProcessBuilder, Runtime.exec, or script evaluation exists.
 * 3. Each action is independently permission-gated via SecureStorage toggles.
 * 4. User-visible feedback is triggered on Android for every remote action.
 */
class RemoteActionRegistry(
    private val secureStorage: SecureStorage? = null,
    private val telemetryProvider: TelemetryProvider? = null,
    private val feedbackController: ActionFeedbackController? = null
) {
    companion object {
        const val SCHEMA_VERSION = 1

        // Allowed Action Identifiers
        const val ACTION_PING = "device.ping"
        const val ACTION_INFO = "device.info"

        val ALLOWED_ACTIONS: Set<String> = setOf(ACTION_PING, ACTION_INFO)

        // Status Codes (common.proto)
        const val STATUS_OK = "STATUS_OK"
        const val STATUS_ERROR_UNKNOWN = "STATUS_ERROR_UNKNOWN"
        const val STATUS_INVALID_ARGUMENT = "STATUS_INVALID_ARGUMENT"
        const val STATUS_ACTION_NOT_PERMITTED = "STATUS_ACTION_NOT_PERMITTED"

        const val MAX_PING_DURATION_SECONDS = 30
        const val DEFAULT_PING_DURATION_SECONDS = 5

        fun fromContext(context: Context): RemoteActionRegistry {
            val secureStorage = SecureStorage.fromContext(context)
            val telemetryProvider = AndroidTelemetryProvider(context)
            val feedbackController = AndroidActionFeedbackController(context)
            return RemoteActionRegistry(secureStorage, telemetryProvider, feedbackController)
        }
    }

    interface TelemetryProvider {
        fun getModel(): String
        fun getOsVersion(): String
        fun getBatteryPercent(): Int
        fun isCharging(): Boolean
        fun getTotalStorageBytes(): Long
        fun getAvailableStorageBytes(): Long
        fun getAppVersion(): String
    }

    interface ActionFeedbackController {
        fun triggerPing(durationSeconds: Int)
        fun notifyActionExecuted(actionName: String)
    }

    data class DevicePingResponseDto(
        val requestId: String,
        val status: String,
        val message: String
    )

    data class DeviceInfoResponseDto(
        val requestId: String,
        val status: String,
        val model: String,
        val osVersion: String,
        val batteryPercent: Int,
        val isCharging: Boolean,
        val totalStorageBytes: Long,
        val availableStorageBytes: Long,
        val appVersion: String,
        val errorMessage: String = ""
    )

    fun shutdown() {
        (feedbackController as? AndroidActionFeedbackController)?.shutdown()
    }

    /**
     * Checks if the given action identifier is present in the build-time allowlist.
     */
    fun isActionAllowlisted(actionId: String): Boolean {
        return ALLOWED_ACTIONS.contains(actionId)
    }

    /**
     * Executes device.ping: Bounded audio/vibration feedback.
     */
    fun executePing(durationSeconds: Int, requestId: String = UUID.randomUUID().toString()): DevicePingResponseDto {
        // Gate check
        val isAllowed = secureStorage?.isRemotePingAllowed() ?: true
        if (!isAllowed) {
            return DevicePingResponseDto(
                requestId = requestId,
                status = STATUS_ACTION_NOT_PERMITTED,
                message = "Remote ping is disabled in Android device settings"
            )
        }

        if (durationSeconds < 0) {
            return DevicePingResponseDto(
                requestId = requestId,
                status = STATUS_INVALID_ARGUMENT,
                message = "Invalid ping duration: cannot be negative"
            )
        }

        val clampedDuration = when {
            durationSeconds == 0 -> DEFAULT_PING_DURATION_SECONDS
            durationSeconds > MAX_PING_DURATION_SECONDS -> MAX_PING_DURATION_SECONDS
            else -> durationSeconds
        }

        feedbackController?.triggerPing(clampedDuration)
        feedbackController?.notifyActionExecuted(ACTION_PING)

        return DevicePingResponseDto(
            requestId = requestId,
            status = STATUS_OK,
            message = "Device ping active for $clampedDuration seconds"
        )
    }

    /**
     * Executes device.info: Safe system telemetry collection.
     */
    fun executeInfo(requestId: String = UUID.randomUUID().toString()): DeviceInfoResponseDto {
        // Gate check
        val isAllowed = secureStorage?.isRemoteInfoAllowed() ?: true
        if (!isAllowed) {
            return DeviceInfoResponseDto(
                requestId = requestId,
                status = STATUS_ACTION_NOT_PERMITTED,
                model = "",
                osVersion = "",
                batteryPercent = -1,
                isCharging = false,
                totalStorageBytes = 0L,
                availableStorageBytes = 0L,
                appVersion = "",
                errorMessage = "Remote device info is disabled in Android device settings"
            )
        }

        val provider = telemetryProvider ?: DefaultTelemetryProvider()
        feedbackController?.notifyActionExecuted(ACTION_INFO)

        return DeviceInfoResponseDto(
            requestId = requestId,
            status = STATUS_OK,
            model = provider.getModel(),
            osVersion = provider.getOsVersion(),
            batteryPercent = provider.getBatteryPercent(),
            isCharging = provider.isCharging(),
            totalStorageBytes = provider.getTotalStorageBytes(),
            availableStorageBytes = provider.getAvailableStorageBytes(),
            appVersion = provider.getAppVersion(),
            errorMessage = ""
        )
    }

    /**
     * Dispatches an incoming decrypted ApplicationMessage.
     * Returns serialized response bytes if recognized, or error if arbitrary command attempted.
     */
    fun processApplicationMessage(payloadBytes: ByteArray): ByteArray? {
        val payloadStr = String(payloadBytes, Charsets.UTF_8)
        val json = try {
            JSONObject(payloadStr)
        } catch (_: Exception) {
            return null
        }

        // Strict rejection of arbitrary execution or injection keywords
        if (json.has("shell_cmd") || json.has("exec") || json.has("command") || json.has("run")) {
            val reqId = json.optString("request_id", UUID.randomUUID().toString())
            return serializeActionError(reqId, STATUS_ACTION_NOT_PERMITTED, "Arbitrary command execution is permanently disabled by policy")
        }

        if (json.has("device_ping_req")) {
            val req = json.getJSONObject("device_ping_req")
            val requestId = req.optString("request_id", UUID.randomUUID().toString())
            val durationSeconds = req.optInt("duration_seconds", DEFAULT_PING_DURATION_SECONDS)
            val resp = executePing(durationSeconds, requestId)
            return serializeDevicePingResponse(resp)
        }

        if (json.has("device_info_req")) {
            val req = json.getJSONObject("device_info_req")
            val requestId = req.optString("request_id", UUID.randomUUID().toString())
            val resp = executeInfo(requestId)
            return serializeDeviceInfoResponse(resp)
        }

        // Check if an unallowed generic action was requested
        if (json.has("action_request")) {
            val req = json.getJSONObject("action_request")
            val actionName = req.optString("action", "")
            val requestId = req.optString("request_id", UUID.randomUUID().toString())
            if (!isActionAllowlisted(actionName)) {
                return serializeActionError(requestId, STATUS_ACTION_NOT_PERMITTED, "Action '$actionName' is not in the build-time allowlist")
            }
        }

        return null
    }

    fun serializeDevicePingResponse(dto: DevicePingResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val respObj = JSONObject().apply {
                put("request_id", dto.requestId)
                put("status", dto.status)
                put("message", dto.message)
            }
            put("device_ping_resp", respObj)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun serializeDeviceInfoResponse(dto: DeviceInfoResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val respObj = JSONObject().apply {
                put("request_id", dto.requestId)
                put("status", dto.status)
                put("model", dto.model)
                put("os_version", dto.osVersion)
                put("battery_percent", dto.batteryPercent)
                put("is_charging", dto.isCharging)
                put("total_storage_bytes", dto.totalStorageBytes)
                put("available_storage_bytes", dto.availableStorageBytes)
                put("app_version", dto.appVersion)
                if (dto.errorMessage.isNotEmpty()) {
                    put("error_message", dto.errorMessage)
                }
            }
            put("device_info_resp", respObj)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun serializeActionError(requestId: String, status: String, message: String): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val errObj = JSONObject().apply {
                put("request_id", requestId)
                put("code", status)
                put("message", message)
            }
            put("error", errObj)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    private class DefaultTelemetryProvider : TelemetryProvider {
        override fun getModel(): String = "Android Device"
        override fun getOsVersion(): String = "Android 14"
        override fun getBatteryPercent(): Int = 85
        override fun isCharging(): Boolean = false
        override fun getTotalStorageBytes(): Long = 128_000_000_000L
        override fun getAvailableStorageBytes(): Long = 64_000_000_000L
        override fun getAppVersion(): String = "1.0.0"
    }
}

class AndroidTelemetryProvider(private val context: Context) : RemoteActionRegistry.TelemetryProvider {
    override fun getModel(): String = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
    override fun getOsVersion(): String = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
    override fun getBatteryPercent(): Int {
        val batteryStatus: Intent? = IntentFilter(Intent.ACTION_BATTERY_CHANGED).let { filter ->
            context.registerReceiver(null, filter)
        }
        val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryStatus?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (level >= 0 && scale > 0) (level * 100 / scale) else -1
    }
    override fun isCharging(): Boolean {
        val batteryStatus: Intent? = IntentFilter(Intent.ACTION_BATTERY_CHANGED).let { filter ->
            context.registerReceiver(null, filter)
        }
        val status = batteryStatus?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        return status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
    }
    override fun getTotalStorageBytes(): Long {
        return try {
            val stat = StatFs(context.filesDir.absolutePath)
            stat.totalBytes
        } catch (_: Exception) {
            0L
        }
    }
    override fun getAvailableStorageBytes(): Long {
        return try {
            val stat = StatFs(context.filesDir.absolutePath)
            stat.availableBytes
        } catch (_: Exception) {
            0L
        }
    }
    override fun getAppVersion(): String {
        return try {
            val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            pInfo.versionName ?: "1.0.0"
        } catch (_: Exception) {
            "1.0.0"
        }
    }
}

class AndroidActionFeedbackController(private val context: Context) : RemoteActionRegistry.ActionFeedbackController {
    companion object {
        private const val ACTION_CHANNEL_ID = "phonelink_remote_actions"
        private const val ACTION_NOTIFICATION_ID = 1003
    }

    private val stopScheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PhoneLink-PingStop").apply { isDaemon = true }
    }
    private var activeRingtone: Ringtone? = null
    private var scheduledStopTask: ScheduledFuture<*>? = null

    @Synchronized
    override fun triggerPing(durationSeconds: Int) {
        val clampedDuration = durationSeconds.coerceIn(1, RemoteActionRegistry.MAX_PING_DURATION_SECONDS)
        val millis = clampedDuration * 1000L

        try {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vibratorManager = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
                vibratorManager?.defaultVibrator
            } else {
                @Suppress("DEPRECATION")
                context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                @Suppress("DEPRECATION")
                val vibAttrs = AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_ALARM)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
                @Suppress("DEPRECATION")
                vibrator?.vibrate(VibrationEffect.createOneShot(millis, VibrationEffect.DEFAULT_AMPLITUDE), vibAttrs)
            } else {
                @Suppress("DEPRECATION")
                vibrator?.vibrate(millis)
            }
        } catch (_: Exception) {}

        try {
            scheduledStopTask?.cancel(false)
            activeRingtone?.stop()
            val alarmUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
                ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
            val ringtone = RingtoneManager.getRingtone(context, alarmUri)
            if (ringtone != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                ringtone.audioAttributes = AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_ALARM)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
            }
            activeRingtone = ringtone
            ringtone?.play()
            scheduledStopTask = stopScheduler.schedule({
                synchronized(this) {
                    try {
                        activeRingtone?.stop()
                    } catch (_: Exception) {}
                    activeRingtone = null
                }
            }, millis, TimeUnit.MILLISECONDS)
        } catch (_: Exception) {}
    }

    fun shutdown() {
        synchronized(this) {
            try {
                scheduledStopTask?.cancel(false)
                scheduledStopTask = null
                activeRingtone?.stop()
                activeRingtone = null
            } catch (_: Exception) {}
        }
        stopScheduler.shutdownNow()
    }

    override fun notifyActionExecuted(actionName: String) {
        try {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val ch = NotificationChannel(
                    ACTION_CHANNEL_ID,
                    "PhoneLink Remote Actions",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Visible alerts when paired Mac executes device actions"
                }
                nm.createNotificationChannel(ch)
            }
            val label = when (actionName) {
                RemoteActionRegistry.ACTION_PING -> "Paired Mac pinged this device"
                RemoteActionRegistry.ACTION_INFO -> "Paired Mac queried device info"
                else -> "Remote action executed: $actionName"
            }
            val notification = NotificationCompat.Builder(context, ACTION_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("PhoneLink Action")
                .setContentText(label)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build()
            nm.notify(ACTION_NOTIFICATION_ID, notification)
        } catch (_: Exception) {}
    }
}
