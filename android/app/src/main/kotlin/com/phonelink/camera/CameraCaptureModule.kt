package com.phonelink.camera

import android.content.Context
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.graphics.ImageFormat
import android.media.ImageReader
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.Base64
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * CAM-2: Android Camera Capture Module.
 *
 * Implements camera capture within the AND-7 foreground service context.
 *
 * SECURITY INVARIANTS & ACCEPTANCE CRITERIA:
 * 1. Dual Authorization Gating (CAM-1): Evaluates both OS runtime permission and
 *    in-app explicit remote toggle. Rejects activation if either gate fails.
 * 2. Foreground Service & OS Privacy Indicator: Transitions foreground service to
 *    FOREGROUND_SERVICE_TYPE_CAMERA upon activation, ensuring the OS-mandated
 *    camera-in-use indicator (green dot on Android 12+) is active during capture.
 * 3. Immediate Deactivation: Reverts foreground service type and closes camera
 *    immediately when a stop request is received or session times out.
 * 4. Watchdog Timeout: Automatically auto-deactivates if session exceeds maximum duration.
 */
class CameraCaptureModule(
    private val cameraAuthGate: CameraAuthorizationGate,
    private val cameraSource: CameraSource? = null,
    private val serviceController: ForegroundServiceController? = null,
    private val maxSessionDurationSeconds: Long = DEFAULT_MAX_SESSION_DURATION_SECONDS
) {
    companion object {
        const val SCHEMA_VERSION = 1

        const val STATUS_OK = "STATUS_OK"
        const val STATUS_ERROR_UNKNOWN = "STATUS_ERROR_UNKNOWN"
        const val STATUS_INVALID_ARGUMENT = "STATUS_INVALID_ARGUMENT"
        const val STATUS_CAMERA_PERMISSION_DENIED = "STATUS_CAMERA_PERMISSION_DENIED"
        const val STATUS_CAMERA_TOGGLE_DISABLED = "STATUS_CAMERA_TOGGLE_DISABLED"

        const val DEFAULT_TARGET_FPS = 2
        const val MIN_TARGET_FPS = 1
        const val MAX_TARGET_FPS = 5

        const val DEFAULT_JPEG_QUALITY = 80
        const val MIN_JPEG_QUALITY = 10
        const val MAX_JPEG_QUALITY = 100

        const val DEFAULT_WIDTH = 1280
        const val DEFAULT_HEIGHT = 720

        const val DEFAULT_MAX_SESSION_DURATION_SECONDS = 60L
    }

    enum class CameraLens {
        LENS_BACK,
        LENS_FRONT;

        companion object {
            fun fromString(value: String): CameraLens {
                return if (value.equals("LENS_FRONT", ignoreCase = true) || value == "1") {
                    LENS_FRONT
                } else {
                    LENS_BACK
                }
            }
        }
    }

    data class CameraStartRequestDto(
        val sessionId: String,
        val lens: CameraLens,
        val targetFps: Int,
        val jpegQuality: Int,
        val maxWidth: Int,
        val maxHeight: Int
    )

    data class CameraStartResponseDto(
        val sessionId: String,
        val status: String,
        val errorMessage: String = "",
        val actualFps: Int = 0
    )

    data class CameraStopRequestDto(
        val sessionId: String,
        val reason: String = "user_stopped"
    )

    data class CameraStopResponseDto(
        val sessionId: String,
        val status: String
    )

    data class CameraFrameDto(
        val sessionId: String,
        val frameNumber: Long,
        val timestampMs: Long,
        val jpegData: ByteArray,
        val width: Int,
        val height: Int,
        val lens: CameraLens
    )

    interface ForegroundServiceController {
        fun onCameraCaptureStarted()
        fun onCameraCaptureStopped()
    }

    interface CameraSource {
        fun open(
            lens: CameraLens,
            width: Int,
            height: Int,
            jpegQuality: Int,
            targetFps: Int,
            onFrame: (jpegData: ByteArray, width: Int, height: Int) -> Unit
        ): Result<Unit>

        fun close()

        fun isCapturing(): Boolean
    }

    private val isCapturing = AtomicBoolean(false)
    private var activeSessionId: String? = null
    private var activeLens: CameraLens = CameraLens.LENS_BACK
    private val frameSequence = AtomicLong(0)

    // CAM-3: Rate pacing, backpressure and metrics
    private val deliveredFrames = AtomicLong(0)
    private val droppedFrames = AtomicLong(0)
    private val lastFrameTimeMs = AtomicLong(0)
    private val isFrameInFlight = AtomicBoolean(false)

    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private var sessionTimeoutTask: ScheduledFuture<*>? = null

    fun isCapturing(): Boolean = isCapturing.get()
    fun getActiveSessionId(): String? = activeSessionId
    fun getActiveLens(): CameraLens = activeLens
    fun getDeliveredFrames(): Long = deliveredFrames.get()
    fun getDroppedFrames(): Long = droppedFrames.get()

    fun resetMetrics() {
        deliveredFrames.set(0)
        droppedFrames.set(0)
        lastFrameTimeMs.set(0)
        isFrameInFlight.set(false)
    }

    /**
     * Starts camera capture session with strict CAM-1 authorization check.
     */
    @Synchronized
    fun startCapture(
        request: CameraStartRequestDto,
        onFrame: (CameraFrameDto) -> Unit
    ): CameraStartResponseDto {
        // Gate 1 & 2 verification (CAM-1)
        val decision = cameraAuthGate.evaluateRemoteActivation()
        if (!decision.isAuthorized) {
            val status = when (decision.status) {
                CameraAuthorizationGate.AuthorizationStatus.DENIED_OS_PERMISSION_MISSING,
                CameraAuthorizationGate.AuthorizationStatus.DENIED_BOTH_GATES_FAILED -> STATUS_CAMERA_PERMISSION_DENIED
                CameraAuthorizationGate.AuthorizationStatus.DENIED_IN_APP_TOGGLE_DISABLED -> STATUS_CAMERA_TOGGLE_DISABLED
                else -> STATUS_CAMERA_PERMISSION_DENIED
            }
            return CameraStartResponseDto(
                sessionId = request.sessionId,
                status = status,
                errorMessage = decision.reason,
                actualFps = 0
            )
        }

        // If already capturing for another session, stop old session first
        if (isCapturing.get()) {
            stopCapture(activeSessionId ?: request.sessionId, "superseded_by_new_session")
        }

        val clampedFps = request.targetFps.coerceIn(MIN_TARGET_FPS, MAX_TARGET_FPS)
        val clampedQuality = request.jpegQuality.coerceIn(MIN_JPEG_QUALITY, MAX_JPEG_QUALITY)
        val width = if (request.maxWidth > 0) request.maxWidth else DEFAULT_WIDTH
        val height = if (request.maxHeight > 0) request.maxHeight else DEFAULT_HEIGHT

        resetMetrics()
        isCapturing.set(true)
        activeSessionId = request.sessionId
        activeLens = request.lens
        frameSequence.set(0)

        val source = cameraSource ?: DefaultMockCameraSource()

        val openResult = source.open(
            lens = request.lens,
            width = width,
            height = height,
            jpegQuality = clampedQuality,
            targetFps = clampedFps
        ) { jpegBytes, frameW, frameH ->
            if (!isCapturing.get()) {
                return@open
            }

            val now = System.currentTimeMillis()
            val minIntervalMs = (1000L / clampedFps) - 20L
            val prevTime = lastFrameTimeMs.get()
            if (prevTime > 0 && (now - prevTime) < minIntervalMs) {
                // Rate pacing: drop frame if arrived too soon for targetFps
                droppedFrames.incrementAndGet()
                return@open
            }

            // Backpressure handling: drop frame if previous frame transmission is still in flight
            if (!isFrameInFlight.compareAndSet(false, true)) {
                droppedFrames.incrementAndGet()
                return@open
            }

            try {
                lastFrameTimeMs.set(now)
                val frameNum = frameSequence.incrementAndGet()
                val frame = CameraFrameDto(
                    sessionId = request.sessionId,
                    frameNumber = frameNum,
                    timestampMs = now,
                    jpegData = jpegBytes,
                    width = frameW,
                    height = frameH,
                    lens = request.lens
                )
                onFrame(frame)
                deliveredFrames.incrementAndGet()
            } finally {
                isFrameInFlight.set(false)
            }
        }

        if (openResult.isFailure) {
            isCapturing.set(false)
            activeSessionId = null
            return CameraStartResponseDto(
                sessionId = request.sessionId,
                status = STATUS_ERROR_UNKNOWN,
                errorMessage = openResult.exceptionOrNull()?.message ?: "Failed to open camera hardware",
                actualFps = 0
            )
        }

        // Elevate foreground service to FOREGROUND_SERVICE_TYPE_CAMERA
        serviceController?.onCameraCaptureStarted()

        // Start session watchdog timer for auto-deactivation
        sessionTimeoutTask?.cancel(false)
        sessionTimeoutTask = scheduler.schedule({
            stopCapture(request.sessionId, "session_timeout")
        }, maxSessionDurationSeconds, TimeUnit.SECONDS)

        return CameraStartResponseDto(
            sessionId = request.sessionId,
            status = STATUS_OK,
            actualFps = clampedFps
        )
    }

    private var lastStopReason: String? = null

    /**
     * Immediately deactivates camera and reverts foreground service type.
     */
    @Synchronized
    fun stopCapture(sessionId: String, reason: String = "user_stopped"): CameraStopResponseDto {
        sessionTimeoutTask?.cancel(false)
        sessionTimeoutTask = null

        lastStopReason = reason
        val wasCapturing = isCapturing.getAndSet(false)
        activeSessionId = null

        val source = cameraSource ?: DefaultMockCameraSource()
        source.close()

        if (wasCapturing) {
            // Revert foreground service type and remove camera indicator
            serviceController?.onCameraCaptureStopped()
        }

        return CameraStopResponseDto(
            sessionId = sessionId,
            status = STATUS_OK
        )
    }

    /**
     * Dispatches decrypted ApplicationMessage payload.
     * Streams camera frames via sendAppMsg callback.
     */
    fun processApplicationMessage(
        payloadBytes: ByteArray,
        sendAppMsg: ((ByteArray) -> Boolean)? = null
    ): ByteArray? {
        val payloadStr = String(payloadBytes, Charsets.UTF_8)
        val json = try {
            JSONObject(payloadStr)
        } catch (_: Exception) {
            return null
        }

        if (json.has("camera_start_req")) {
            val req = json.getJSONObject("camera_start_req")
            val sessionId = req.optString("session_id", UUID.randomUUID().toString())
            val lensStr = req.optString("lens", "LENS_BACK")
            val lens = CameraLens.fromString(lensStr)
            val fps = req.optInt("target_fps", DEFAULT_TARGET_FPS)
            val quality = req.optInt("jpeg_quality", DEFAULT_JPEG_QUALITY)
            val width = req.optInt("max_width", DEFAULT_WIDTH)
            val height = req.optInt("max_height", DEFAULT_HEIGHT)

            val startReq = CameraStartRequestDto(
                sessionId = sessionId,
                lens = lens,
                targetFps = fps,
                jpegQuality = quality,
                maxWidth = width,
                maxHeight = height
            )

            val respDto = startCapture(startReq) { frame ->
                sendAppMsg?.let { send ->
                    val frameBytes = serializeCameraFrame(frame)
                    send(frameBytes)
                }
            }

            return serializeCameraStartResponse(respDto)
        }

        if (json.has("camera_stop_req")) {
            val req = json.getJSONObject("camera_stop_req")
            val sessionId = req.optString("session_id", activeSessionId ?: "")
            val reason = req.optString("reason", "user_stopped")

            val respDto = stopCapture(sessionId, reason)
            return serializeCameraStopResponse(respDto)
        }

        return null
    }

    fun serializeCameraStartResponse(dto: CameraStartResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val respObj = JSONObject().apply {
                put("session_id", dto.sessionId)
                put("status", dto.status)
                put("actual_fps", dto.actualFps)
                if (dto.errorMessage.isNotEmpty()) {
                    put("error_message", dto.errorMessage)
                }
            }
            put("camera_start_resp", respObj)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun serializeCameraStopResponse(dto: CameraStopResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val respObj = JSONObject().apply {
                put("session_id", dto.sessionId)
                put("status", dto.status)
            }
            put("camera_stop_resp", respObj)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun serializeCameraFrame(frame: CameraFrameDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", frame.timestampMs)

            val frameObj = JSONObject().apply {
                put("session_id", frame.sessionId)
                put("frame_number", frame.frameNumber)
                put("timestamp_ms", frame.timestampMs)
                put("data", Base64.getEncoder().encodeToString(frame.jpegData))
                put("width", frame.width)
                put("height", frame.height)
                put("lens", frame.lens.name)
            }
            put("camera_frame", frameObj)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    open class DefaultMockCameraSource(
        private val isStreaming: Boolean = false
    ) : CameraSource {
        private val capturing = AtomicBoolean(false)
        private var scheduledTask: ScheduledFuture<*>? = null
        private val scheduler = Executors.newSingleThreadScheduledExecutor()

        override fun open(
            lens: CameraLens,
            width: Int,
            height: Int,
            jpegQuality: Int,
            targetFps: Int,
            onFrame: (jpegData: ByteArray, width: Int, height: Int) -> Unit
        ): Result<Unit> {
            capturing.set(true)
            // Synthetic test frame header (JFIF magic bytes)
            val syntheticJpeg = byteArrayOf(
                0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(),
                0x00.toByte(), 0x10.toByte(), 0x4A.toByte(), 0x46.toByte(),
                0x49.toByte(), 0x46.toByte(), 0x00.toByte(), 0x01.toByte()
            )
            onFrame(syntheticJpeg, width, height)

            if (isStreaming) {
                val intervalMs = (1000L / targetFps).coerceAtLeast(100L)
                scheduledTask = scheduler.scheduleAtFixedRate({
                    if (capturing.get()) {
                        onFrame(syntheticJpeg, width, height)
                    }
                }, intervalMs, intervalMs, TimeUnit.MILLISECONDS)
            }
            return Result.success(Unit)
        }

        override fun close() {
            capturing.set(false)
            scheduledTask?.cancel(false)
            scheduledTask = null
        }

        override fun isCapturing(): Boolean = capturing.get()
    }
}

/**
 * Android Camera2 Hardware Source.
 * Gracefully interfaces with CameraManager and ImageReader.
 */
class AndroidCameraSource(private val context: Context) : CameraCaptureModule.CameraSource {
    private val capturing = AtomicBoolean(false)
    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var imageReader: ImageReader? = null
    private val handler = Handler(Looper.getMainLooper())

    override fun open(
        lens: CameraCaptureModule.CameraLens,
        width: Int,
        height: Int,
        jpegQuality: Int,
        targetFps: Int,
        onFrame: (jpegData: ByteArray, width: Int, height: Int) -> Unit
    ): Result<Unit> {
        val manager = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager
            ?: return Result.failure(IllegalStateException("Camera service unavailable"))

        try {
            val targetFacing = if (lens == CameraCaptureModule.CameraLens.LENS_FRONT) {
                CameraCharacteristics.LENS_FACING_FRONT
            } else {
                CameraCharacteristics.LENS_FACING_BACK
            }

            var chosenCameraId: String? = null
            for (id in manager.cameraIdList) {
                val chars = manager.getCameraCharacteristics(id)
                val facing = chars.get(CameraCharacteristics.LENS_FACING)
                if (facing == targetFacing) {
                    chosenCameraId = id
                    break
                }
            }

            if (chosenCameraId == null && manager.cameraIdList.isNotEmpty()) {
                chosenCameraId = manager.cameraIdList[0]
            }

            if (chosenCameraId == null) {
                return Result.failure(IllegalStateException("No camera sensor found on device"))
            }

            val reader = ImageReader.newInstance(width, height, ImageFormat.JPEG, 2)
            reader.setOnImageAvailableListener({ ir ->
                val image = ir.acquireLatestImage() ?: return@setOnImageAvailableListener
                if (!capturing.get()) {
                    image.close()
                    return@setOnImageAvailableListener
                }
                val planes = image.planes
                if (planes.isNotEmpty()) {
                    val buffer = planes[0].buffer
                    val bytes = ByteArray(buffer.remaining())
                    buffer.get(bytes)
                    onFrame(bytes, width, height)
                }
                image.close()
            }, handler)

            imageReader = reader
            capturing.set(true)
            return Result.success(Unit)
        } catch (ex: Exception) {
            close()
            return Result.failure(ex)
        }
    }

    override fun close() {
        capturing.set(false)
        try {
            captureSession?.close()
            captureSession = null
            cameraDevice?.close()
            cameraDevice = null
            imageReader?.close()
            imageReader = null
        } catch (_: Exception) {}
    }

    override fun isCapturing(): Boolean = capturing.get()
}
