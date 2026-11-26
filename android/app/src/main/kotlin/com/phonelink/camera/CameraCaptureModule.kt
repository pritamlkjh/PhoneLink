package com.phonelink.camera

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.util.Range
import org.json.JSONObject
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

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
        fun isCameraForegroundReady(): Boolean = true
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
    private var activeCameraSource: CameraSource? = null
    private var activeSendAppMsg: ((ByteArray) -> Boolean)? = null
    private val frameSequence = AtomicLong(0)

    // CAM-3: Rate pacing, backpressure and metrics
    private val deliveredFrames = AtomicLong(0)
    private val droppedFrames = AtomicLong(0)
    private val lastFrameTimeMs = AtomicLong(0)
    private val isFrameInFlight = AtomicBoolean(false)

    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PhoneLink-CamWatchdog").apply { isDaemon = true }
    }
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
        activeCameraSource = source

        // Elevate foreground service to FOREGROUND_SERVICE_TYPE_CAMERA before Camera2 openCamera(),
        // so Android 14–16 background camera policy checks see the active camera FGS type.
        serviceController?.onCameraCaptureStarted()
        if (serviceController != null && !serviceController.isCameraForegroundReady()) {
            isCapturing.set(false)
            activeSessionId = null
            activeCameraSource = null
            serviceController.onCameraCaptureStopped()
            return CameraStartResponseDto(
                sessionId = request.sessionId,
                status = STATUS_CAMERA_PERMISSION_DENIED,
                errorMessage = "Android blocked background camera access: unlock the phone and open PhoneLink on screen before starting remote camera.",
                actualFps = 0
            )
        }

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
            activeCameraSource = null
            serviceController?.onCameraCaptureStopped()
            return CameraStartResponseDto(
                sessionId = request.sessionId,
                status = STATUS_ERROR_UNKNOWN,
                errorMessage = openResult.exceptionOrNull()?.message ?: "Failed to open camera hardware",
                actualFps = 0
            )
        }

        // Start session watchdog timer for auto-deactivation and peer notification
        sessionTimeoutTask?.cancel(false)
        sessionTimeoutTask = scheduler.schedule({
            val stopResp = stopCapture(request.sessionId, "session_timeout")
            val notifier = activeSendAppMsg
            if (notifier != null) {
                try {
                    notifier(serializeCameraStopResponse(stopResp))
                } catch (_: Exception) {}
            }
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

        val source = activeCameraSource ?: cameraSource
        activeCameraSource = null
        source?.close()

        if (wasCapturing) {
            // Revert foreground service type and remove camera indicator
            serviceController?.onCameraCaptureStopped()
        }

        return CameraStopResponseDto(
            sessionId = sessionId,
            status = STATUS_OK
        )
    }

    fun shutdown() {
        stopCapture(activeSessionId ?: "shutdown", "shutdown")
        activeSendAppMsg = null
        scheduler.shutdownNow()
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

            activeSendAppMsg = sendAppMsg
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
        private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "PhoneLink-MockCam").apply { isDaemon = true }
        }

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
 * Opens CameraDevice, negotiates supported JPEG resolution and FPS range,
 * creates CameraCaptureSession, and delivers repeating JPEG frames off the UI thread.
 */
class AndroidCameraSource(private val context: Context) : CameraCaptureModule.CameraSource {
    private val cameraLock = Any()
    private val capturing = AtomicBoolean(false)
    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var imageReader: ImageReader? = null
    private var backgroundThread: HandlerThread? = null
    private var backgroundHandler: Handler? = null
    private var closeLatch: CountDownLatch? = null

    @SuppressLint("MissingPermission")
    override fun open(
        lens: CameraCaptureModule.CameraLens,
        width: Int,
        height: Int,
        jpegQuality: Int,
        targetFps: Int,
        onFrame: (jpegData: ByteArray, width: Int, height: Int) -> Unit
    ): Result<Unit> = synchronized(cameraLock) {
        if (context.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            return Result.failure(SecurityException("CAMERA runtime permission not granted"))
        }

        val manager = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager
            ?: return Result.failure(IllegalStateException("Camera service unavailable"))

        close()

        try {
            val targetFacing = if (lens == CameraCaptureModule.CameraLens.LENS_FRONT) {
                CameraCharacteristics.LENS_FACING_FRONT
            } else {
                CameraCharacteristics.LENS_FACING_BACK
            }

            var chosenCameraId: String? = null
            var chosenChars: CameraCharacteristics? = null
            for (id in manager.cameraIdList) {
                val chars = manager.getCameraCharacteristics(id)
                val facing = chars.get(CameraCharacteristics.LENS_FACING)
                if (facing == targetFacing) {
                    chosenCameraId = id
                    chosenChars = chars
                    break
                }
            }

            if (chosenCameraId == null && manager.cameraIdList.isNotEmpty()) {
                chosenCameraId = manager.cameraIdList[0]
                chosenChars = manager.getCameraCharacteristics(chosenCameraId)
            }

            if (chosenCameraId == null || chosenChars == null) {
                return Result.failure(IllegalStateException("No camera sensor found on device"))
            }

            val chosenSize = selectJpegSize(chosenChars, width, height)
            val chosenFpsRange = selectFpsRange(chosenChars, targetFps)

            val thread = HandlerThread("PhoneLink-Camera2").apply { start() }
            val handler = Handler(thread.looper)
            backgroundThread = thread
            backgroundHandler = handler

            val reader = ImageReader.newInstance(chosenSize.first, chosenSize.second, ImageFormat.JPEG, 2)
            reader.setOnImageAvailableListener({ ir ->
                val image = ir.acquireLatestImage() ?: return@setOnImageAvailableListener
                try {
                    if (!capturing.get()) return@setOnImageAvailableListener
                    val planes = image.planes
                    if (planes.isNotEmpty()) {
                        val buffer = planes[0].buffer
                        val bytes = ByteArray(buffer.remaining())
                        buffer.get(bytes)
                        onFrame(bytes, image.width, image.height)
                    }
                } finally {
                    image.close()
                }
            }, handler)
            imageReader = reader
            capturing.set(true)

            val openLatch = CountDownLatch(1)
            val openError = AtomicReference<Throwable?>(null)

            manager.openCamera(chosenCameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    if (!capturing.get()) {
                        device.close()
                        openLatch.countDown()
                        return
                    }
                    cameraDevice = device
                    startRepeatingPreview(device, reader, jpegQuality, chosenFpsRange, handler, openLatch, openError)
                }

                override fun onDisconnected(device: CameraDevice) {
                    capturing.set(false)
                    device.close()
                    cameraDevice = null
                    openError.compareAndSet(null, IllegalStateException("Camera disconnected"))
                    openLatch.countDown()
                }

                override fun onError(device: CameraDevice, error: Int) {
                    capturing.set(false)
                    device.close()
                    cameraDevice = null
                    openError.compareAndSet(null, IllegalStateException("Camera open error code: $error"))
                    openLatch.countDown()
                }

                override fun onClosed(device: CameraDevice) {
                    closeLatch?.countDown()
                }
            }, handler)

            if (!openLatch.await(5, TimeUnit.SECONDS)) {
                close()
                return Result.failure(IllegalStateException("Timed out opening Android Camera2 device"))
            }

            openError.get()?.let { err ->
                close()
                return Result.failure(err)
            }

            return Result.success(Unit)
        } catch (ex: CameraAccessException) {
            close()
            val friendlyMsg = when (ex.reason) {
                CameraAccessException.CAMERA_DISABLED ->
                    "Camera blocked by Android privacy/background policy (${ex.message}): unlock phone, ensure 'Camera access' Quick Setting is ON, and keep PhoneLink open/recent."
                CameraAccessException.CAMERA_IN_USE,
                CameraAccessException.MAX_CAMERAS_IN_USE ->
                    "Camera is currently in use by another app (${ex.message})"
                else -> ex.message ?: "Camera access failed (${ex.reason})"
            }
            return Result.failure(IllegalStateException(friendlyMsg, ex))
        } catch (ex: Exception) {
            close()
            return Result.failure(ex)
        }
    }

    private fun startRepeatingPreview(
        device: CameraDevice,
        reader: ImageReader,
        jpegQuality: Int,
        fpsRange: Range<Int>?,
        handler: Handler,
        openLatch: CountDownLatch,
        openError: AtomicReference<Throwable?>
    ) {
        val stateCallback = object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(session: CameraCaptureSession) {
                if (!capturing.get()) {
                    session.close()
                    openLatch.countDown()
                    return
                }
                captureSession = session
                try {
                    val reqBuilder = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                        addTarget(reader.surface)
                        set(CaptureRequest.CONTROL_MODE, CaptureRequest.CONTROL_MODE_AUTO)
                        set(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_ON)
                        set(CaptureRequest.CONTROL_AWB_MODE, CaptureRequest.CONTROL_AWB_MODE_AUTO)
                        set(CaptureRequest.JPEG_QUALITY, jpegQuality.coerceIn(10, 100).toByte())
                        if (fpsRange != null) {
                            set(CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE, fpsRange)
                        }
                    }
                    session.setRepeatingRequest(reqBuilder.build(), null, handler)
                } catch (ex: Exception) {
                    openError.compareAndSet(null, ex)
                } finally {
                    openLatch.countDown()
                }
            }

            override fun onConfigureFailed(session: CameraCaptureSession) {
                openError.compareAndSet(null, IllegalStateException("Camera2 capture session configuration failed"))
                openLatch.countDown()
            }
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val outputs = listOf(OutputConfiguration(reader.surface))
                val sessionConfig = SessionConfiguration(
                    SessionConfiguration.SESSION_REGULAR,
                    outputs,
                    context.mainExecutor,
                    stateCallback
                )
                device.createCaptureSession(sessionConfig)
            } else {
                @Suppress("DEPRECATION")
                device.createCaptureSession(listOf(reader.surface), stateCallback, handler)
            }
        } catch (ex: Exception) {
            openError.compareAndSet(null, ex)
            openLatch.countDown()
        }
    }

    private fun selectJpegSize(chars: CameraCharacteristics, maxW: Int, maxH: Int): Pair<Int, Int> {
        val map = chars.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return maxW to maxH
        val sizes = map.getOutputSizes(ImageFormat.JPEG) ?: return maxW to maxH
        val targetArea = maxW.toLong() * maxH.toLong()
        val best = sizes
            .filter { it.width <= maxW && it.height <= maxH }
            .maxByOrNull { it.width.toLong() * it.height.toLong() }
            ?: sizes.minByOrNull { kotlin.math.abs(it.width.toLong() * it.height.toLong() - targetArea) }
        return if (best != null) best.width to best.height else maxW to maxH
    }

    companion object {
        /**
         * Selects an AE FPS range containing [targetFps] with minimal span, or falls back to
         * the range with the lowest minimum FPS so auto-exposure can extend shutter in low light.
         */
        internal fun selectPreferredFpsRange(ranges: List<Pair<Int, Int>>, targetFps: Int): Pair<Int, Int>? {
            if (ranges.isEmpty()) return null
            return ranges
                .filter { targetFps in it.first..it.second }
                .minWithOrNull(compareBy<Pair<Int, Int>> { it.second - it.first }.thenBy { it.first })
                ?: ranges.minWithOrNull(compareBy<Pair<Int, Int>> { it.first }.thenBy { it.second })
        }
    }

    private fun selectFpsRange(chars: CameraCharacteristics, targetFps: Int): Range<Int>? {
        val ranges = chars.get(CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES) ?: return null
        val pairs = ranges.map { it.lower to it.upper }
        val chosen = selectPreferredFpsRange(pairs, targetFps) ?: return null
        return Range(chosen.first, chosen.second)
    }

    override fun close() = synchronized(cameraLock) {
        capturing.set(false)
        try {
            captureSession?.stopRepeating()
        } catch (_: Exception) {}
        try {
            captureSession?.close()
            captureSession = null
        } catch (_: Exception) {}
        val dev = cameraDevice
        cameraDevice = null
        if (dev != null) {
            val latch = CountDownLatch(1)
            closeLatch = latch
            try {
                dev.close()
                // Wait briefly for vendor Camera HAL (Oppo/Realme/Vivo) onClosed callback
                latch.await(500, TimeUnit.MILLISECONDS)
            } catch (_: Exception) {
            } finally {
                closeLatch = null
            }
        }
        try {
            imageReader?.close()
            imageReader = null
            backgroundThread?.quitSafely()
            backgroundThread = null
            backgroundHandler = null
        } catch (_: Exception) {}
    }

    override fun isCapturing(): Boolean = capturing.get()
}
