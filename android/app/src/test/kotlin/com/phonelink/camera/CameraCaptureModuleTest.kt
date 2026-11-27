package com.phonelink.camera

import com.phonelink.identity.InMemorySharedPreferences
import com.phonelink.storage.SecureStorage
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class CameraCaptureModuleTest {

    private lateinit var mockPrefs: InMemorySharedPreferences
    private lateinit var storage: SecureStorage
    private var osPermissionGranted = false
    private lateinit var authGate: CameraAuthorizationGate
    private lateinit var testCameraSource: TestCameraSource
    private lateinit var testServiceController: TestServiceController
    private lateinit var module: CameraCaptureModule

    class TestServiceController : CameraCaptureModule.ForegroundServiceController {
        val startedCount = AtomicInteger(0)
        val stoppedCount = AtomicInteger(0)

        override fun onCameraCaptureStarted() {
            startedCount.incrementAndGet()
        }

        override fun onCameraCaptureStopped() {
            stoppedCount.incrementAndGet()
        }
    }

    class TestCameraSource : CameraCaptureModule.CameraSource {
        val capturing = AtomicBoolean(false)
        var lastLens: CameraCaptureModule.CameraLens? = null
        var lastWidth: Int = 0
        var lastHeight: Int = 0
        var lastFps: Int = 0
        var frameEmitter: ((ByteArray, Int, Int) -> Unit)? = null

        override fun open(
            lens: CameraCaptureModule.CameraLens,
            width: Int,
            height: Int,
            jpegQuality: Int,
            targetFps: Int,
            onFrame: (jpegData: ByteArray, width: Int, height: Int) -> Unit
        ): Result<Unit> {
            capturing.set(true)
            lastLens = lens
            lastWidth = width
            lastHeight = height
            lastFps = targetFps
            frameEmitter = onFrame

            // Emit a mock frame
            val mockJpeg = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0x01, 0x02)
            onFrame(mockJpeg, width, height)
            return Result.success(Unit)
        }

        override fun close() {
            capturing.set(false)
            frameEmitter = null
        }

        override fun isCapturing(): Boolean = capturing.get()
    }

    @Before
    fun setUp() {
        mockPrefs = InMemorySharedPreferences()
        storage = SecureStorage(mockPrefs)
        osPermissionGranted = false
        storage.setCameraAllowed(false) // Default on install is false

        authGate = CameraAuthorizationGate(
            secureStorage = storage,
            permissionChecker = { osPermissionGranted }
        )

        testCameraSource = TestCameraSource()
        testServiceController = TestServiceController()

        module = CameraCaptureModule(
            cameraAuthGate = authGate,
            cameraSource = testCameraSource,
            serviceController = testServiceController,
            maxSessionDurationSeconds = 60
        )
    }

    @Test
    fun testCameraStartRejectedWhenBothGatesDisabled() {
        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-1",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 2,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )
        val resp = module.startCapture(req) {}
        assertEquals(CameraCaptureModule.STATUS_CAMERA_PERMISSION_DENIED, resp.status)
        assertFalse(testCameraSource.isCapturing())
        assertEquals(0, testServiceController.startedCount.get())
    }

    @Test
    fun testCameraStartRejectedWhenInAppToggleDisabled() {
        // OS permission granted, but in-app toggle is OFF (CAM-1 security invariant)
        osPermissionGranted = true
        storage.setCameraAllowed(false)

        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-2",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 3,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )
        val resp = module.startCapture(req) {}
        assertEquals(CameraCaptureModule.STATUS_CAMERA_TOGGLE_DISABLED, resp.status)
        assertFalse(testCameraSource.isCapturing())
        assertEquals(0, testServiceController.startedCount.get())
    }

    @Test
    fun testCameraStartRejectedWhenOSPermissionMissing() {
        // In-app toggle ON, but OS permission NOT granted
        osPermissionGranted = false
        storage.setCameraAllowed(true)

        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-3",
            lens = CameraCaptureModule.CameraLens.LENS_FRONT,
            targetFps = 2,
            jpegQuality = 80,
            maxWidth = 640,
            maxHeight = 480
        )
        val resp = module.startCapture(req) {}
        assertEquals(CameraCaptureModule.STATUS_CAMERA_PERMISSION_DENIED, resp.status)
        assertFalse(testCameraSource.isCapturing())
        assertEquals(0, testServiceController.startedCount.get())
    }

    @Test
    fun testCameraStartSuccessWhenBothGatesPass() {
        // Both gates satisfied (CAM-1 & CAM-2)
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        var frameReceived: CameraCaptureModule.CameraFrameDto? = null
        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-4",
            lens = CameraCaptureModule.CameraLens.LENS_FRONT,
            targetFps = 4,
            jpegQuality = 85,
            maxWidth = 1280,
            maxHeight = 720
        )

        val resp = module.startCapture(req) { frame ->
            frameReceived = frame
        }

        assertEquals(CameraCaptureModule.STATUS_OK, resp.status)
        assertEquals(4, resp.actualFps)
        assertTrue(module.isCapturing())
        assertTrue(testCameraSource.isCapturing())
        assertEquals(1, testServiceController.startedCount.get())
        assertEquals(CameraCaptureModule.CameraLens.LENS_FRONT, testCameraSource.lastLens)

        assertNotNull(frameReceived)
        assertEquals("sess-4", frameReceived?.sessionId)
        assertEquals(1L, frameReceived?.frameNumber)
        assertEquals(1280, frameReceived?.width)
        assertEquals(720, frameReceived?.height)
        assertEquals(CameraCaptureModule.CameraLens.LENS_FRONT, frameReceived?.lens)
    }

    @Test
    fun testCameraStopExecutionAndCleanup() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-5",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 2,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )
        module.startCapture(req) {}
        assertTrue(module.isCapturing())
        assertEquals(1, testServiceController.startedCount.get())

        val stopResp = module.stopCapture("sess-5", "user_requested")
        assertEquals(CameraCaptureModule.STATUS_OK, stopResp.status)
        assertFalse(module.isCapturing())
        assertFalse(testCameraSource.isCapturing())
        assertEquals(1, testServiceController.stoppedCount.get())
    }

    @Test
    fun testTargetFpsAndDimensionClamping() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        // Target FPS 0 clamps to MIN (1)
        val reqMin = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-min",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 0,
            jpegQuality = 5,
            maxWidth = 0,
            maxHeight = 0
        )
        val respMin = module.startCapture(reqMin) {}
        assertEquals(CameraCaptureModule.MIN_TARGET_FPS, respMin.actualFps)
        assertEquals(CameraCaptureModule.DEFAULT_WIDTH, testCameraSource.lastWidth)
        assertEquals(CameraCaptureModule.DEFAULT_HEIGHT, testCameraSource.lastHeight)

        // Target FPS 50 clamps to MAX (5)
        val reqMax = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-max",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 50,
            jpegQuality = 150,
            maxWidth = 1920,
            maxHeight = 1080
        )
        val respMax = module.startCapture(reqMax) {}
        assertEquals(CameraCaptureModule.MAX_TARGET_FPS, respMax.actualFps)
        assertEquals(1920, testCameraSource.lastWidth)
        assertEquals(1080, testCameraSource.lastHeight)
    }

    @Test
    fun testAutoDeactivationOnTimeoutWatchdog() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        // Module with 1 second session watchdog
        val timeoutModule = CameraCaptureModule(
            cameraAuthGate = authGate,
            cameraSource = testCameraSource,
            serviceController = testServiceController,
            maxSessionDurationSeconds = 1
        )

        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-timeout",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 2,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )
        val resp = timeoutModule.startCapture(req) {}
        assertEquals(CameraCaptureModule.STATUS_OK, resp.status)
        assertTrue(timeoutModule.isCapturing())

        // Wait for watchdog to trigger (1.2 seconds)
        Thread.sleep(1200)

        assertFalse(timeoutModule.isCapturing())
        assertFalse(testCameraSource.isCapturing())
        assertEquals(1, testServiceController.stoppedCount.get())
    }

    @Test
    fun testApplicationMessageDispatch() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        val emittedFrames = mutableListOf<ByteArray>()

        // 1. Camera Start Request Dispatch
        val startReqJson = JSONObject().apply {
            put("schema_version", 1)
            val sub = JSONObject().apply {
                put("session_id", "cam-app-1")
                put("lens", "LENS_FRONT")
                put("target_fps", 3)
                put("jpeg_quality", 85)
                put("max_width", 1280)
                put("max_height", 720)
            }
            put("camera_start_req", sub)
        }

        val startRespBytes = module.processApplicationMessage(startReqJson.toString().toByteArray(Charsets.UTF_8)) { frameBytes ->
            emittedFrames.add(frameBytes)
            true
        }

        assertNotNull(startRespBytes)
        val startRespJson = JSONObject(String(startRespBytes!!, Charsets.UTF_8))
        assertTrue(startRespJson.has("camera_start_resp"))
        val startRespBody = startRespJson.getJSONObject("camera_start_resp")
        assertEquals("cam-app-1", startRespBody.getString("session_id"))
        assertEquals(CameraCaptureModule.STATUS_OK, startRespBody.getString("status"))
        assertEquals(3, startRespBody.getInt("actual_fps"))

        // Verify emitted frame
        assertEquals(1, emittedFrames.size)
        val frameJson = JSONObject(String(emittedFrames[0], Charsets.UTF_8))
        assertTrue(frameJson.has("camera_frame"))
        val frameBody = frameJson.getJSONObject("camera_frame")
        assertEquals("cam-app-1", frameBody.getString("session_id"))
        assertEquals(1L, frameBody.getLong("frame_number"))
        assertEquals(1280, frameBody.getInt("width"))
        assertEquals(720, frameBody.getInt("height"))
        assertEquals("LENS_FRONT", frameBody.getString("lens"))

        // 2. Camera Stop Request Dispatch
        val stopReqJson = JSONObject().apply {
            put("schema_version", 1)
            val sub = JSONObject().apply {
                put("session_id", "cam-app-1")
                put("reason", "done")
            }
            put("camera_stop_req", sub)
        }

        val stopRespBytes = module.processApplicationMessage(stopReqJson.toString().toByteArray(Charsets.UTF_8))
        assertNotNull(stopRespBytes)
        val stopRespJson = JSONObject(String(stopRespBytes!!, Charsets.UTF_8))
        assertTrue(stopRespJson.has("camera_stop_resp"))
        val stopRespBody = stopRespJson.getJSONObject("camera_stop_resp")
        assertEquals("cam-app-1", stopRespBody.getString("session_id"))
        assertEquals(CameraCaptureModule.STATUS_OK, stopRespBody.getString("status"))
        assertFalse(module.isCapturing())
    }

    @Test
    fun testCameraStreamingRatePacingAndDrop() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        val deliveredList = mutableListOf<CameraCaptureModule.CameraFrameDto>()
        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-pacing",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 2, // 2 FPS -> interval is ~500ms
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )

        val resp = module.startCapture(req) { frame ->
            deliveredList.add(frame)
        }
        assertEquals(CameraCaptureModule.STATUS_OK, resp.status)
        assertEquals(1, deliveredList.size) // First frame emitted on open

        // Rapidly invoke frame emitter (simulating 30 FPS camera sensor burst)
        val mockBytes = byteArrayOf(0x01, 0x02)
        testCameraSource.frameEmitter?.invoke(mockBytes, 1280, 720)
        testCameraSource.frameEmitter?.invoke(mockBytes, 1280, 720)
        testCameraSource.frameEmitter?.invoke(mockBytes, 1280, 720)

        // Frames within minIntervalMs (<480ms) should be dropped by rate pacing
        assertEquals(1, deliveredList.size)
        assertEquals(3L, module.getDroppedFrames())
        assertEquals(1L, module.getDeliveredFrames())

        module.stopCapture("sess-pacing")
    }

    @Test
    fun testCameraStreamingBackpressureFrameDrop() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        val inFlightLatch = CountDownLatch(1)
        val releaseLatch = CountDownLatch(1)
        val deliveredCount = AtomicInteger(0)

        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-backpressure",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 5,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )

        val resp = module.startCapture(req) { _ ->
            val count = deliveredCount.incrementAndGet()
            if (count == 2) {
                // Second frame blocks inside callback
                inFlightLatch.countDown()
                releaseLatch.await(2, TimeUnit.SECONDS)
            }
        }
        assertEquals(CameraCaptureModule.STATUS_OK, resp.status)
        assertEquals(1, deliveredCount.get())

        // Wait past minInterval (so rate-pacing doesn't drop it)
        Thread.sleep(250)

        // Spawn a background thread to deliver the second frame (which will block in callback)
        val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
        val mockBytes = byteArrayOf(0x01, 0x02)
        executor.submit {
            testCameraSource.frameEmitter?.invoke(mockBytes, 1280, 720)
        }

        // Wait until second frame has entered the callback and is holding isFrameInFlight
        assertTrue(inFlightLatch.await(1, TimeUnit.SECONDS))

        // Concurrently invoke frame emitter from another thread while frame 2 is in-flight
        testCameraSource.frameEmitter?.invoke(mockBytes, 1280, 720)

        // Release the blocking frame 2
        releaseLatch.countDown()
        executor.shutdown()
        executor.awaitTermination(1, TimeUnit.SECONDS)

        assertEquals(2, deliveredCount.get())
        assertTrue(module.getDroppedFrames() >= 1L)

        module.stopCapture("sess-backpressure")
    }

    @Test
    fun testStreamStopHaltsFrameDeliveryImmediately() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        val deliveredList = mutableListOf<CameraCaptureModule.CameraFrameDto>()
        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-stop-halt",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 2,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )

        module.startCapture(req) { frame ->
            deliveredList.add(frame)
        }
        assertEquals(1, deliveredList.size)

        // Stop session
        val stopResp = module.stopCapture("sess-stop-halt", "user_stopped")
        assertEquals(CameraCaptureModule.STATUS_OK, stopResp.status)
        assertFalse(module.isCapturing())

        // Emitting after stop must be completely ignored
        val mockBytes = byteArrayOf(0x01, 0x02)
        testCameraSource.frameEmitter?.invoke(mockBytes, 1280, 720)

        assertEquals(1, deliveredList.size) // No additional frames delivered
    }

    @Test
    fun testCameraStreamingDefaultMockContinuous() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        val streamingSource = CameraCaptureModule.DefaultMockCameraSource(isStreaming = true)
        val streamingModule = CameraCaptureModule(
            cameraAuthGate = authGate,
            cameraSource = streamingSource,
            serviceController = testServiceController,
            maxSessionDurationSeconds = 10
        )

        val frames = mutableListOf<CameraCaptureModule.CameraFrameDto>()
        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-mock-stream",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 5, // 5 FPS = every ~200ms
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )

        val resp = streamingModule.startCapture(req) { frame ->
            synchronized(frames) {
                frames.add(frame)
            }
        }
        assertEquals(CameraCaptureModule.STATUS_OK, resp.status)

        // Wait ~550ms for periodic frames to arrive (should receive at least 2 frames)
        Thread.sleep(550)

        val countBeforeStop: Int
        synchronized(frames) {
            countBeforeStop = frames.size
        }
        assertTrue("Expected at least 2 frames but got $countBeforeStop", countBeforeStop >= 2)

        // Stop capture
        streamingModule.stopCapture("sess-mock-stream")
        assertFalse(streamingModule.isCapturing())
        assertFalse(streamingSource.isCapturing())

        // Wait another 300ms to confirm no more frames are delivered
        Thread.sleep(300)

        val countAfterStop: Int
        synchronized(frames) {
            countAfterStop = frames.size
        }
        assertEquals("Frames must not increase after stop", countBeforeStop, countAfterStop)
    }

    @Test
    fun testServiceElevatedBeforeCameraOpenAndRolledBackOnOpenFailure() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        var sawElevatedServiceDuringOpen = false
        val failingSource = object : CameraCaptureModule.CameraSource {
            override fun open(
                lens: CameraCaptureModule.CameraLens,
                width: Int,
                height: Int,
                jpegQuality: Int,
                targetFps: Int,
                onFrame: (jpegData: ByteArray, width: Int, height: Int) -> Unit
            ): Result<Unit> {
                sawElevatedServiceDuringOpen = (testServiceController.startedCount.get() == 1)
                return Result.failure(IllegalStateException("Simulated CAMERA_DISABLED"))
            }

            override fun close() {}
            override fun isCapturing(): Boolean = false
        }

        val failModule = CameraCaptureModule(
            cameraAuthGate = authGate,
            cameraSource = failingSource,
            serviceController = testServiceController
        )
        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-fail-open",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 2,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )

        val resp = failModule.startCapture(req) {}
        assertEquals(CameraCaptureModule.STATUS_ERROR_UNKNOWN, resp.status)
        assertTrue(resp.errorMessage.contains("Simulated CAMERA_DISABLED"))
        assertTrue("Service must elevate to camera FGS before Camera2 openCamera()", sawElevatedServiceDuringOpen)
        assertEquals(1, testServiceController.startedCount.get())
        assertEquals(1, testServiceController.stoppedCount.get())
        assertFalse(failModule.isCapturing())
    }

    @Test
    fun testSelectPreferredFpsRangePrefersVariableLowLightFallback() {
        val hwRanges = listOf(15 to 15, 7 to 30, 30 to 30)
        assertEquals(7 to 30, AndroidCameraSource.selectPreferredFpsRange(hwRanges, 2))
        assertEquals(15 to 15, AndroidCameraSource.selectPreferredFpsRange(hwRanges, 15))
    }

    @Test
    fun testCameraStartFailsFastWhenForegroundServicePromotionBlocked() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        val blockedController = object : CameraCaptureModule.ForegroundServiceController {
            override fun onCameraCaptureStarted() {}
            override fun onCameraCaptureStopped() {}
            override fun isCameraForegroundReady(): Boolean = false
        }

        val blockedModule = CameraCaptureModule(
            cameraAuthGate = authGate,
            cameraSource = testCameraSource,
            serviceController = blockedController
        )
        val req = CameraCaptureModule.CameraStartRequestDto(
            sessionId = "sess-fgs-blocked",
            lens = CameraCaptureModule.CameraLens.LENS_BACK,
            targetFps = 2,
            jpegQuality = 80,
            maxWidth = 1280,
            maxHeight = 720
        )

        val resp = blockedModule.startCapture(req) {}
        assertEquals(CameraCaptureModule.STATUS_CAMERA_PERMISSION_DENIED, resp.status)
        assertTrue(resp.errorMessage.contains("open PhoneLink on screen"))
        assertFalse(testCameraSource.isCapturing())
        assertFalse(blockedModule.isCapturing())
    }

    @Test
    fun testStaleSessionTimeoutDoesNotStopNewerSessionAndUnexpectedStopNotifiesPeer() {
        osPermissionGranted = true
        storage.setCameraAllowed(true)

        var unexpectedListener: ((String) -> Unit)? = null
        val customSource = object : CameraCaptureModule.CameraSource {
            val capturing = AtomicBoolean(false)
            override fun open(
                lens: CameraCaptureModule.CameraLens,
                width: Int,
                height: Int,
                jpegQuality: Int,
                targetFps: Int,
                onFrame: (ByteArray, Int, Int) -> Unit
            ): Result<Unit> {
                capturing.set(true)
                return Result.success(Unit)
            }
            override fun close() { capturing.set(false) }
            override fun isCapturing(): Boolean = capturing.get()
            override fun setUnexpectedStopListener(listener: ((reason: String) -> Unit)?) {
                unexpectedListener = listener
            }
        }

        val emitted = mutableListOf<ByteArray>()
        val camModule = CameraCaptureModule(authGate, customSource, testServiceController)

        val startJson = JSONObject().apply {
            put("camera_start_req", JSONObject().apply {
                put("session_id", "sess-new")
                put("lens", "LENS_BACK")
                put("target_fps", 2)
            })
        }.toString().toByteArray(Charsets.UTF_8)

        camModule.processApplicationMessage(startJson) { msg ->
            emitted.add(msg)
            true
        }
        assertTrue(camModule.isCapturing())
        assertEquals("sess-new", camModule.getActiveSessionId())

        // Stale timeout for an older session must NOT stop sess-new
        camModule.stopCapture("sess-old", "session_timeout")
        assertTrue("Active session must not be stopped by stale session_timeout", camModule.isCapturing())
        assertEquals("sess-new", camModule.getActiveSessionId())

        // Hardware preemption must stop sess-new and send camera_stop_resp
        unexpectedListener?.invoke("camera_disconnected")
        assertFalse(camModule.isCapturing())
        assertTrue(emitted.any { String(it, Charsets.UTF_8).contains("\"camera_stop_resp\"") })
    }
}
