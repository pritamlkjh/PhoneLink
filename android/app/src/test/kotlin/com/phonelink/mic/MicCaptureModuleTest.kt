package com.phonelink.mic

import com.phonelink.identity.InMemorySharedPreferences
import com.phonelink.storage.SecureStorage
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class MicCaptureModuleTest {

    private lateinit var storage: SecureStorage
    private var osPermissionGranted = false
    private lateinit var authGate: MicAuthorizationGate
    private lateinit var testMicSource: TestMicSource
    private lateinit var testServiceController: TestServiceController
    private lateinit var module: MicCaptureModule

    class TestServiceController(
        var allowForegroundPromotion: Boolean = true
    ) : MicCaptureModule.ForegroundServiceController {
        val startedCount = AtomicInteger(0)
        val stoppedCount = AtomicInteger(0)

        override fun onMicCaptureStarted() {
            startedCount.incrementAndGet()
        }

        override fun onMicCaptureStopped() {
            stoppedCount.incrementAndGet()
        }

        override fun isMicForegroundReady(): Boolean = allowForegroundPromotion
    }

    class TestMicSource : MicCaptureModule.MicSource {
        val capturing = AtomicBoolean(false)
        var lastRequestedRate: Int = 0
        var lastChunkMs: Int = 0
        var chunkEmitter: ((ByteArray, Int, Int, Int) -> Unit)? = null
        var dropEmitter: (() -> Unit)? = null

        override fun open(
            sampleRateHz: Int,
            channels: Int,
            chunkDurationMs: Int,
            onChunk: (pcmData: ByteArray, sampleRateHz: Int, channels: Int, bitsPerSample: Int) -> Unit,
            onDroppedChunk: () -> Unit
        ): Result<MicCaptureModule.ActualAudioFormat> {
            capturing.set(true)
            lastRequestedRate = sampleRateHz
            lastChunkMs = chunkDurationMs
            chunkEmitter = onChunk
            dropEmitter = onDroppedChunk

            val mockPcm = ByteArray(320) { 0x11 }
            onChunk(mockPcm, sampleRateHz, channels, MicCaptureModule.DEFAULT_BITS_PER_SAMPLE)
            return Result.success(MicCaptureModule.ActualAudioFormat(sampleRateHz, channels, MicCaptureModule.DEFAULT_BITS_PER_SAMPLE))
        }

        override fun close() {
            capturing.set(false)
            chunkEmitter = null
            dropEmitter = null
        }

        override fun isCapturing(): Boolean = capturing.get()
    }

    @Before
    fun setUp() {
        storage = SecureStorage(InMemorySharedPreferences())
        osPermissionGranted = false
        storage.setMicAllowed(false)

        authGate = MicAuthorizationGate(storage) { osPermissionGranted }
        testMicSource = TestMicSource()
        testServiceController = TestServiceController()
        module = MicCaptureModule(
            micAuthGate = authGate,
            micSource = testMicSource,
            serviceController = testServiceController,
            maxSessionDurationSeconds = 60
        )
    }

    @Test
    fun testMicStartRejectedWhenGatesFail() {
        val req = MicCaptureModule.MicStartRequestDto(sessionId = "mic-1")
        val bothOff = module.startCapture(req) {}
        assertEquals(MicCaptureModule.STATUS_MIC_PERMISSION_DENIED, bothOff.status)
        assertEquals(0, testServiceController.startedCount.get())

        osPermissionGranted = true
        val toggleOff = module.startCapture(req) {}
        assertEquals(MicCaptureModule.STATUS_MIC_TOGGLE_DISABLED, toggleOff.status)
        assertFalse(testMicSource.isCapturing())
    }

    @Test
    fun testMicStartAndStopLifecycleWithDualGateAuthorized() {
        osPermissionGranted = true
        storage.setMicAllowed(true)

        val chunks = mutableListOf<MicCaptureModule.MicAudioChunkDto>()
        val req = MicCaptureModule.MicStartRequestDto(
            sessionId = "mic-2",
            sampleRateHz = 96000, // Expect clamped to 48000
            channels = 1,
            chunkDurationMs = 200
        )
        val startResp = module.startCapture(req) { chunk -> chunks.add(chunk) }
        assertEquals(MicCaptureModule.STATUS_OK, startResp.status)
        assertEquals(MicCaptureModule.MAX_SAMPLE_RATE_HZ, startResp.actualSampleRateHz)
        assertTrue(module.isCapturing())
        assertEquals(1, chunks.size)
        assertEquals(1L, chunks[0].chunkNumber)
        assertEquals(1, testServiceController.startedCount.get())

        testMicSource.dropEmitter?.invoke()
        assertEquals(1L, module.getDroppedChunks())

        val stopResp = module.stopCapture("mic-2", "done")
        assertEquals(MicCaptureModule.STATUS_OK, stopResp.status)
        assertFalse(module.isCapturing())
        assertFalse(testMicSource.isCapturing())
        assertEquals(1, testServiceController.stoppedCount.get())
    }

    @Test
    fun testMicFailsFastWhenForegroundServiceBlocked() {
        osPermissionGranted = true
        storage.setMicAllowed(true)
        testServiceController.allowForegroundPromotion = false

        val resp = module.startCapture(MicCaptureModule.MicStartRequestDto("mic-fgs-blocked")) {}
        assertEquals(MicCaptureModule.STATUS_MIC_PERMISSION_DENIED, resp.status)
        assertTrue(resp.errorMessage.contains("open PhoneLink on screen"))
        assertFalse(testMicSource.isCapturing())
        assertEquals(1, testServiceController.stoppedCount.get())
    }

    @Test
    fun testServiceRolledBackWhenMicSourceOpenFails() {
        osPermissionGranted = true
        storage.setMicAllowed(true)

        var sawElevated = false
        val brokenSource = object : MicCaptureModule.MicSource {
            override fun open(
                sampleRateHz: Int,
                channels: Int,
                chunkDurationMs: Int,
                onChunk: (ByteArray, Int, Int, Int) -> Unit,
                onDroppedChunk: () -> Unit
            ): Result<MicCaptureModule.ActualAudioFormat> {
                sawElevated = testServiceController.startedCount.get() == 1
                return Result.failure(IllegalStateException("AudioRecord busy"))
            }
            override fun close() {}
            override fun isCapturing(): Boolean = false
        }

        val brokenModule = MicCaptureModule(authGate, brokenSource, testServiceController)
        val resp = brokenModule.startCapture(MicCaptureModule.MicStartRequestDto("mic-fail-open")) {}
        assertEquals(MicCaptureModule.STATUS_ERROR_UNKNOWN, resp.status)
        assertTrue(sawElevated)
        assertEquals(1, testServiceController.startedCount.get())
        assertEquals(1, testServiceController.stoppedCount.get())
        assertFalse(brokenModule.isCapturing())
    }

    @Test
    fun testMicWatchdogAutoDeactivationAndApplicationDispatch() {
        osPermissionGranted = true
        storage.setMicAllowed(true)

        val watchdogModule = MicCaptureModule(authGate, testMicSource, testServiceController, maxSessionDurationSeconds = 1)
        val emitted = mutableListOf<ByteArray>()

        val reqJson = JSONObject().apply {
            put("schema_version", 1)
            put("mic_start_req", JSONObject().apply {
                put("session_id", "mic-wd")
                put("sample_rate_hz", 16000)
                put("channels", 1)
                put("chunk_duration_ms", 200)
            })
        }.toString().toByteArray(Charsets.UTF_8)

        val startBytes = watchdogModule.processApplicationMessage(reqJson) { msg ->
            emitted.add(msg)
            true
        }
        assertNotNull(startBytes)
        val startJson = JSONObject(String(startBytes!!, Charsets.UTF_8)).getJSONObject("mic_start_resp")
        assertEquals(MicCaptureModule.STATUS_OK, startJson.getString("status"))
        assertEquals(16000, startJson.getInt("actual_sample_rate_hz"))
        assertTrue(emitted.isNotEmpty())

        Thread.sleep(1250)
        assertFalse(watchdogModule.isCapturing())
        assertFalse(testMicSource.isCapturing())
    }

    @Test
    fun testBuildSampleRateCandidatesIncludesRequestedAndFallbacks() {
        val candidates = AndroidMicSource.buildSampleRateCandidates(22050)
        assertEquals(listOf(22050, 16000, 44100, 48000), candidates)
        assertEquals(listOf(16000, 44100, 48000), AndroidMicSource.buildSampleRateCandidates(16000))
    }
}
