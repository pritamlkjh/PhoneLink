package com.phonelink.mic

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioRecordingConfiguration
import android.media.MediaRecorder
import android.os.Build
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Remote Microphone Capture Module.
 *
 * Captures mono 16-bit PCM chunks under strict dual-gate consent and active
 * FOREGROUND_SERVICE_TYPE_MICROPHONE lifecycle enforcement.
 */
class MicCaptureModule(
    private val micAuthGate: MicAuthorizationGate,
    private val micSource: MicSource? = null,
    private val serviceController: ForegroundServiceController? = null,
    private val maxSessionDurationSeconds: Long = DEFAULT_MAX_SESSION_DURATION_SECONDS
) {
    companion object {
        const val SCHEMA_VERSION = 1

        const val STATUS_OK = "STATUS_OK"
        const val STATUS_ERROR_UNKNOWN = "STATUS_ERROR_UNKNOWN"
        const val STATUS_INVALID_ARGUMENT = "STATUS_INVALID_ARGUMENT"
        const val STATUS_MIC_PERMISSION_DENIED = "STATUS_MIC_PERMISSION_DENIED"
        const val STATUS_MIC_TOGGLE_DISABLED = "STATUS_MIC_TOGGLE_DISABLED"

        const val DEFAULT_SAMPLE_RATE_HZ = 16000
        const val MIN_SAMPLE_RATE_HZ = 8000
        const val MAX_SAMPLE_RATE_HZ = 48000
        const val DEFAULT_CHANNELS = 1
        const val DEFAULT_BITS_PER_SAMPLE = 16
        const val DEFAULT_CHUNK_DURATION_MS = 200
        const val MIN_CHUNK_DURATION_MS = 50
        const val MAX_CHUNK_DURATION_MS = 1000
        const val DEFAULT_MAX_SESSION_DURATION_SECONDS = 300L
    }

    data class MicStartRequestDto(
        val sessionId: String,
        val sampleRateHz: Int = DEFAULT_SAMPLE_RATE_HZ,
        val channels: Int = DEFAULT_CHANNELS,
        val chunkDurationMs: Int = DEFAULT_CHUNK_DURATION_MS
    )

    data class MicStartResponseDto(
        val sessionId: String,
        val status: String,
        val errorMessage: String = "",
        val actualSampleRateHz: Int = 0,
        val actualChannels: Int = DEFAULT_CHANNELS,
        val bitsPerSample: Int = DEFAULT_BITS_PER_SAMPLE
    )

    data class MicStopRequestDto(
        val sessionId: String,
        val reason: String = "user_stopped"
    )

    data class MicStopResponseDto(
        val sessionId: String,
        val status: String
    )

    data class MicAudioChunkDto(
        val sessionId: String,
        val chunkNumber: Long,
        val timestampMs: Long,
        val pcmData: ByteArray,
        val sampleRateHz: Int,
        val channels: Int,
        val bitsPerSample: Int
    )

    data class ActualAudioFormat(
        val sampleRateHz: Int,
        val channels: Int = DEFAULT_CHANNELS,
        val bitsPerSample: Int = DEFAULT_BITS_PER_SAMPLE
    )

    interface ForegroundServiceController {
        fun onMicCaptureStarted()
        fun onMicCaptureStopped()
        fun isMicForegroundReady(): Boolean = true
    }

    interface MicSource {
        fun open(
            sampleRateHz: Int,
            channels: Int,
            chunkDurationMs: Int,
            onChunk: (pcmData: ByteArray, sampleRateHz: Int, channels: Int, bitsPerSample: Int) -> Unit,
            onDroppedChunk: () -> Unit = {}
        ): Result<ActualAudioFormat>

        fun close()
        fun isCapturing(): Boolean

        fun setUnexpectedStopListener(listener: ((reason: String) -> Unit)?) {}
    }

    private val isCapturing = AtomicBoolean(false)
    private var activeSessionId: String? = null
    private var activeMicSource: MicSource? = null
    private var activeSendAppMsg: ((ByteArray) -> Boolean)? = null
    private val chunkSequence = AtomicLong(0)
    private val deliveredChunks = AtomicLong(0)
    private val droppedChunks = AtomicLong(0)

    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "PhoneLink-MicWatchdog").apply { isDaemon = true }
    }
    private var sessionTimeoutTask: ScheduledFuture<*>? = null

    fun isCapturing(): Boolean = isCapturing.get()
    fun getActiveSessionId(): String? = activeSessionId
    fun getDeliveredChunks(): Long = deliveredChunks.get()
    fun getDroppedChunks(): Long = droppedChunks.get()

    /** Resets per-session chunk delivery metrics. */
    fun resetMetrics() {
        deliveredChunks.set(0)
        droppedChunks.set(0)
    }

    /** Starts an authorized microphone capture session after passing both consent gates. */
    @Synchronized
    fun startCapture(
        request: MicStartRequestDto,
        onChunk: (MicAudioChunkDto) -> Unit
    ): MicStartResponseDto {
        val decision = micAuthGate.evaluateRemoteActivation()
        if (!decision.isAuthorized) {
            val status = when (decision.status) {
                MicAuthorizationGate.AuthorizationStatus.DENIED_OS_PERMISSION_MISSING,
                MicAuthorizationGate.AuthorizationStatus.DENIED_BOTH_GATES_FAILED -> STATUS_MIC_PERMISSION_DENIED
                MicAuthorizationGate.AuthorizationStatus.DENIED_IN_APP_TOGGLE_DISABLED -> STATUS_MIC_TOGGLE_DISABLED
                else -> STATUS_MIC_PERMISSION_DENIED
            }
            return MicStartResponseDto(
                sessionId = request.sessionId,
                status = status,
                errorMessage = decision.reason
            )
        }

        if (isCapturing.get()) {
            stopCapture(activeSessionId ?: request.sessionId, "superseded_by_new_session")
        }

        val targetRate = request.sampleRateHz.coerceIn(MIN_SAMPLE_RATE_HZ, MAX_SAMPLE_RATE_HZ)
        val channels = DEFAULT_CHANNELS
        val chunkMs = request.chunkDurationMs.coerceIn(MIN_CHUNK_DURATION_MS, MAX_CHUNK_DURATION_MS)

        resetMetrics()
        isCapturing.set(true)
        activeSessionId = request.sessionId
        chunkSequence.set(0)

        val source = micSource ?: DefaultMockMicSource()
        activeMicSource = source
        source.setUnexpectedStopListener { reason ->
            val currentSession = activeSessionId
            if (isCapturing.get() && currentSession == request.sessionId) {
                val stopResp = stopCapture(request.sessionId, reason)
                val notifier = activeSendAppMsg
                if (notifier != null) {
                    try {
                        notifier(serializeMicStopResponse(stopResp))
                    } catch (_: Exception) {}
                }
            }
        }

        // Promote foreground service before opening AudioRecord so Android 14-16 FGS rules see MICROPHONE active.
        serviceController?.onMicCaptureStarted()
        if (serviceController != null && !serviceController.isMicForegroundReady()) {
            isCapturing.set(false)
            activeSessionId = null
            activeMicSource = null
            serviceController.onMicCaptureStopped()
            return MicStartResponseDto(
                sessionId = request.sessionId,
                status = STATUS_MIC_PERMISSION_DENIED,
                errorMessage = "Android blocked background microphone access: unlock the phone and open PhoneLink on screen before starting mic stream."
            )
        }

        val openResult = source.open(
            sampleRateHz = targetRate,
            channels = channels,
            chunkDurationMs = chunkMs,
            onChunk = { pcmData, actualRate, actualChannels, bits ->
                if (!isCapturing.get()) return@open
                val chunkNum = chunkSequence.incrementAndGet()
                val dto = MicAudioChunkDto(
                    sessionId = request.sessionId,
                    chunkNumber = chunkNum,
                    timestampMs = System.currentTimeMillis(),
                    pcmData = pcmData,
                    sampleRateHz = actualRate,
                    channels = actualChannels,
                    bitsPerSample = bits
                )
                onChunk(dto)
                deliveredChunks.incrementAndGet()
            },
            onDroppedChunk = {
                droppedChunks.incrementAndGet()
            }
        )

        if (openResult.isFailure) {
            isCapturing.set(false)
            activeSessionId = null
            activeMicSource = null
            serviceController?.onMicCaptureStopped()
            return MicStartResponseDto(
                sessionId = request.sessionId,
                status = STATUS_ERROR_UNKNOWN,
                errorMessage = openResult.exceptionOrNull()?.message ?: "Failed to open microphone hardware"
            )
        }

        val actualFormat = openResult.getOrThrow()

        val watchdogSessionId = request.sessionId
        sessionTimeoutTask?.cancel(false)
        val watchdogSeconds = maxSessionDurationSeconds.coerceIn(1L, DEFAULT_MAX_SESSION_DURATION_SECONDS)
        sessionTimeoutTask = scheduler.schedule({
            if (!isCapturing.get() || activeSessionId != watchdogSessionId) {
                return@schedule
            }
            val stopResp = stopCapture(watchdogSessionId, "session_timeout")
            val notifier = activeSendAppMsg
            if (notifier != null) {
                try {
                    notifier(serializeMicStopResponse(stopResp))
                } catch (_: Exception) {}
            }
        }, watchdogSeconds, TimeUnit.SECONDS)

        return MicStartResponseDto(
            sessionId = request.sessionId,
            status = STATUS_OK,
            actualSampleRateHz = actualFormat.sampleRateHz,
            actualChannels = actualFormat.channels,
            bitsPerSample = actualFormat.bitsPerSample
        )
    }

    private var lastStopReason: String? = null

    /** Immediately stops microphone capture and releases hardware resources. */
    @Synchronized
    fun stopCapture(sessionId: String, reason: String = "user_stopped"): MicStopResponseDto {
        if (reason == "session_timeout" && sessionId.isNotEmpty() && activeSessionId != null && activeSessionId != sessionId) {
            return MicStopResponseDto(sessionId = sessionId, status = STATUS_OK)
        }
        sessionTimeoutTask?.cancel(false)
        sessionTimeoutTask = null
        lastStopReason = reason

        val wasCapturing = isCapturing.getAndSet(false)
        activeSessionId = null

        val source = activeMicSource ?: micSource
        activeMicSource = null
        source?.setUnexpectedStopListener(null)
        source?.close()

        if (wasCapturing) {
            serviceController?.onMicCaptureStopped()
        }

        return MicStopResponseDto(
            sessionId = sessionId,
            status = STATUS_OK
        )
    }

    fun shutdown() {
        stopCapture(activeSessionId ?: "shutdown", "shutdown")
        activeSendAppMsg = null
        scheduler.shutdownNow()
    }

    /** Dispatches decrypted ApplicationMessage payloads targeting microphone streaming. */
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

        if (json.has("mic_start_req")) {
            val req = json.getJSONObject("mic_start_req")
            val sessionId = req.optString("session_id", UUID.randomUUID().toString())
            val sampleRate = req.optInt("sample_rate_hz", DEFAULT_SAMPLE_RATE_HZ)
            val channels = req.optInt("channels", DEFAULT_CHANNELS)
            val chunkMs = req.optInt("chunk_duration_ms", DEFAULT_CHUNK_DURATION_MS)

            activeSendAppMsg = sendAppMsg
            val resp = startCapture(
                MicStartRequestDto(
                    sessionId = sessionId,
                    sampleRateHz = sampleRate,
                    channels = channels,
                    chunkDurationMs = chunkMs
                )
            ) { chunk ->
                sendAppMsg?.invoke(serializeMicAudioChunk(chunk))
            }
            return serializeMicStartResponse(resp)
        }

        if (json.has("mic_stop_req")) {
            val req = json.getJSONObject("mic_stop_req")
            val sessionId = req.optString("session_id", activeSessionId ?: "")
            val reason = req.optString("reason", "user_stopped")
            val resp = stopCapture(sessionId, reason)
            return serializeMicStopResponse(resp)
        }

        return null
    }

    fun serializeMicStartResponse(dto: MicStartResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())
            val resp = JSONObject().apply {
                put("session_id", dto.sessionId)
                put("status", dto.status)
                put("actual_sample_rate_hz", dto.actualSampleRateHz)
                put("actual_channels", dto.actualChannels)
                put("bits_per_sample", dto.bitsPerSample)
                if (dto.errorMessage.isNotEmpty()) {
                    put("error_message", dto.errorMessage)
                }
            }
            put("mic_start_resp", resp)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun serializeMicStopResponse(dto: MicStopResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())
            val resp = JSONObject().apply {
                put("session_id", dto.sessionId)
                put("status", dto.status)
            }
            put("mic_stop_resp", resp)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun serializeMicAudioChunk(chunk: MicAudioChunkDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", chunk.timestampMs)
            val body = JSONObject().apply {
                put("session_id", chunk.sessionId)
                put("chunk_number", chunk.chunkNumber)
                put("timestamp_ms", chunk.timestampMs)
                put("data", Base64.getEncoder().encodeToString(chunk.pcmData))
                put("sample_rate_hz", chunk.sampleRateHz)
                put("channels", chunk.channels)
                put("bits_per_sample", chunk.bitsPerSample)
            }
            put("mic_chunk", body)
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    open class DefaultMockMicSource(
        private val isStreaming: Boolean = false
    ) : MicSource {
        private val capturing = AtomicBoolean(false)
        private var scheduledTask: ScheduledFuture<*>? = null
        private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "PhoneLink-MockMic").apply { isDaemon = true }
        }

        override fun open(
            sampleRateHz: Int,
            channels: Int,
            chunkDurationMs: Int,
            onChunk: (pcmData: ByteArray, sampleRateHz: Int, channels: Int, bitsPerSample: Int) -> Unit,
            onDroppedChunk: () -> Unit
        ): Result<ActualAudioFormat> {
            capturing.set(true)
            val frameSamples = maxOf(160, (sampleRateHz * chunkDurationMs) / 1000)
            val syntheticPcm = ByteArray(frameSamples * channels * 2) { i -> ((i * 7) and 0x7F).toByte() }
            onChunk(syntheticPcm, sampleRateHz, channels, MicCaptureModule.DEFAULT_BITS_PER_SAMPLE)

            if (isStreaming) {
                val intervalMs = chunkDurationMs.toLong().coerceAtLeast(50L)
                scheduledTask = scheduler.scheduleAtFixedRate({
                    if (capturing.get()) {
                        onChunk(syntheticPcm, sampleRateHz, channels, MicCaptureModule.DEFAULT_BITS_PER_SAMPLE)
                    }
                }, intervalMs, intervalMs, TimeUnit.MILLISECONDS)
            }
            return Result.success(ActualAudioFormat(sampleRateHz, channels, MicCaptureModule.DEFAULT_BITS_PER_SAMPLE))
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
 * Android AudioRecord Hardware Source.
 * Probes supported sample rates cleanly and decouples hardware reads from WebSocket sends
 * using a bounded queue so audio capture never blocks on slow relay links.
 */
class AndroidMicSource(private val context: Context) : MicCaptureModule.MicSource {
    private val micLock = Any()
    private val capturing = AtomicBoolean(false)
    @Volatile private var unexpectedStopListener: ((String) -> Unit)? = null
    private var audioRecord: AudioRecord? = null
    private var captureThread: Thread? = null
    private var senderThread: Thread? = null
    private var audioRecordingCallback: AudioManager.AudioRecordingCallback? = null

    override fun setUnexpectedStopListener(listener: ((reason: String) -> Unit)?) {
        unexpectedStopListener = listener
    }

    companion object {
        private const val QUEUE_CAPACITY = 16

        /** Builds an ordered list of candidate sample rates starting with the requested rate. */
        internal fun buildSampleRateCandidates(requestedRate: Int): List<Int> =
            listOf(requestedRate, MicCaptureModule.DEFAULT_SAMPLE_RATE_HZ, 44100, 48000).distinct()
    }

    @SuppressLint("MissingPermission")
    override fun open(
        sampleRateHz: Int,
        channels: Int,
        chunkDurationMs: Int,
        onChunk: (pcmData: ByteArray, sampleRateHz: Int, channels: Int, bitsPerSample: Int) -> Unit,
        onDroppedChunk: () -> Unit
    ): Result<MicCaptureModule.ActualAudioFormat> = synchronized(micLock) {
        if (context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            return Result.failure(SecurityException("RECORD_AUDIO runtime permission not granted"))
        }

        close()

        val channelConfig = AudioFormat.CHANNEL_IN_MONO
        val encoding = AudioFormat.ENCODING_PCM_16BIT

        var selectedRate = -1
        var minBufferBytes = 0
        for (candidate in buildSampleRateCandidates(sampleRateHz)) {
            val minBuf = AudioRecord.getMinBufferSize(candidate, channelConfig, encoding)
            if (minBuf > 0) {
                selectedRate = candidate
                minBufferBytes = minBuf
                break
            }
        }

        if (selectedRate <= 0 || minBufferBytes <= 0) {
            return Result.failure(IllegalStateException("AudioRecord unavailable for any supported sample rate"))
        }

        val chunkBytesRaw = (selectedRate * channels * 2 * chunkDurationMs) / 1000
        val chunkBytes = maxOf(640, (chunkBytesRaw / 2) * 2)
        val recordBufferBytes = maxOf(minBufferBytes * 2, chunkBytes * 4)

        val recorder = try {
            AudioRecord(
                MediaRecorder.AudioSource.MIC,
                selectedRate,
                channelConfig,
                encoding,
                recordBufferBytes
            )
        } catch (ex: Exception) {
            return Result.failure(IllegalStateException("Failed to create AudioRecord: ${ex.message}", ex))
        }

        if (recorder.state != AudioRecord.STATE_INITIALIZED) {
            try {
                recorder.release()
            } catch (_: Exception) {}
            return Result.failure(
                IllegalStateException("Microphone hardware unavailable or busy (check Quick Settings 'Mic access' or active calls)")
            )
        }

        return try {
            val queue = ArrayBlockingQueue<ByteArray>(QUEUE_CAPACITY)
            audioRecord = recorder
            capturing.set(true)
            recorder.startRecording()

            if (recorder.recordingState != AudioRecord.RECORDSTATE_RECORDING) {
                close()
                return Result.failure(
                    IllegalStateException("Microphone could not enter recording state (privacy switch or active call may be blocking access)")
                )
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val am = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
                if (am != null) {
                    val recSessionId = recorder.audioSessionId
                    val recCb = object : AudioManager.AudioRecordingCallback() {
                        override fun onRecordingConfigChanged(configs: List<AudioRecordingConfiguration>) {
                            val mine = configs.firstOrNull { it.clientAudioSessionId == recSessionId }
                            if (mine != null && mine.isClientSilenced && capturing.get()) {
                                capturing.set(false)
                                Executors.newSingleThreadExecutor { r ->
                                    Thread(r, "PhoneLink-MicSilenceStop").apply { isDaemon = true }
                                }.execute {
                                    close()
                                    unexpectedStopListener?.invoke("mic_silenced_by_system")
                                }
                            }
                        }
                    }
                    audioRecordingCallback = recCb
                    am.registerAudioRecordingCallback(recCb, Handler(Looper.getMainLooper()))
                }
            }

            val sender = Thread({
                while (capturing.get() || queue.isNotEmpty()) {
                    try {
                        val packet = queue.poll(100, TimeUnit.MILLISECONDS) ?: continue
                        if (!capturing.get()) break
                        onChunk(packet, selectedRate, channels, MicCaptureModule.DEFAULT_BITS_PER_SAMPLE)
                    } catch (_: InterruptedException) {
                        if (!capturing.get()) break
                    } catch (_: Exception) {
                        // Continue draining so capture thread does not stall
                    }
                }
            }, "PhoneLink-MicSender").apply { isDaemon = true }

            val reader = Thread({
                val frameBuf = ByteArray(chunkBytes)
                var filled = 0
                var errorReason: String? = null
                while (capturing.get()) {
                    val read = try {
                        recorder.read(frameBuf, filled, chunkBytes - filled)
                    } catch (_: Exception) {
                        errorReason = "mic_read_exception"
                        break
                    }
                    if (read < 0) {
                        errorReason = "mic_read_error_$read"
                        break
                    }
                    if (read == 0) {
                        try {
                            Thread.sleep(10)
                        } catch (_: InterruptedException) {
                            break
                        }
                        continue
                    }
                    filled += read
                    if (filled >= chunkBytes) {
                        val packet = frameBuf.copyOf(chunkBytes)
                        if (!queue.offer(packet)) {
                            queue.poll()
                            onDroppedChunk()
                            queue.offer(packet)
                        }
                        filled = 0
                    }
                }
                if (errorReason != null && capturing.get()) {
                    capturing.set(false)
                    val reasonCopy = errorReason
                    Executors.newSingleThreadExecutor { r ->
                        Thread(r, "PhoneLink-MicErrStop").apply { isDaemon = true }
                    }.execute {
                        close()
                        unexpectedStopListener?.invoke(reasonCopy)
                    }
                }
            }, "PhoneLink-MicCapture").apply { isDaemon = true }

            senderThread = sender
            captureThread = reader
            sender.start()
            reader.start()

            Result.success(MicCaptureModule.ActualAudioFormat(selectedRate, channels, MicCaptureModule.DEFAULT_BITS_PER_SAMPLE))
        } catch (ex: Exception) {
            close()
            Result.failure(ex)
        }
    }

    override fun close() = synchronized(micLock) {
        capturing.set(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            audioRecordingCallback?.let { cb ->
                try {
                    val am = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
                    am?.unregisterAudioRecordingCallback(cb)
                } catch (_: Exception) {}
            }
        }
        audioRecordingCallback = null

        val recorder = audioRecord
        if (recorder != null) {
            try {
                if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) {
                    recorder.stop()
                }
            } catch (_: Exception) {}
        }

        captureThread?.interrupt()
        senderThread?.interrupt()
        try {
            captureThread?.join(1500)
        } catch (_: Exception) {}
        try {
            senderThread?.join(500)
        } catch (_: Exception) {}
        captureThread = null
        senderThread = null

        if (recorder != null) {
            audioRecord = null
            try {
                recorder.release()
            } catch (_: Exception) {}
        }
    }

    override fun isCapturing(): Boolean = capturing.get()
}
