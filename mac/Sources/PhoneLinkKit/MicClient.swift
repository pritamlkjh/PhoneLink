import Foundation

/// Protocol models, stream controller, and E2E client for remote microphone audio.
public struct MicStartRequest: Codable, Sendable {
    public let sessionId: String
    public let sampleRateHz: UInt32
    public let channels: UInt32
    public let chunkDurationMs: UInt32

    public init(
        sessionId: String = UUID().uuidString,
        sampleRateHz: UInt32 = 16000,
        channels: UInt32 = 1,
        chunkDurationMs: UInt32 = 200
    ) {
        self.sessionId = sessionId
        self.sampleRateHz = sampleRateHz
        self.channels = channels
        self.chunkDurationMs = chunkDurationMs
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case sampleRateHz = "sample_rate_hz"
        case channels
        case chunkDurationMs = "chunk_duration_ms"
    }
}

public struct MicStartResponse: Codable, Sendable {
    public let sessionId: String
    public let status: String
    public let errorMessage: String?
    public let actualSampleRateHz: UInt32
    public let actualChannels: UInt32
    public let bitsPerSample: UInt32

    public init(
        sessionId: String,
        status: String,
        errorMessage: String? = nil,
        actualSampleRateHz: UInt32 = 0,
        actualChannels: UInt32 = 1,
        bitsPerSample: UInt32 = 16
    ) {
        self.sessionId = sessionId
        self.status = status
        self.errorMessage = errorMessage
        self.actualSampleRateHz = actualSampleRateHz
        self.actualChannels = actualChannels
        self.bitsPerSample = bitsPerSample
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case status
        case errorMessage = "error_message"
        case actualSampleRateHz = "actual_sample_rate_hz"
        case actualChannels = "actual_channels"
        case bitsPerSample = "bits_per_sample"
    }
}

public struct MicStopRequest: Codable, Sendable {
    public let sessionId: String
    public let reason: String

    public init(sessionId: String, reason: String = "user_stopped") {
        self.sessionId = sessionId
        self.reason = reason
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case reason
    }
}

public struct MicStopResponse: Codable, Sendable {
    public let sessionId: String
    public let status: String

    public init(sessionId: String, status: String) {
        self.sessionId = sessionId
        self.status = status
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case status
    }
}

public struct MicAudioChunk: Sendable {
    public let sessionId: String
    public let chunkNumber: UInt64
    public let timestampMs: Int64
    public let pcmData: Data
    public let sampleRateHz: UInt32
    public let channels: UInt32
    public let bitsPerSample: UInt32

    public init(
        sessionId: String,
        chunkNumber: UInt64,
        timestampMs: Int64,
        pcmData: Data,
        sampleRateHz: UInt32,
        channels: UInt32 = 1,
        bitsPerSample: UInt32 = 16
    ) {
        self.sessionId = sessionId
        self.chunkNumber = chunkNumber
        self.timestampMs = timestampMs
        self.pcmData = pcmData
        self.sampleRateHz = sampleRateHz
        self.channels = channels
        self.bitsPerSample = bitsPerSample
    }
}

public struct MicStreamStats: Sendable {
    public let chunksReceived: UInt64
    public let chunksDropped: UInt64
    public let bytesReceived: UInt64
    public let lastLatencyMs: Int64
    public let averageLatencyMs: Double
    public let rateKbps: Double
    public let elapsedSeconds: Double

    public init(
        chunksReceived: UInt64,
        chunksDropped: UInt64,
        bytesReceived: UInt64,
        lastLatencyMs: Int64,
        averageLatencyMs: Double,
        rateKbps: Double,
        elapsedSeconds: Double
    ) {
        self.chunksReceived = chunksReceived
        self.chunksDropped = chunksDropped
        self.bytesReceived = bytesReceived
        self.lastLatencyMs = lastLatencyMs
        self.averageLatencyMs = averageLatencyMs
        self.rateKbps = rateKbps
        self.elapsedSeconds = elapsedSeconds
    }
}

public struct MicStreamSummary: Codable, Sendable {
    public let sessionId: String
    public let totalChunks: UInt64
    public let droppedChunks: UInt64
    public let totalBytes: UInt64
    public let actualSampleRateHz: UInt32
    public let actualChannels: UInt32
    public let bitsPerSample: UInt32
    public let averageLatencyMs: Double
    public let durationSeconds: Double
    public let stopReason: String

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case totalChunks = "total_chunks"
        case droppedChunks = "dropped_chunks"
        case totalBytes = "total_bytes"
        case actualSampleRateHz = "actual_sample_rate_hz"
        case actualChannels = "actual_channels"
        case bitsPerSample = "bits_per_sample"
        case averageLatencyMs = "average_latency_ms"
        case durationSeconds = "duration_seconds"
        case stopReason = "stop_reason"
    }
}

/// Thread-safe handle allowing CLI signal handlers to cleanly request mic teardown.
public final class MicStreamControl: @unchecked Sendable {
    private let lock = NSLock()
    private var pendingStopReason: String? = nil
    private var stopCallback: (@Sendable (String) -> Void)? = nil
    private var preConnectCancelCallback: (@Sendable (String) -> Void)? = nil

    public init() {}

    public func attachPreConnectCancelHandler(_ handler: @escaping @Sendable (String) -> Void) {
        let pending = lock.withLock { () -> String? in
            preConnectCancelCallback = handler
            return stopCallback == nil ? pendingStopReason : nil
        }
        if let reason = pending {
            handler(reason)
        }
    }

    public func attachStopHandler(_ handler: @escaping @Sendable (String) -> Void) {
        let pending: String? = lock.withLock {
            stopCallback = handler
            return pendingStopReason
        }
        if let reason = pending {
            handler(reason)
        }
    }

    public func requestStop(reason: String = "user_stopped") {
        let (handler, preCb): ((@Sendable (String) -> Void)?, (@Sendable (String) -> Void)?) = lock.withLock {
            if pendingStopReason == nil {
                pendingStopReason = reason
            }
            return (stopCallback, preConnectCancelCallback)
        }
        if let handler {
            handler(reason)
        } else {
            preCb?(reason)
        }
    }
}

public final class MicClient: @unchecked Sendable {
    public static let schemaVersion: Int = 1

    public static func buildMicStartRequest(
        sessionId: String = UUID().uuidString,
        sampleRateHz: UInt32 = 16000,
        channels: UInt32 = 1,
        chunkDurationMs: UInt32 = 200
    ) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "mic_start_req": [
                "session_id": sessionId,
                "sample_rate_hz": sampleRateHz,
                "channels": channels,
                "chunk_duration_ms": chunkDurationMs
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    public static func parseMicStartResponse(data: Data) throws -> MicStartResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let obj = json["mic_start_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing mic_start_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: obj)
        return try JSONDecoder().decode(MicStartResponse.self, from: subData)
    }

    public static func buildMicStopRequest(sessionId: String, reason: String = "user_stopped") throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "mic_stop_req": [
                "session_id": sessionId,
                "reason": reason
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    public static func parseMicStopResponse(data: Data) throws -> MicStopResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let obj = json["mic_stop_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing mic_stop_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: obj)
        return try JSONDecoder().decode(MicStopResponse.self, from: subData)
    }

    public static func parseMicAudioChunk(data: Data) throws -> MicAudioChunk {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let obj = json["mic_chunk"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing mic_chunk in decrypted payload")
        }
        let sessionId = obj["session_id"] as? String ?? ""
        let chunkNumber = (obj["chunk_number"] as? NSNumber)?.uint64Value ?? 0
        let timestampMs = (obj["timestamp_ms"] as? NSNumber)?.int64Value ?? 0
        let dataB64 = obj["data"] as? String ?? ""
        guard let pcmData = Data(base64Encoded: dataB64) else {
            throw AuthClientError.invalidResponse("Invalid base64 PCM data in mic_chunk")
        }
        let sampleRate = (obj["sample_rate_hz"] as? NSNumber)?.uint32Value ?? 16000
        let channels = (obj["channels"] as? NSNumber)?.uint32Value ?? 1
        let bits = (obj["bits_per_sample"] as? NSNumber)?.uint32Value ?? 16

        return MicAudioChunk(
            sessionId: sessionId,
            chunkNumber: chunkNumber,
            timestampMs: timestampMs,
            pcmData: pcmData,
            sampleRateHz: sampleRate,
            channels: channels,
            bitsPerSample: bits
        )
    }

    /// Streams encrypted PCM audio chunks from Android over the VPS relay.
    public static func streamMic(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        sampleRateHz: UInt32 = 16000,
        channels: UInt32 = 1,
        chunkDurationMs: UInt32 = 200,
        maxDurationSeconds: Double = 15.0,
        maxChunks: UInt64? = nil,
        control: MicStreamControl? = nil,
        onStarted: (@Sendable (MicStartResponse) -> Void)? = nil,
        onChunk: @escaping @Sendable (MicAudioChunk, MicStreamStats) -> Void,
        onStatusChange: (@Sendable (String) -> Void)? = nil
    ) async throws -> MicStreamSummary {
        onStatusChange?("Connecting to VPS relay...")
        let session = try await E2ETransportSession.connectAndAuthenticate(
            vpsBaseURL: vpsBaseURL,
            identity: identity,
            client: client,
            presenceTimeoutSeconds: 3.0
        )

        onStatusChange?("Establishing end-to-end encryption...")
        let state = MicStreamingSessionState()
        let activeSessionId = UUID().uuidString
        state.setSessionId(activeSessionId)

        let safeMaxDuration = (maxDurationSeconds.isFinite && maxDurationSeconds > 0) ? min(maxDurationSeconds, 300.0) : 0
        let effectiveTimeout = safeMaxDuration > 0 ? safeMaxDuration + 10.0 : 310.0

        control?.attachPreConnectCancelHandler { reason in
            state.setStopReason(reason)
            session.disconnect()
        }

        defer {
            state.cancelTasks()
        }

        return try await session.runSession(
            timeoutSeconds: effectiveTimeout,
            timeoutMessage: "Timed out waiting for microphone stream",
            onReady: { activeSession in
                onStatusChange?("Starting microphone stream on Android...")
                let reqData = try buildMicStartRequest(
                    sessionId: activeSessionId,
                    sampleRateHz: sampleRateHz,
                    channels: channels,
                    chunkDurationMs: chunkDurationMs
                )
                try await activeSession.sendEncrypted(plaintext: reqData)
            },
            onPayload: { decrypted, activeSession, finish in
                guard let payloadObj = try JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
                    return
                }

                let sendStopRequest: @Sendable (String) -> Void = { reason in
                    guard state.markStopSent(reason: reason) else { return }
                    onStatusChange?("Stopping microphone stream (\(reason))...")

                    let task = Task {
                        do {
                            let stopData = try buildMicStopRequest(sessionId: activeSessionId, reason: reason)
                            try await activeSession.sendEncrypted(plaintext: stopData)
                            try? await Task.sleep(nanoseconds: 1_500_000_000)
                            finish(.success(state.buildSummary()))
                        } catch {
                            finish(.success(state.buildSummary()))
                        }
                    }
                    state.trackTask(task)
                }

                if payloadObj["mic_start_resp"] != nil {
                    let startResp = try parseMicStartResponse(data: decrypted)
                    guard startResp.sessionId == activeSessionId else { return }
                    if startResp.status != "STATUS_OK" {
                        let errMsg = startResp.errorMessage ?? startResp.status
                        finish(.failure(AuthClientError.invalidResponse("Mic start rejected: \(startResp.status) - \(errMsg)")))
                        return
                    }

                    state.markStarted(format: startResp)
                    onStarted?(startResp)
                    onStatusChange?("Microphone streaming active (\(startResp.actualSampleRateHz) Hz mono)")
                    control?.attachStopHandler(sendStopRequest)

                    if safeMaxDuration > 0 {
                        let task = Task {
                            let ns = UInt64(safeMaxDuration * 1_000_000_000)
                            try? await Task.sleep(nanoseconds: ns)
                            guard !Task.isCancelled else { return }
                            sendStopRequest("duration_completed")
                        }
                        state.trackTask(task)
                    }
                } else if payloadObj["mic_chunk"] != nil {
                    let chunk = try parseMicAudioChunk(data: decrypted)
                    guard chunk.sessionId == activeSessionId else { return }
                    let (stats, count) = state.recordChunk(chunk: chunk)
                    onChunk(chunk, stats)

                    if let maxC = maxChunks, count >= maxC {
                        sendStopRequest("max_chunks_reached")
                    }
                } else if payloadObj["mic_stop_resp"] != nil {
                    let stopResp = try parseMicStopResponse(data: decrypted)
                    guard stopResp.sessionId == activeSessionId else { return }
                    finish(.success(state.buildSummary()))
                } else if let errObj = payloadObj["error"] as? [String: Any] {
                    let msg = errObj["message"] as? String ?? "Android error"
                    finish(.failure(AuthClientError.invalidResponse("Remote error: \(msg)")))
                }
            },
            onTerminalState: { newState, finish in
                switch newState {
                case .peerOffline, .disconnected, .error:
                    if state.isStopAlreadySent() {
                        finish(.success(state.buildSummary()))
                    }
                default:
                    break
                }
            }
        )
    }
}

private final class MicStreamingSessionState: @unchecked Sendable {
    private let lock = NSLock()
    private var sessionId: String = ""
    private var isStopSent = false
    private var isTerminated = false
    private var startTime: Date? = nil
    private var actualSampleRateHz: UInt32 = 16000
    private var actualChannels: UInt32 = 1
    private var bitsPerSample: UInt32 = 16
    private var chunksReceived: UInt64 = 0
    private var chunksDropped: UInt64 = 0
    private var totalBytes: UInt64 = 0
    private var totalLatencyMs: Int64 = 0
    private var expectedNextChunk: UInt64 = 1
    private var stopReason: String = "completed"
    private var backgroundTasks: [Task<Void, Never>] = []

    func setSessionId(_ id: String) {
        lock.withLock { sessionId = id }
    }

    func trackTask(_ task: Task<Void, Never>) {
        let cancel = lock.withLock { () -> Bool in
            if isTerminated { return true }
            backgroundTasks.append(task)
            return false
        }
        if cancel { task.cancel() }
    }

    func cancelTasks() {
        let tasks = lock.withLock { () -> [Task<Void, Never>] in
            isTerminated = true
            let list = backgroundTasks
            backgroundTasks.removeAll()
            return list
        }
        tasks.forEach { $0.cancel() }
    }

    func isStopAlreadySent() -> Bool {
        lock.withLock { isStopSent }
    }

    func markStarted(format: MicStartResponse) {
        lock.withLock {
            if startTime == nil { startTime = Date() }
            if format.actualSampleRateHz > 0 { actualSampleRateHz = format.actualSampleRateHz }
            if format.actualChannels > 0 { actualChannels = format.actualChannels }
            if format.bitsPerSample > 0 { bitsPerSample = format.bitsPerSample }
        }
    }

    func hasStarted() -> Bool {
        lock.withLock { startTime != nil }
    }

    func setStopReason(_ reason: String) {
        lock.withLock { stopReason = reason }
    }

    func recordChunk(chunk: MicAudioChunk) -> (MicStreamStats, UInt64) {
        lock.withLock {
            if startTime == nil { startTime = Date() }
            let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
            let rawLatency = nowMs.subtractingReportingOverflow(chunk.timestampMs)
            let latencyMs = rawLatency.overflow ? 0 : max(0, rawLatency.partialValue)
            totalLatencyMs = totalLatencyMs &+ latencyMs

            if chunk.chunkNumber > expectedNextChunk {
                chunksDropped &+= (chunk.chunkNumber - expectedNextChunk)
            }
            expectedNextChunk = chunk.chunkNumber == UInt64.max ? UInt64.max : (chunk.chunkNumber + 1)
            chunksReceived += 1
            totalBytes += UInt64(chunk.pcmData.count)

            let elapsed = max(0.001, Date().timeIntervalSince(startTime!))
            let avgLatency = Double(totalLatencyMs) / Double(chunksReceived)
            let rateKbps = (Double(totalBytes) * 8.0) / elapsed / 1000.0

            let stats = MicStreamStats(
                chunksReceived: chunksReceived,
                chunksDropped: chunksDropped,
                bytesReceived: totalBytes,
                lastLatencyMs: latencyMs,
                averageLatencyMs: avgLatency,
                rateKbps: rateKbps,
                elapsedSeconds: elapsed
            )
            return (stats, chunksReceived)
        }
    }

    func markStopSent(reason: String) -> Bool {
        lock.withLock {
            if isStopSent { return false }
            isStopSent = true
            stopReason = reason
            return true
        }
    }

    func buildSummary() -> MicStreamSummary {
        lock.withLock {
            let elapsed = startTime != nil ? Date().timeIntervalSince(startTime!) : 0
            let avgLatency = chunksReceived > 0 ? Double(totalLatencyMs) / Double(chunksReceived) : 0
            return MicStreamSummary(
                sessionId: sessionId,
                totalChunks: chunksReceived,
                droppedChunks: chunksDropped,
                totalBytes: totalBytes,
                actualSampleRateHz: actualSampleRateHz,
                actualChannels: actualChannels,
                bitsPerSample: bitsPerSample,
                averageLatencyMs: avgLatency,
                durationSeconds: elapsed,
                stopReason: stopReason
            )
        }
    }
}
