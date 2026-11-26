import Foundation

/// CAM-2 / CAM-3: PhoneLink Camera Protocol Client Models & Parser.
/// Implements strongly-typed request builders and response parsers for:
/// 1. camera_start_req / camera_start_resp
/// 2. camera_stop_req / camera_stop_resp
/// 3. camera_frame (streamed JPEG frames)

public enum CameraLens: String, Codable, Sendable {
    case back = "LENS_BACK"
    case front = "LENS_FRONT"
}

public struct CameraStartRequest: Codable, Sendable {
    public let sessionId: String
    public let lens: CameraLens
    public let targetFps: UInt32
    public let jpegQuality: UInt32
    public let maxWidth: UInt32
    public let maxHeight: UInt32

    public init(
        sessionId: String = UUID().uuidString,
        lens: CameraLens = .back,
        targetFps: UInt32 = 2,
        jpegQuality: UInt32 = 80,
        maxWidth: UInt32 = 1280,
        maxHeight: UInt32 = 720
    ) {
        self.sessionId = sessionId
        self.lens = lens
        self.targetFps = targetFps
        self.jpegQuality = jpegQuality
        self.maxWidth = maxWidth
        self.maxHeight = maxHeight
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case lens
        case targetFps = "target_fps"
        case jpegQuality = "jpeg_quality"
        case maxWidth = "max_width"
        case maxHeight = "max_height"
    }
}

public struct CameraStartResponse: Codable, Sendable {
    public let sessionId: String
    public let status: String
    public let errorMessage: String?
    public let actualFps: UInt32

    public init(
        sessionId: String,
        status: String,
        errorMessage: String? = nil,
        actualFps: UInt32 = 0
    ) {
        self.sessionId = sessionId
        self.status = status
        self.errorMessage = errorMessage
        self.actualFps = actualFps
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case status
        case errorMessage = "error_message"
        case actualFps = "actual_fps"
    }
}

public struct CameraStopRequest: Codable, Sendable {
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

public struct CameraStopResponse: Codable, Sendable {
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

public struct CameraFrame: Sendable {
    public let sessionId: String
    public let frameNumber: UInt64
    public let timestampMs: Int64
    public let jpegData: Data
    public let width: UInt32
    public let height: UInt32
    public let lens: CameraLens

    public init(
        sessionId: String,
        frameNumber: UInt64,
        timestampMs: Int64,
        jpegData: Data,
        width: UInt32,
        height: UInt32,
        lens: CameraLens
    ) {
        self.sessionId = sessionId
        self.frameNumber = frameNumber
        self.timestampMs = timestampMs
        self.jpegData = jpegData
        self.width = width
        self.height = height
        self.lens = lens
    }
}

public final class CameraClient: @unchecked Sendable {
    public static let schemaVersion: Int = 1

    /// Builds a compliant ApplicationMessage containing CameraStartRequest.
    public static func buildCameraStartRequest(
        sessionId: String = UUID().uuidString,
        lens: CameraLens = .back,
        targetFps: UInt32 = 2,
        jpegQuality: UInt32 = 80,
        maxWidth: UInt32 = 1280,
        maxHeight: UInt32 = 720
    ) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "camera_start_req": [
                "session_id": sessionId,
                "lens": lens.rawValue,
                "target_fps": targetFps,
                "jpeg_quality": jpegQuality,
                "max_width": maxWidth,
                "max_height": maxHeight
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing CameraStartResponse.
    public static func parseCameraStartResponse(data: Data) throws -> CameraStartResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let startRespObj = json["camera_start_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing camera_start_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: startRespObj)
        return try JSONDecoder().decode(CameraStartResponse.self, from: subData)
    }

    /// Builds a compliant ApplicationMessage containing CameraStopRequest.
    public static func buildCameraStopRequest(
        sessionId: String,
        reason: String = "user_stopped"
    ) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "camera_stop_req": [
                "session_id": sessionId,
                "reason": reason
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing CameraStopResponse.
    public static func parseCameraStopResponse(data: Data) throws -> CameraStopResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let stopRespObj = json["camera_stop_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing camera_stop_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: stopRespObj)
        return try JSONDecoder().decode(CameraStopResponse.self, from: subData)
    }

    /// Parses an ApplicationMessage containing CameraFrame.
    public static func parseCameraFrame(data: Data) throws -> CameraFrame {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let frameObj = json["camera_frame"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing camera_frame in decrypted payload")
        }

        let sessionId = frameObj["session_id"] as? String ?? ""
        let frameNumber = (frameObj["frame_number"] as? NSNumber)?.uint64Value ?? 0
        let timestampMs = (frameObj["timestamp_ms"] as? NSNumber)?.int64Value ?? 0
        let dataB64 = frameObj["data"] as? String ?? ""
        guard let jpegData = Data(base64Encoded: dataB64) else {
            throw AuthClientError.invalidResponse("Invalid base64 JPEG data in camera_frame")
        }
        let width = (frameObj["width"] as? NSNumber)?.uint32Value ?? 0
        let height = (frameObj["height"] as? NSNumber)?.uint32Value ?? 0
        let lensStr = frameObj["lens"] as? String ?? "LENS_BACK"
        let lens = CameraLens(rawValue: lensStr) ?? .back

        return CameraFrame(
            sessionId: sessionId,
            frameNumber: frameNumber,
            timestampMs: timestampMs,
            jpegData: jpegData,
            width: width,
            height: height,
            lens: lens
        )
    }

    /// CAM-3: Streams camera frames through the VPS relay over an authenticated E2E-encrypted session.
    public static func streamCamera(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        lens: CameraLens = .back,
        targetFps: UInt32 = 2,
        jpegQuality: UInt32 = 80,
        maxWidth: UInt32 = 1280,
        maxHeight: UInt32 = 720,
        maxDurationSeconds: Double = 30.0,
        maxFrames: UInt64? = nil,
        onFrame: @escaping @Sendable (CameraFrame, CameraStreamStats) -> Void,
        onStatusChange: (@Sendable (String) -> Void)? = nil
    ) async throws -> CameraStreamSummary {
        onStatusChange?("Connecting to VPS relay...")
        let session = try await E2ETransportSession.connectAndAuthenticate(
            vpsBaseURL: vpsBaseURL,
            identity: identity,
            client: client,
            presenceTimeoutSeconds: 3.0
        )

        onStatusChange?("Establishing end-to-end encryption...")
        let sessionState = CameraStreamingSessionState()
        let activeSessionId = UUID().uuidString
        sessionState.setSessionId(activeSessionId)

        let effectiveTimeout = maxDurationSeconds > 0 ? maxDurationSeconds + 10.0 : 300.0

        return try await session.runSession(
            timeoutSeconds: effectiveTimeout,
            timeoutMessage: "Timed out waiting for camera stream",
            onReady: { activeSession in
                onStatusChange?("Starting camera stream on Android...")
                let reqData = try buildCameraStartRequest(
                    sessionId: activeSessionId,
                    lens: lens,
                    targetFps: targetFps,
                    jpegQuality: jpegQuality,
                    maxWidth: maxWidth,
                    maxHeight: maxHeight
                )
                try await activeSession.sendEncrypted(plaintext: reqData)
            },
            onPayload: { decrypted, activeSession, finish in
                guard let payloadObj = try JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
                    return
                }

                let sendStopRequest: @Sendable (String) -> Void = { reason in
                    guard sessionState.markStopSent(reason: reason) else { return }
                    onStatusChange?("Stopping camera stream (\(reason))...")

                    Task {
                        do {
                            let stopData = try buildCameraStopRequest(sessionId: activeSessionId, reason: reason)
                            try await activeSession.sendEncrypted(plaintext: stopData)

                            try? await Task.sleep(nanoseconds: 2_000_000_000)
                            finish(.success(sessionState.buildSummary()))
                        } catch {
                            finish(.failure(error))
                        }
                    }
                }

                if payloadObj["camera_start_resp"] != nil {
                    let startResp = try parseCameraStartResponse(data: decrypted)
                    if startResp.status != "STATUS_OK" {
                        let errMsg = startResp.errorMessage ?? startResp.status
                        finish(.failure(AuthClientError.invalidResponse("Camera start rejected: \(startResp.status) - \(errMsg)")))
                        return
                    }
                    sessionState.markStarted()
                    onStatusChange?("Camera streaming active at \(startResp.actualFps) FPS")

                    if maxDurationSeconds > 0 {
                        Task {
                            let nanoseconds = UInt64(maxDurationSeconds * 1_000_000_000)
                            try? await Task.sleep(nanoseconds: nanoseconds)
                            sendStopRequest("duration_completed")
                        }
                    }
                } else if payloadObj["camera_frame"] != nil {
                    let frame = try parseCameraFrame(data: decrypted)
                    let (stats, count) = sessionState.recordFrame(frame: frame)
                    onFrame(frame, stats)

                    if let maxF = maxFrames, count >= maxF {
                        sendStopRequest("max_frames_reached")
                    }
                } else if payloadObj["camera_stop_resp"] != nil {
                    _ = try parseCameraStopResponse(data: decrypted)
                    finish(.success(sessionState.buildSummary()))
                }
            },
            onTerminalState: { newState, finish in
                switch newState {
                case .peerOffline, .disconnected, .error:
                    if sessionState.hasStarted() {
                        sessionState.setStopReason("connection_lost")
                        finish(.success(sessionState.buildSummary()))
                    }
                default:
                    break
                }
            }
        )
    }
}

public struct CameraStreamStats: Sendable {
    public let framesReceived: UInt64
    public let framesDropped: UInt64
    public let lastLatencyMs: Int64
    public let averageLatencyMs: Double
    public let currentFps: Double
    public let elapsedSeconds: Double

    public init(
        framesReceived: UInt64,
        framesDropped: UInt64,
        lastLatencyMs: Int64,
        averageLatencyMs: Double,
        currentFps: Double,
        elapsedSeconds: Double
    ) {
        self.framesReceived = framesReceived
        self.framesDropped = framesDropped
        self.lastLatencyMs = lastLatencyMs
        self.averageLatencyMs = averageLatencyMs
        self.currentFps = currentFps
        self.elapsedSeconds = elapsedSeconds
    }
}

public struct CameraStreamSummary: Codable, Sendable {
    public let sessionId: String
    public let totalFrames: UInt64
    public let droppedFrames: UInt64
    public let averageLatencyMs: Double
    public let averageFps: Double
    public let durationSeconds: Double
    public let stopReason: String

    public init(
        sessionId: String,
        totalFrames: UInt64,
        droppedFrames: UInt64,
        averageLatencyMs: Double,
        averageFps: Double,
        durationSeconds: Double,
        stopReason: String
    ) {
        self.sessionId = sessionId
        self.totalFrames = totalFrames
        self.droppedFrames = droppedFrames
        self.averageLatencyMs = averageLatencyMs
        self.averageFps = averageFps
        self.durationSeconds = durationSeconds
        self.stopReason = stopReason
    }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case totalFrames = "total_frames"
        case droppedFrames = "dropped_frames"
        case averageLatencyMs = "average_latency_ms"
        case averageFps = "average_fps"
        case durationSeconds = "duration_seconds"
        case stopReason = "stop_reason"
    }
}

private final class CameraStreamingSessionState: @unchecked Sendable {
    private let lock = NSLock()
    private var keys: E2EEncryptionManager.SessionKeys?
    private var isTerminated: Bool = false
    private var sessionId: String?
    private var isStopSent: Bool = false
    private var startTime: Date?
    private var framesReceived: UInt64 = 0
    private var droppedFrames: UInt64 = 0
    private var totalLatencyMs: Int64 = 0
    private var expectedNextFrame: UInt64 = 1
    private var stopReason: String = "completed"

    func setKeys(_ k: E2EEncryptionManager.SessionKeys) {
        lock.lock()
        defer { lock.unlock() }
        keys = k
    }

    func getKeys() -> E2EEncryptionManager.SessionKeys? {
        lock.lock()
        defer { lock.unlock() }
        return keys
    }

    func setSessionId(_ id: String) {
        lock.lock()
        defer { lock.unlock() }
        sessionId = id
    }

    func getSessionId() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return sessionId
    }

    func markStarted() {
        lock.lock()
        defer { lock.unlock() }
        if startTime == nil {
            startTime = Date()
        }
    }

    func hasStarted() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return startTime != nil
    }

    func setStopReason(_ reason: String) {
        lock.lock()
        defer { lock.unlock() }
        stopReason = reason
    }

    func recordFrame(frame: CameraFrame) -> (CameraStreamStats, UInt64) {
        lock.lock()
        defer { lock.unlock() }
        if startTime == nil {
            startTime = Date()
        }
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let latencyMs = max(0, nowMs - frame.timestampMs)
        totalLatencyMs += latencyMs

        if frame.frameNumber > expectedNextFrame {
            droppedFrames += (frame.frameNumber - expectedNextFrame)
        }
        expectedNextFrame = frame.frameNumber + 1
        framesReceived += 1

        let elapsed = Date().timeIntervalSince(startTime!)
        let avgLatency = framesReceived > 0 ? Double(totalLatencyMs) / Double(framesReceived) : 0
        let currentFps = elapsed > 0 ? Double(framesReceived) / elapsed : 0

        let stats = CameraStreamStats(
            framesReceived: framesReceived,
            framesDropped: droppedFrames,
            lastLatencyMs: latencyMs,
            averageLatencyMs: avgLatency,
            currentFps: currentFps,
            elapsedSeconds: elapsed
        )
        return (stats, framesReceived)
    }

    func markStopSent(reason: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if isStopSent { return false }
        isStopSent = true
        stopReason = reason
        return true
    }

    func terminateOnce() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if isTerminated { return false }
        isTerminated = true
        return true
    }

    func isEnded() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return isTerminated
    }

    func buildSummary() -> CameraStreamSummary {
        lock.lock()
        defer { lock.unlock() }
        let elapsed = startTime != nil ? Date().timeIntervalSince(startTime!) : 0
        let avgLatency = framesReceived > 0 ? Double(totalLatencyMs) / Double(framesReceived) : 0
        let avgFps = elapsed > 0 ? Double(framesReceived) / elapsed : 0
        return CameraStreamSummary(
            sessionId: sessionId ?? "",
            totalFrames: framesReceived,
            droppedFrames: droppedFrames,
            averageLatencyMs: avgLatency,
            averageFps: avgFps,
            durationSeconds: elapsed,
            stopReason: stopReason
        )
    }
}
