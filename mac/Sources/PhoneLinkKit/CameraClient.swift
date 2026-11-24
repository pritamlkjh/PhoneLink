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
}
