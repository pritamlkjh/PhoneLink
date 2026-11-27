import Foundation

/// FILE-5: Scoped Remote Action System - Mac Client Models & Handler.
/// Implements strongly-typed request builders and response parsers for allowlisted actions:
/// 1. device.ping (DevicePingRequest / DevicePingResponse)
/// 2. device.info (DeviceInfoRequest / DeviceInfoResponse)

public struct DevicePingRequest: Codable, Sendable {
    public let requestId: String
    public let durationSeconds: UInt32

    public init(requestId: String = UUID().uuidString, durationSeconds: UInt32 = 5) {
        self.requestId = requestId
        self.durationSeconds = durationSeconds
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case durationSeconds = "duration_seconds"
    }
}

public struct DevicePingResponse: Codable, Sendable {
    public let requestId: String
    public let status: String
    public let message: String

    public init(requestId: String, status: String, message: String) {
        self.requestId = requestId
        self.status = status
        self.message = message
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case status
        case message
    }
}

public struct DeviceInfoRequest: Codable, Sendable {
    public let requestId: String

    public init(requestId: String = UUID().uuidString) {
        self.requestId = requestId
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
    }
}

public struct DeviceInfoResponse: Codable, Sendable {
    public let requestId: String
    public let status: String
    public let model: String
    public let osVersion: String
    public let batteryPercent: Int
    public let isCharging: Bool
    public let totalStorageBytes: UInt64
    public let availableStorageBytes: UInt64
    public let appVersion: String
    public let errorMessage: String?

    public init(
        requestId: String,
        status: String,
        model: String,
        osVersion: String,
        batteryPercent: Int,
        isCharging: Bool,
        totalStorageBytes: UInt64,
        availableStorageBytes: UInt64,
        appVersion: String,
        errorMessage: String? = nil
    ) {
        self.requestId = requestId
        self.status = status
        self.model = model
        self.osVersion = osVersion
        self.batteryPercent = batteryPercent
        self.isCharging = isCharging
        self.totalStorageBytes = totalStorageBytes
        self.availableStorageBytes = availableStorageBytes
        self.appVersion = appVersion
        self.errorMessage = errorMessage
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case status
        case model
        case osVersion = "os_version"
        case batteryPercent = "battery_percent"
        case isCharging = "is_charging"
        case totalStorageBytes = "total_storage_bytes"
        case availableStorageBytes = "available_storage_bytes"
        case appVersion = "app_version"
        case errorMessage = "error_message"
    }
}

public final class ActionClient: @unchecked Sendable {
    public static let schemaVersion: Int = 1

    /// Builds a compliant ApplicationMessage containing a DevicePingRequest.
    public static func buildDevicePingRequest(durationSeconds: UInt32 = 5, requestId: String = UUID().uuidString) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "device_ping_req": [
                "request_id": requestId,
                "duration_seconds": durationSeconds
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing DevicePingResponse.
    public static func parseDevicePingResponse(data: Data) throws -> DevicePingResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthClientError.invalidResponse("Invalid JSON payload")
        }

        if let errObj = json["error"] as? [String: Any] {
            let code = errObj["code"] as? String ?? "STATUS_ERROR_UNKNOWN"
            let msg = errObj["message"] as? String ?? "Unknown error"
            let reqId = errObj["request_id"] as? String ?? ""
            return DevicePingResponse(requestId: reqId, status: code, message: msg)
        }

        guard let pingRespObj = json["device_ping_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing device_ping_resp in decrypted payload")
        }

        let subData = try JSONSerialization.data(withJSONObject: pingRespObj)
        return try JSONDecoder().decode(DevicePingResponse.self, from: subData)
    }

    /// Builds a compliant ApplicationMessage containing a DeviceInfoRequest.
    public static func buildDeviceInfoRequest(requestId: String = UUID().uuidString) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "device_info_req": [
                "request_id": requestId
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing DeviceInfoResponse.
    public static func parseDeviceInfoResponse(data: Data) throws -> DeviceInfoResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthClientError.invalidResponse("Invalid JSON payload")
        }

        if let errObj = json["error"] as? [String: Any] {
            let code = errObj["code"] as? String ?? "STATUS_ERROR_UNKNOWN"
            let msg = errObj["message"] as? String ?? "Unknown error"
            let reqId = errObj["request_id"] as? String ?? ""
            return DeviceInfoResponse(
                requestId: reqId,
                status: code,
                model: "",
                osVersion: "",
                batteryPercent: -1,
                isCharging: false,
                totalStorageBytes: 0,
                availableStorageBytes: 0,
                appVersion: "",
                errorMessage: msg
            )
        }

        guard let infoRespObj = json["device_info_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing device_info_resp in decrypted payload")
        }

        let subData = try JSONSerialization.data(withJSONObject: infoRespObj)
        return try JSONDecoder().decode(DeviceInfoResponse.self, from: subData)
    }

    /// Executes end-to-end device ping through the VPS relay with authenticated ephemeral key exchange.
    public static func sendPing(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        durationSeconds: UInt32 = 5,
        timeoutSeconds: Double = 5.0
    ) async throws -> DevicePingResponse {
        let session = try await E2ETransportSession.connectAndAuthenticate(
            vpsBaseURL: vpsBaseURL,
            identity: identity,
            client: client,
            presenceTimeoutSeconds: 2.5
        )
        let reqId = UUID().uuidString
        return try await session.runSession(
            timeoutSeconds: timeoutSeconds,
            timeoutMessage: "Timed out waiting for device ping response",
            onReady: { activeSession in
                let reqData = try buildDevicePingRequest(durationSeconds: durationSeconds, requestId: reqId)
                try await activeSession.sendEncrypted(plaintext: reqData)
            },
            onPayload: { decrypted, _, finish in
                let response = try parseDevicePingResponse(data: decrypted)
                if !response.requestId.isEmpty && response.requestId != reqId {
                    return
                }
                finish(.success(response))
            }
        )
    }

    /// Executes end-to-end device info collection through the VPS relay with authenticated ephemeral key exchange.
    public static func fetchDeviceInfo(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        timeoutSeconds: Double = 5.0
    ) async throws -> DeviceInfoResponse {
        let session = try await E2ETransportSession.connectAndAuthenticate(
            vpsBaseURL: vpsBaseURL,
            identity: identity,
            client: client,
            presenceTimeoutSeconds: 2.5
        )
        let reqId = UUID().uuidString
        return try await session.runSession(
            timeoutSeconds: timeoutSeconds,
            timeoutMessage: "Timed out waiting for device info response",
            onReady: { activeSession in
                let reqData = try buildDeviceInfoRequest(requestId: reqId)
                try await activeSession.sendEncrypted(plaintext: reqData)
            },
            onPayload: { decrypted, _, finish in
                let response = try parseDeviceInfoResponse(data: decrypted)
                if !response.requestId.isEmpty && response.requestId != reqId {
                    return
                }
                finish(.success(response))
            }
        )
    }
}
