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

    /// Executes end-to-end device ping through the VPS relay with ephemeral key exchange.
    public static func sendPing(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        durationSeconds: UInt32 = 5,
        timeoutSeconds: Double = 5.0
    ) async throws -> DevicePingResponse {
        let manager = ConnectionManager(vpsBaseURL: vpsBaseURL, identity: identity, authClient: client)
        let presence = await manager.connectAndWaitForPresence(timeoutSeconds: 2.5)

        guard case .peerOnline = presence else {
            manager.disconnect()
            throw AuthClientError.invalidResponse("Paired Android device is OFFLINE")
        }

        let e2e = E2EEncryptionManager()
        let sessionState = ActionHandshakeSessionState()

        return try await withCheckedThrowingContinuation { continuation in
            manager.onMessageReceived = { data in
                guard !sessionState.isResumed() else { return }

                guard let text = String(data: data, encoding: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
                      let type = json["type"] as? String else {
                    return
                }

                if type == "E2E_ACK" {
                    guard let peerPubB64 = json["ephemeral_public_key"] as? String,
                          let peerPubData = Data(base64Encoded: peerPubB64) else {
                        return
                    }

                    do {
                        let keys = try e2e.deriveSessionKeys(peerPublicKeyData: peerPubData)
                        sessionState.setKeys(keys)

                        let reqData = try buildDevicePingRequest(durationSeconds: durationSeconds)
                        let encrypted = try E2EEncryptionManager.encryptAESGCM(key: keys.keyMacToAndroid, plaintext: reqData)

                        let payloadJson: [String: Any] = [
                            "type": "E2E_PAYLOAD",
                            "ciphertext": encrypted.base64EncodedString()
                        ]
                        let outData = try JSONSerialization.data(withJSONObject: payloadJson)
                        Task {
                            do {
                                try await manager.send(data: outData)
                            } catch {
                                if sessionState.resumeOnce() {
                                    manager.disconnect()
                                    continuation.resume(throwing: error)
                                }
                            }
                        }
                    } catch {
                        if sessionState.resumeOnce() {
                            manager.disconnect()
                            continuation.resume(throwing: error)
                        }
                    }
                } else if type == "E2E_PAYLOAD" {
                    guard let keys = sessionState.getKeys(),
                          let ctB64 = json["ciphertext"] as? String,
                          let ct = Data(base64Encoded: ctB64) else {
                        return
                    }

                    do {
                        let decrypted = try E2EEncryptionManager.decryptAESGCM(key: keys.keyAndroidToMac, payload: ct)
                        let response = try parseDevicePingResponse(data: decrypted)
                        if sessionState.resumeOnce() {
                            manager.disconnect()
                            continuation.resume(returning: response)
                        }
                    } catch {
                        if sessionState.resumeOnce() {
                            manager.disconnect()
                            continuation.resume(throwing: error)
                        }
                    }
                }
            }

            Task {
                do {
                    let initJson: [String: Any] = [
                        "type": "E2E_INIT",
                        "ephemeral_public_key": e2e.publicKeyRaw.base64EncodedString(),
                        "timestamp": Int64(Date().timeIntervalSince1970 * 1000)
                    ]
                    let initData = try JSONSerialization.data(withJSONObject: initJson)
                    try await manager.send(data: initData)
                } catch {
                    if sessionState.resumeOnce() {
                        manager.disconnect()
                        continuation.resume(throwing: error)
                    }
                }
            }

            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                if sessionState.resumeOnce() {
                    manager.disconnect()
                    continuation.resume(throwing: AuthClientError.invalidResponse("Timed out waiting for device ping response"))
                }
            }
        }
    }

    /// Executes end-to-end device info collection through the VPS relay with ephemeral key exchange.
    public static func fetchDeviceInfo(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        timeoutSeconds: Double = 5.0
    ) async throws -> DeviceInfoResponse {
        let manager = ConnectionManager(vpsBaseURL: vpsBaseURL, identity: identity, authClient: client)
        let presence = await manager.connectAndWaitForPresence(timeoutSeconds: 2.5)

        guard case .peerOnline = presence else {
            manager.disconnect()
            throw AuthClientError.invalidResponse("Paired Android device is OFFLINE")
        }

        let e2e = E2EEncryptionManager()
        let sessionState = ActionHandshakeSessionState()

        return try await withCheckedThrowingContinuation { continuation in
            manager.onMessageReceived = { data in
                guard !sessionState.isResumed() else { return }

                guard let text = String(data: data, encoding: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
                      let type = json["type"] as? String else {
                    return
                }

                if type == "E2E_ACK" {
                    guard let peerPubB64 = json["ephemeral_public_key"] as? String,
                          let peerPubData = Data(base64Encoded: peerPubB64) else {
                        return
                    }

                    do {
                        let keys = try e2e.deriveSessionKeys(peerPublicKeyData: peerPubData)
                        sessionState.setKeys(keys)

                        let reqData = try buildDeviceInfoRequest()
                        let encrypted = try E2EEncryptionManager.encryptAESGCM(key: keys.keyMacToAndroid, plaintext: reqData)

                        let payloadJson: [String: Any] = [
                            "type": "E2E_PAYLOAD",
                            "ciphertext": encrypted.base64EncodedString()
                        ]
                        let outData = try JSONSerialization.data(withJSONObject: payloadJson)
                        Task {
                            do {
                                try await manager.send(data: outData)
                            } catch {
                                if sessionState.resumeOnce() {
                                    manager.disconnect()
                                    continuation.resume(throwing: error)
                                }
                            }
                        }
                    } catch {
                        if sessionState.resumeOnce() {
                            manager.disconnect()
                            continuation.resume(throwing: error)
                        }
                    }
                } else if type == "E2E_PAYLOAD" {
                    guard let keys = sessionState.getKeys(),
                          let ctB64 = json["ciphertext"] as? String,
                          let ct = Data(base64Encoded: ctB64) else {
                        return
                    }

                    do {
                        let decrypted = try E2EEncryptionManager.decryptAESGCM(key: keys.keyAndroidToMac, payload: ct)
                        let response = try parseDeviceInfoResponse(data: decrypted)
                        if sessionState.resumeOnce() {
                            manager.disconnect()
                            continuation.resume(returning: response)
                        }
                    } catch {
                        if sessionState.resumeOnce() {
                            manager.disconnect()
                            continuation.resume(throwing: error)
                        }
                    }
                }
            }

            Task {
                do {
                    let initJson: [String: Any] = [
                        "type": "E2E_INIT",
                        "ephemeral_public_key": e2e.publicKeyRaw.base64EncodedString(),
                        "timestamp": Int64(Date().timeIntervalSince1970 * 1000)
                    ]
                    let initData = try JSONSerialization.data(withJSONObject: initJson)
                    try await manager.send(data: initData)
                } catch {
                    if sessionState.resumeOnce() {
                        manager.disconnect()
                        continuation.resume(throwing: error)
                    }
                }
            }

            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                if sessionState.resumeOnce() {
                    manager.disconnect()
                    continuation.resume(throwing: AuthClientError.invalidResponse("Timed out waiting for device info response"))
                }
            }
        }
    }
}

private final class ActionHandshakeSessionState: @unchecked Sendable {
    private var resumed = false
    private var keys: E2EEncryptionManager.SessionKeys?
    private let lock = NSLock()

    func isResumed() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return resumed
    }

    func resumeOnce() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if resumed { return false }
        resumed = true
        return true
    }

    func setKeys(_ keys: E2EEncryptionManager.SessionKeys) {
        lock.lock()
        defer { lock.unlock() }
        self.keys = keys
    }

    func getKeys() -> E2EEncryptionManager.SessionKeys? {
        lock.lock()
        defer { lock.unlock() }
        return keys
    }
}
