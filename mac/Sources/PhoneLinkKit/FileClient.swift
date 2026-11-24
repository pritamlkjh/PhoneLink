import Foundation
import CryptoKit

/// FILE-2: Mac Remote File Client Models & Serialization
public struct FileItem: Codable, Sendable {
    public let path: String
    public let name: String
    public let isDirectory: Bool
    public let sizeBytes: UInt64
    public let modifiedTime: Int64
    public let mimeType: String

    public init(
        path: String,
        name: String,
        isDirectory: Bool,
        sizeBytes: UInt64,
        modifiedTime: Int64,
        mimeType: String
    ) {
        self.path = path
        self.name = name
        self.isDirectory = isDirectory
        self.sizeBytes = sizeBytes
        self.modifiedTime = modifiedTime
        self.mimeType = mimeType
    }

    enum CodingKeys: String, CodingKey {
        case path
        case name
        case isDirectory = "is_directory"
        case sizeBytes = "size_bytes"
        case modifiedTime = "modified_time"
        case mimeType = "mime_type"
    }
}

public struct FileListResponse: Codable, Sendable {
    public let requestId: String
    public let status: String
    public let currentDirectory: String
    public let items: [FileItem]
    public let errorMessage: String?

    public init(
        requestId: String,
        status: String,
        currentDirectory: String,
        items: [FileItem],
        errorMessage: String? = nil
    ) {
        self.requestId = requestId
        self.status = status
        self.currentDirectory = currentDirectory
        self.items = items
        self.errorMessage = errorMessage
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case status
        case currentDirectory = "current_directory"
        case items
        case errorMessage = "error_message"
    }
}

public final class FileClient: @unchecked Sendable {
    public static let schemaVersion: Int = 1

    /// Builds a compliant ApplicationMessage containing a FileListRequest.
    public static func buildFileListRequest(targetDirectory: String, requestId: String = UUID().uuidString) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "file_list_req": [
                "request_id": requestId,
                "target_directory": targetDirectory
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing FileListResponse.
    public static func parseFileListResponse(data: Data) throws -> FileListResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let fileListRespObj = json["file_list_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing file_list_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: fileListRespObj)
        return try JSONDecoder().decode(FileListResponse.self, from: subData)
    }

    /// Formats bytes into human-readable representation (e.g. 1.2 MB, 450 KB).
    public static func formatByteSize(_ bytes: UInt64) -> String {
        if bytes == 0 { return "0 B" }
        let units = ["B", "KB", "MB", "GB", "TB"]
        var size = Double(bytes)
        var unitIndex = 0
        while size >= 1024 && unitIndex < units.count - 1 {
            size /= 1024
            unitIndex += 1
        }
        if unitIndex == 0 {
            return "\(bytes) B"
        }
        return String(format: "%.1f %@", size, units[unitIndex])
    }

    /// Formats epoch milliseconds into readable timestamp.
    public static func formatDate(_ millis: Int64) -> String {
        let date = Date(timeIntervalSince1970: Double(millis) / 1000.0)
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        formatter.timeZone = .current
        return formatter.string(from: date)
    }

    /// Executes end-to-end directory listing against the connected Android device.
    /// Handles ephemeral key agreement and AES-256-GCM encryption/decryption.
    public static func listRemoteFiles(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        targetDirectory: String,
        timeoutSeconds: Double = 5.0
    ) async throws -> FileListResponse {
        let manager = ConnectionManager(vpsBaseURL: vpsBaseURL, identity: identity, authClient: client)
        let presence = await manager.connectAndWaitForPresence(timeoutSeconds: 2.5)

        guard case .peerOnline = presence else {
            manager.disconnect()
            throw AuthClientError.invalidResponse("Paired Android device is OFFLINE")
        }

        let e2e = E2EEncryptionManager()
        let sessionState = E2EHandshakeSessionState()

        return try await withCheckedThrowingContinuation { continuation in
            // Setup message listener
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

                        let reqData = try buildFileListRequest(targetDirectory: targetDirectory)
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
                        let response = try parseFileListResponse(data: decrypted)
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

            // Start handshake: send E2E_INIT
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

            // Timeout timer
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                if sessionState.resumeOnce() {
                    manager.disconnect()
                    continuation.resume(throwing: AuthClientError.invalidResponse("Request timed out waiting for Android response"))
                }
            }
        }
    }
}

private final class E2EHandshakeSessionState: @unchecked Sendable {
    private var resumed = false
    private var keys: E2EEncryptionManager.SessionKeys?
    private let lock = NSLock()

    func isResumed() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return resumed
    }

    func resumeOnce() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if resumed { return false }
        resumed = true
        return true
    }

    func setKeys(_ keys: E2EEncryptionManager.SessionKeys) {
        lock.lock(); defer { lock.unlock() }
        self.keys = keys
    }

    func getKeys() -> E2EEncryptionManager.SessionKeys? {
        lock.lock(); defer { lock.unlock() }
        return keys
    }
}
