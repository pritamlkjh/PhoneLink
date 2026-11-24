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

public struct FileDownloadInitResponse: Codable, Sendable {
    public let transferId: String
    public let status: String
    public let filePath: String
    public let totalSizeBytes: UInt64
    public let chunkSizeBytes: UInt32
    public let sha256Checksum: String
    public let errorMessage: String?

    public init(
        transferId: String,
        status: String,
        filePath: String,
        totalSizeBytes: UInt64,
        chunkSizeBytes: UInt32,
        sha256Checksum: String,
        errorMessage: String? = nil
    ) {
        self.transferId = transferId
        self.status = status
        self.filePath = filePath
        self.totalSizeBytes = totalSizeBytes
        self.chunkSizeBytes = chunkSizeBytes
        self.sha256Checksum = sha256Checksum
        self.errorMessage = errorMessage
    }

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case status
        case filePath = "file_path"
        case totalSizeBytes = "total_size_bytes"
        case chunkSizeBytes = "chunk_size_bytes"
        case sha256Checksum = "sha256_checksum"
        case errorMessage = "error_message"
    }
}

public struct FileChunk: Codable, Sendable {
    public let transferId: String
    public let chunkIndex: UInt64
    public let offset: UInt64
    public let dataBase64: String
    public let chunkSha256: String
    public let isFinalChunk: Bool

    public init(
        transferId: String,
        chunkIndex: UInt64,
        offset: UInt64,
        dataBase64: String,
        chunkSha256: String,
        isFinalChunk: Bool
    ) {
        self.transferId = transferId
        self.chunkIndex = chunkIndex
        self.offset = offset
        self.dataBase64 = dataBase64
        self.chunkSha256 = chunkSha256
        self.isFinalChunk = isFinalChunk
    }

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case chunkIndex = "chunk_index"
        case offset
        case dataBase64 = "data"
        case chunkSha256 = "chunk_sha256"
        case isFinalChunk = "is_final_chunk"
    }
}

public struct DownloadProgress: Sendable {
    public let bytesTransferred: UInt64
    public let totalBytes: UInt64
    public let chunkIndex: UInt64
    public let bytesPerSecond: Double

    public init(bytesTransferred: UInt64, totalBytes: UInt64, chunkIndex: UInt64, bytesPerSecond: Double) {
        self.bytesTransferred = bytesTransferred
        self.totalBytes = totalBytes
        self.chunkIndex = chunkIndex
        self.bytesPerSecond = bytesPerSecond
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

    /// Builds a compliant ApplicationMessage containing a FileDownloadRequest.
    public static func buildFileDownloadRequest(
        filePath: String,
        startOffset: UInt64 = 0,
        transferId: String = UUID().uuidString
    ) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "file_download_req": [
                "transfer_id": transferId,
                "file_path": filePath,
                "start_offset": startOffset
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing FileDownloadInitResponse.
    public static func parseFileDownloadInitResponse(data: Data) throws -> FileDownloadInitResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let subObj = json["file_download_init_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing file_download_init_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: subObj)
        return try JSONDecoder().decode(FileDownloadInitResponse.self, from: subData)
    }

    /// Parses an ApplicationMessage containing FileChunk.
    public static func parseFileChunk(data: Data) throws -> FileChunk {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let subObj = json["file_chunk"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing file_chunk in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: subObj)
        return try JSONDecoder().decode(FileChunk.self, from: subData)
    }

    /// Computes SHA-256 hex string for given Data.
    public static func computeSHA256Hex(data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Computes whole-file SHA-256 hex string for file at given URL.
    public static func computeFileSHA256Hex(at url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 65536) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
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

    /// Downloads a remote file from Android through the relay with verifiable chunked SHA-256 integrity and resumability.
    public static func downloadRemoteFile(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        remotePath: String,
        localDestinationURL: URL,
        allowResume: Bool = true,
        timeoutSeconds: Double = 60.0,
        progressHandler: (@Sendable (DownloadProgress) -> Void)? = nil
    ) async throws -> (bytesTransferred: UInt64, sha256: String) {
        let partURL = localDestinationURL.appendingPathExtension("part")
        var startOffset: UInt64 = 0
        var hasher = SHA256()

        if allowResume && FileManager.default.fileExists(atPath: partURL.path) {
            let attrs = try FileManager.default.attributesOfItem(atPath: partURL.path)
            let existingSize = (attrs[.size] as? NSNumber)?.uint64Value ?? 0
            if existingSize > 0 {
                startOffset = existingSize
                // Prime hasher with existing prefix bytes
                let reader = try FileHandle(forReadingFrom: partURL)
                while true {
                    let slice = try reader.read(upToCount: 65536) ?? Data()
                    if slice.isEmpty { break }
                    hasher.update(data: slice)
                }
                try reader.close()
            }
        } else {
            let parentDir = localDestinationURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: partURL.path, contents: nil)
        }

        let writer = try FileHandle(forWritingTo: partURL)
        try writer.seekToEnd()
        let initialOffset = startOffset

        let state = DownloadSessionState(
            hasher: hasher,
            initialBytes: initialOffset,
            fileHandle: writer,
            partURL: partURL,
            destinationURL: localDestinationURL
        )

        let manager = ConnectionManager(vpsBaseURL: vpsBaseURL, identity: identity, authClient: client)
        let presence = await manager.connectAndWaitForPresence(timeoutSeconds: 3.0)

        guard case .peerOnline = presence else {
            state.closeHandle()
            manager.disconnect()
            throw AuthClientError.invalidResponse("Paired Android device is OFFLINE")
        }

        let e2e = E2EEncryptionManager()

        return try await withCheckedThrowingContinuation { continuation in
            manager.onMessageReceived = { data in
                guard !state.isCompleted() else { return }

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
                        state.setKeys(keys)

                        let reqData = try buildFileDownloadRequest(filePath: remotePath, startOffset: initialOffset)
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
                                if state.markCompleted() {
                                    state.closeHandle()
                                    manager.disconnect()
                                    continuation.resume(throwing: error)
                                }
                            }
                        }
                    } catch {
                        if state.markCompleted() {
                            state.closeHandle()
                            manager.disconnect()
                            continuation.resume(throwing: error)
                        }
                    }
                } else if type == "E2E_PAYLOAD" {
                    guard let keys = state.getKeys(),
                          let ctB64 = json["ciphertext"] as? String,
                          let ct = Data(base64Encoded: ctB64) else {
                        return
                    }

                    do {
                        let decrypted = try E2EEncryptionManager.decryptAESGCM(key: keys.keyAndroidToMac, payload: ct)
                        guard let subJson = try JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
                            return
                        }

                        if subJson["file_download_init_resp"] != nil {
                            let initResp = try parseFileDownloadInitResponse(data: decrypted)
                            if initResp.status != "STATUS_OK" {
                                let errMsg = initResp.errorMessage ?? initResp.status
                                if state.markCompleted() {
                                    state.closeHandle()
                                    manager.disconnect()
                                    continuation.resume(throwing: AuthClientError.invalidResponse(errMsg))
                                }
                                return
                            }
                            state.setInitResponse(initResp)

                            // If 0-byte file
                            if initResp.totalSizeBytes == 0 {
                                state.closeHandle()
                                try? FileManager.default.removeItem(at: localDestinationURL)
                                try FileManager.default.moveItem(at: partURL, to: localDestinationURL)
                                if state.markCompleted() {
                                    manager.disconnect()
                                    continuation.resume(returning: (bytesTransferred: 0, sha256: initResp.sha256Checksum))
                                }
                            }
                        } else if subJson["file_chunk"] != nil {
                            let chunk = try parseFileChunk(data: decrypted)
                            let (isFinal, progress, finalSha) = try state.processChunk(chunk: chunk)
                            progressHandler?(progress)

                            if isFinal {
                                if state.markCompleted() {
                                    manager.disconnect()
                                    continuation.resume(returning: (bytesTransferred: progress.totalBytes, sha256: finalSha ?? ""))
                                }
                            }
                        }
                    } catch {
                        if state.markCompleted() {
                            state.closeHandle()
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
                    if state.markCompleted() {
                        state.closeHandle()
                        manager.disconnect()
                        continuation.resume(throwing: error)
                    }
                }
            }

            // Timeout watchdog
            Task {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                if state.markCompleted() {
                    state.closeHandle()
                    manager.disconnect()
                    continuation.resume(throwing: AuthClientError.invalidResponse("Request timed out during file download"))
                }
            }
        }
    }
}

private final class DownloadSessionState: @unchecked Sendable {
    private let lock = NSLock()
    private var keys: E2EEncryptionManager.SessionKeys?
    private var initResp: FileDownloadInitResponse?
    private var completed = false
    private var hasher: SHA256
    private var bytesWritten: UInt64
    private let startTime = Date()
    private var fileHandle: FileHandle?
    private let partURL: URL
    private let destinationURL: URL

    init(hasher: SHA256, initialBytes: UInt64, fileHandle: FileHandle, partURL: URL, destinationURL: URL) {
        self.hasher = hasher
        self.bytesWritten = initialBytes
        self.fileHandle = fileHandle
        self.partURL = partURL
        self.destinationURL = destinationURL
    }

    func setKeys(_ keys: E2EEncryptionManager.SessionKeys) {
        lock.lock(); defer { lock.unlock() }
        self.keys = keys
    }

    func getKeys() -> E2EEncryptionManager.SessionKeys? {
        lock.lock(); defer { lock.unlock() }
        return keys
    }

    func setInitResponse(_ resp: FileDownloadInitResponse) {
        lock.lock(); defer { lock.unlock() }
        self.initResp = resp
    }

    func getInitResponse() -> FileDownloadInitResponse? {
        lock.lock(); defer { lock.unlock() }
        return initResp
    }

    func isCompleted() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return completed
    }

    func markCompleted() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if completed { return false }
        completed = true
        return true
    }

    func processChunk(chunk: FileChunk) throws -> (isFinal: Bool, progress: DownloadProgress, finalSha256: String?) {
        lock.lock(); defer { lock.unlock() }
        guard let chunkData = Data(base64Encoded: chunk.dataBase64) else {
            throw AuthClientError.invalidResponse("Invalid base64 payload in chunk \(chunk.chunkIndex)")
        }

        // Verify chunk checksum
        let computedSha = SHA256.hash(data: chunkData).map { String(format: "%02x", $0) }.joined()
        guard computedSha.lowercased() == chunk.chunkSha256.lowercased() else {
            throw AuthClientError.invalidResponse("STATUS_INTEGRITY_MISMATCH: Chunk \(chunk.chunkIndex) SHA-256 mismatch")
        }

        // Write to file and update hash
        fileHandle?.write(chunkData)
        hasher.update(data: chunkData)
        bytesWritten += UInt64(chunkData.count)

        let elapsed = max(0.001, Date().timeIntervalSince(startTime))
        let speed = Double(bytesWritten) / elapsed
        let total = initResp?.totalSizeBytes ?? bytesWritten
        let progress = DownloadProgress(
            bytesTransferred: bytesWritten,
            totalBytes: total,
            chunkIndex: chunk.chunkIndex,
            bytesPerSecond: speed
        )

        var finalSha: String? = nil
        if chunk.isFinalChunk {
            try? fileHandle?.close()
            fileHandle = nil
            let digest = hasher.finalize()
            finalSha = digest.map { String(format: "%02x", $0) }.joined()

            if let expected = initResp?.sha256Checksum, !expected.isEmpty {
                guard finalSha?.lowercased() == expected.lowercased() else {
                    throw AuthClientError.invalidResponse("STATUS_INTEGRITY_MISMATCH: Whole-file SHA-256 mismatch (expected \(expected), got \(finalSha ?? ""))")
                }
            }

            // Move to destination
            try? FileManager.default.removeItem(at: destinationURL)
            try FileManager.default.moveItem(at: partURL, to: destinationURL)
        }

        return (chunk.isFinalChunk, progress, finalSha)
    }

    func closeHandle() {
        lock.lock(); defer { lock.unlock() }
        try? fileHandle?.close()
        fileHandle = nil
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
