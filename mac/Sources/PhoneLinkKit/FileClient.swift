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

public struct FileUploadRequest: Codable, Sendable {
    public let transferId: String
    public let destinationPath: String
    public let fileName: String
    public let totalSizeBytes: UInt64
    public let sha256Checksum: String

    public init(
        transferId: String,
        destinationPath: String,
        fileName: String,
        totalSizeBytes: UInt64,
        sha256Checksum: String
    ) {
        self.transferId = transferId
        self.destinationPath = destinationPath
        self.fileName = fileName
        self.totalSizeBytes = totalSizeBytes
        self.sha256Checksum = sha256Checksum
    }

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case destinationPath = "destination_path"
        case fileName = "file_name"
        case totalSizeBytes = "total_size_bytes"
        case sha256Checksum = "sha256_checksum"
    }
}

public struct FileUploadInitResponse: Codable, Sendable {
    public let transferId: String
    public let status: String
    public let resumeOffset: UInt64
    public let expectedChunkSize: UInt32
    public let errorMessage: String?

    public init(
        transferId: String,
        status: String,
        resumeOffset: UInt64,
        expectedChunkSize: UInt32,
        errorMessage: String? = nil
    ) {
        self.transferId = transferId
        self.status = status
        self.resumeOffset = resumeOffset
        self.expectedChunkSize = expectedChunkSize
        self.errorMessage = errorMessage
    }

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case status
        case resumeOffset = "resume_offset"
        case expectedChunkSize = "expected_chunk_size"
        case errorMessage = "error_message"
    }
}

public struct FileChunkAck: Codable, Sendable {
    public let transferId: String
    public let chunkIndex: UInt64
    public let status: String
    public let errorMessage: String?

    public init(
        transferId: String,
        chunkIndex: UInt64,
        status: String,
        errorMessage: String? = nil
    ) {
        self.transferId = transferId
        self.chunkIndex = chunkIndex
        self.status = status
        self.errorMessage = errorMessage
    }

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case chunkIndex = "chunk_index"
        case status
        case errorMessage = "error_message"
    }
}

public struct UploadProgress: Sendable {
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

    private static func extractRemoteError(from json: [String: Any]) -> Error? {
        guard let errObj = json["error"] as? [String: Any] else { return nil }
        let code = errObj["code"] as? String ?? "STATUS_ERROR_UNKNOWN"
        let msg = errObj["message"] as? String ?? "Unknown remote error"
        return AuthClientError.invalidResponse("\(code): \(msg)")
    }

    /// Parses an ApplicationMessage containing FileListResponse.
    public static func parseFileListResponse(data: Data) throws -> FileListResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthClientError.invalidResponse("Malformed decrypted payload")
        }
        if let err = extractRemoteError(from: json) { throw err }
        guard let fileListRespObj = json["file_list_resp"] as? [String: Any] else {
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
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthClientError.invalidResponse("Malformed decrypted payload")
        }
        if let err = extractRemoteError(from: json) { throw err }
        guard let subObj = json["file_download_init_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing file_download_init_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: subObj)
        return try JSONDecoder().decode(FileDownloadInitResponse.self, from: subData)
    }

    /// Parses an ApplicationMessage containing FileChunk.
    public static func parseFileChunk(data: Data) throws -> FileChunk {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthClientError.invalidResponse("Malformed decrypted payload")
        }
        if let err = extractRemoteError(from: json) { throw err }
        guard let subObj = json["file_chunk"] as? [String: Any] else {
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

    /// Builds a compliant ApplicationMessage containing a FileUploadRequest.
    public static func buildFileUploadRequest(
        destinationPath: String,
        fileName: String,
        totalSizeBytes: UInt64,
        sha256Checksum: String,
        transferId: String = UUID().uuidString
    ) throws -> Data {
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "file_upload_req": [
                "transfer_id": transferId,
                "destination_path": destinationPath,
                "file_name": fileName,
                "total_size_bytes": totalSizeBytes,
                "sha256_checksum": sha256Checksum
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing FileUploadInitResponse.
    public static func parseFileUploadInitResponse(data: Data) throws -> FileUploadInitResponse {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthClientError.invalidResponse("Malformed decrypted payload")
        }
        if let err = extractRemoteError(from: json) { throw err }
        guard let subObj = json["file_upload_init_resp"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing file_upload_init_resp in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: subObj)
        return try JSONDecoder().decode(FileUploadInitResponse.self, from: subData)
    }

    /// Builds a compliant ApplicationMessage containing a FileChunk.
    public static func buildFileChunk(
        transferId: String,
        chunkIndex: UInt64,
        offset: UInt64,
        chunkData: Data,
        isFinalChunk: Bool
    ) throws -> Data {
        let chunkSha = computeSHA256Hex(data: chunkData)
        let dict: [String: Any] = [
            "schema_version": schemaVersion,
            "message_id": UUID().uuidString,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
            "file_chunk": [
                "transfer_id": transferId,
                "chunk_index": chunkIndex,
                "offset": offset,
                "data": chunkData.base64EncodedString(),
                "chunk_sha256": chunkSha,
                "is_final_chunk": isFinalChunk
            ]
        ]
        return try JSONSerialization.data(withJSONObject: dict)
    }

    /// Parses an ApplicationMessage containing FileChunkAck.
    public static func parseFileChunkAck(data: Data) throws -> FileChunkAck {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthClientError.invalidResponse("Malformed decrypted payload")
        }
        if let err = extractRemoteError(from: json) { throw err }
        guard let subObj = json["file_chunk_ack"] as? [String: Any] else {
            throw AuthClientError.invalidResponse("Missing file_chunk_ack in decrypted payload")
        }
        let subData = try JSONSerialization.data(withJSONObject: subObj)
        return try JSONDecoder().decode(FileChunkAck.self, from: subData)
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

    private static let dateFormatterLock = NSLock()
    private static let sharedDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        formatter.timeZone = .current
        return formatter
    }()

    /// Formats epoch milliseconds into readable timestamp.
    public static func formatDate(_ millis: Int64) -> String {
        let date = Date(timeIntervalSince1970: Double(millis) / 1000.0)
        dateFormatterLock.lock()
        defer { dateFormatterLock.unlock() }
        return sharedDateFormatter.string(from: date)
    }

    /// Formats a file transfer progress bar line with ANSI clear-to-EOL so shrinking speed text leaves no artifacts.
    public static func formatTransferProgressLine(
        bytesTransferred: UInt64,
        totalBytes: UInt64,
        bytesPerSecond: Double,
        barWidth: Int = 30
    ) -> String {
        let rawPct = totalBytes > 0 ? (Double(bytesTransferred) / Double(totalBytes)) * 100.0 : 100.0
        let pct = rawPct.isFinite ? min(100.0, max(0.0, rawPct)) : 0.0
        let safeBps = bytesPerSecond.isFinite ? min(Double(UInt64.max - 1), max(0.0, bytesPerSecond)) : 0.0
        let safeBarWidth = max(1, min(120, barWidth))
        let transferredStr = formatByteSize(bytesTransferred)
        let totalStr = formatByteSize(totalBytes)
        let speedStr = formatByteSize(UInt64(safeBps)) + "/s"
        let completedChars = Int((pct / 100.0) * Double(safeBarWidth))
        let fillCount = max(0, min(safeBarWidth, completedChars))
        let arrowCount = completedChars < safeBarWidth ? 1 : 0
        let spaceCount = max(0, safeBarWidth - fillCount - arrowCount)
        let bar = String(repeating: "=", count: fillCount)
            + (arrowCount > 0 ? ">" : "")
            + String(repeating: " ", count: spaceCount)
        let pctStr = String(format: "%5.1f", pct)
        return "\r\u{001B}[K[\(bar)] \(pctStr)% (\(transferredStr) / \(totalStr)) \(speedStr)"
    }

    private static func padColumn(_ value: String, width: Int) -> String {
        guard value.count < width else { return value }
        return value + String(repeating: " ", count: width - value.count)
    }

    /// Formats a directory listing table safely using native Swift padding (never C %s varargs).
    public static func formatFileListLines(_ response: FileListResponse) -> [String] {
        let dirDisplay = response.currentDirectory.isEmpty ? "/" : "/\(response.currentDirectory)"
        let separator = String(repeating: "-", count: 80)
        var lines: [String] = [
            "Remote Directory: \(dirDisplay) (\(response.items.count) item\(response.items.count == 1 ? "" : "s"))",
            separator,
            "\(padColumn("TYPE", width: 5)) \(padColumn("SIZE", width: 12)) \(padColumn("MODIFIED", width: 20)) NAME",
            separator
        ]
        for item in response.items {
            let typeStr = item.isDirectory ? "DIR" : "FILE"
            let sizeStr = item.isDirectory ? "-" : formatByteSize(item.sizeBytes)
            let dateStr = formatDate(item.modifiedTime)
            let nameStr = item.isDirectory ? "\(item.name)/" : item.name
            lines.append("\(padColumn(typeStr, width: 5)) \(padColumn(sizeStr, width: 12)) \(padColumn(dateStr, width: 20)) \(nameStr)")
        }
        lines.append(separator)
        return lines
    }

    /// Executes end-to-end directory listing against the connected Android device.
    public static func isExpectedFinalUploadAck(
        expectedTransferId: String,
        expectedFinalChunkIndex: UInt64?,
        ackTransferId: String,
        ackChunkIndex: UInt64
    ) -> Bool {
        guard let expectedIdx = expectedFinalChunkIndex else { return false }
        return ackTransferId == expectedTransferId && ackChunkIndex == expectedIdx
    }

    public static func validateDownloadChunkOffset(chunkOffset: UInt64, bytesWritten: UInt64) throws {
        guard chunkOffset == bytesWritten else {
            throw AuthClientError.invalidResponse("Out-of-order chunk offset \(chunkOffset) != expected \(bytesWritten)")
        }
    }

    public static func listRemoteFiles(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        targetDirectory: String,
        timeoutSeconds: Double = 5.0
    ) async throws -> FileListResponse {
        let session = try await E2ETransportSession.connectAndAuthenticate(
            vpsBaseURL: vpsBaseURL,
            identity: identity,
            client: client,
            presenceTimeoutSeconds: 2.5
        )
        return try await session.runSession(
            timeoutSeconds: timeoutSeconds,
            timeoutMessage: "Request timed out waiting for Android response",
            onReady: { activeSession in
                let reqData = try buildFileListRequest(targetDirectory: targetDirectory)
                try await activeSession.sendEncrypted(plaintext: reqData)
            },
            onPayload: { decrypted, _, finish in
                let response = try parseFileListResponse(data: decrypted)
                finish(.success(response))
            }
        )
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
        var destIsDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: localDestinationURL.path, isDirectory: &destIsDir), destIsDir.boolValue {
            throw AuthClientError.invalidResponse("Destination path is an existing directory: \(localDestinationURL.path)")
        }

        let safeTimeout = (timeoutSeconds.isFinite && timeoutSeconds > 0) ? timeoutSeconds : 60.0
        let partURL = localDestinationURL.appendingPathExtension("part")
        var startOffset: UInt64 = 0
        var hasher = SHA256()

        if allowResume && FileManager.default.fileExists(atPath: partURL.path) {
            let attrs = try FileManager.default.attributesOfItem(atPath: partURL.path)
            let existingSize = (attrs[.size] as? NSNumber)?.uint64Value ?? 0
            if existingSize > 0 {
                startOffset = existingSize
                let reader = try FileHandle(forReadingFrom: partURL)
                while true {
                    let slice = try reader.read(upToCount: 65536) ?? Data()
                    if slice.isEmpty { break }
                    hasher.update(data: slice)
                }
                try reader.close()
            }
        }

        let initialOffset = startOffset
        let expectedTransferId = UUID().uuidString

        let state = DownloadSessionState(
            hasher: hasher,
            initialBytes: initialOffset,
            partURL: partURL,
            destinationURL: localDestinationURL,
            expectedTransferId: expectedTransferId
        )

        let session: E2ETransportSession
        do {
            session = try await E2ETransportSession.connectAndAuthenticate(
                vpsBaseURL: vpsBaseURL,
                identity: identity,
                client: client,
                presenceTimeoutSeconds: 3.0
            )
        } catch {
            state.closeHandle()
            throw error
        }

        do {
            return try await session.runSession(
                timeoutSeconds: safeTimeout,
                timeoutMessage: "Request timed out during file download",
                onReady: { activeSession in
                    let reqData = try buildFileDownloadRequest(
                        filePath: remotePath,
                        startOffset: initialOffset,
                        transferId: expectedTransferId
                    )
                    try await activeSession.sendEncrypted(plaintext: reqData)
                },
                onPayload: { decrypted, activeSession, finish in
                    guard let subJson = try JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
                        return
                    }
                    if let err = extractRemoteError(from: subJson) {
                        state.closeHandle()
                        finish(.failure(err))
                        return
                    }

                    if subJson["file_download_init_resp"] != nil {
                        let initResp = try parseFileDownloadInitResponse(data: decrypted)
                        if initResp.status != "STATUS_OK" {
                            state.closeHandle()
                            if initialOffset > initResp.totalSizeBytes {
                                try? FileManager.default.removeItem(at: partURL)
                            }
                            let errMsg = initResp.errorMessage ?? initResp.status
                            finish(.failure(AuthClientError.invalidResponse(errMsg)))
                            return
                        }
                        if initialOffset > initResp.totalSizeBytes {
                            state.closeHandle()
                            try? FileManager.default.removeItem(at: partURL)
                            finish(.failure(AuthClientError.invalidResponse("Local .part size (\(initialOffset)) exceeds remote size (\(initResp.totalSizeBytes)); removed stale .part file, please retry")))
                            return
                        }
                        activeSession.refreshInactivityTimeout()
                        try state.setInitResponseAndOpenFile(initResp)

                        if initResp.totalSizeBytes == 0 {
                            try state.finalizeEmptyFile()
                            finish(.success((bytesTransferred: 0, sha256: initResp.sha256Checksum)))
                        }
                    } else if subJson["file_chunk"] != nil {
                        let chunk = try parseFileChunk(data: decrypted)
                        activeSession.refreshInactivityTimeout()
                        let (isFinal, progress, finalSha) = try state.processChunk(chunk: chunk)
                        progressHandler?(progress)

                        if isFinal {
                            finish(.success((bytesTransferred: progress.totalBytes, sha256: finalSha ?? "")))
                        }
                    }
                }
            )
        } catch {
            state.closeHandle()
            throw error
        }
    }

    /// Uploads a local file to Android through the relay with verifiable chunked SHA-256 integrity and write-scope enforcement.
    public static func uploadLocalFile(
        vpsBaseURL: URL,
        identity: DeviceIdentityManager,
        client: AuthClient,
        localSourceURL: URL,
        remoteDestinationDirectory: String = "",
        remoteFileName: String? = nil,
        timeoutSeconds: Double = 60.0,
        progressHandler: (@Sendable (UploadProgress) -> Void)? = nil
    ) async throws -> (bytesTransferred: UInt64, sha256: String) {
        var srcIsDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: localSourceURL.path, isDirectory: &srcIsDir), !srcIsDir.boolValue else {
            throw AuthClientError.invalidResponse("Local file not found or is a directory: \(localSourceURL.path)")
        }

        let safeTimeout = (timeoutSeconds.isFinite && timeoutSeconds > 0) ? timeoutSeconds : 60.0
        let attrs = try FileManager.default.attributesOfItem(atPath: localSourceURL.path)
        let totalSizeBytes = (attrs[.size] as? NSNumber)?.uint64Value ?? 0
        let wholeFileSha256 = try computeFileSHA256Hex(at: localSourceURL)
        let fileName = remoteFileName ?? localSourceURL.lastPathComponent
        let reqTransferId = UUID().uuidString

        let session = try await E2ETransportSession.connectAndAuthenticate(
            vpsBaseURL: vpsBaseURL,
            identity: identity,
            client: client,
            presenceTimeoutSeconds: 3.0
        )

        let state = UploadSessionState(
            totalBytes: totalSizeBytes,
            wholeFileSha: wholeFileSha256,
            sourceURL: localSourceURL
        )
        let flowWindow = UploadFlowController()

        do {
            return try await session.runSession(
                timeoutSeconds: safeTimeout,
                timeoutMessage: "Request timed out during file upload",
                onReady: { activeSession in
                    let reqData = try buildFileUploadRequest(
                        destinationPath: remoteDestinationDirectory,
                        fileName: fileName,
                        totalSizeBytes: totalSizeBytes,
                        sha256Checksum: wholeFileSha256,
                        transferId: reqTransferId
                    )
                    try await activeSession.sendEncrypted(plaintext: reqData)
                },
                onPayload: { decrypted, activeSession, finish in
                    guard let subJson = try JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
                        return
                    }
                    if let err = extractRemoteError(from: subJson) {
                        Task { await flowWindow.finish() }
                        finish(.failure(err))
                        return
                    }

                    if subJson["file_upload_init_resp"] != nil {
                        let initResp = try parseFileUploadInitResponse(data: decrypted)
                        if initResp.status != "STATUS_OK" {
                            let errMsg = initResp.errorMessage ?? initResp.status
                            Task { await flowWindow.finish() }
                            finish(.failure(AuthClientError.invalidResponse(errMsg)))
                            return
                        }
                        if initResp.resumeOffset > totalSizeBytes {
                            Task { await flowWindow.finish() }
                            finish(.failure(AuthClientError.invalidResponse("Invalid resume offset \(initResp.resumeOffset) > total \(totalSizeBytes)")))
                            return
                        }

                        if totalSizeBytes == 0 || initResp.resumeOffset == totalSizeBytes {
                            Task { await flowWindow.finish() }
                            finish(.success((bytesTransferred: totalSizeBytes, sha256: wholeFileSha256)))
                            return
                        }

                        activeSession.refreshInactivityTimeout()
                        state.setTransferId(initResp.transferId)
                        let chunkSize = max(UInt32(4096), initResp.expectedChunkSize)
                        Task {
                            do {
                                try await streamUploadChunks(
                                    session: activeSession,
                                    state: state,
                                    flowWindow: flowWindow,
                                    resumeOffset: initResp.resumeOffset,
                                    chunkSize: chunkSize,
                                    progressHandler: progressHandler
                                )
                            } catch {
                                await flowWindow.finish()
                                finish(.failure(error))
                            }
                        }
                    } else if subJson["file_chunk_ack"] != nil {
                        let ack = try parseFileChunkAck(data: decrypted)
                        if ack.status != "STATUS_OK" {
                            let errMsg = ack.errorMessage ?? ack.status
                            Task { await flowWindow.finish() }
                            finish(.failure(AuthClientError.invalidResponse(errMsg)))
                            return
                        }
                        guard ack.transferId == state.getTransferId() else { return }
                        activeSession.refreshInactivityTimeout()
                        Task { await flowWindow.recordAck() }

                        if state.isExpectedFinalAck(transferId: ack.transferId, chunkIndex: ack.chunkIndex) {
                            Task { await flowWindow.finish() }
                            finish(.success((bytesTransferred: totalSizeBytes, sha256: wholeFileSha256)))
                        }
                    }
                }
            )
        } catch {
            await flowWindow.finish()
            throw error
        }
    }

    private static func streamUploadChunks(
        session: E2ETransportSession,
        state: UploadSessionState,
        flowWindow: UploadFlowController,
        resumeOffset: UInt64,
        chunkSize: UInt32,
        progressHandler: (@Sendable (UploadProgress) -> Void)?
    ) async throws {
        let handle = try FileHandle(forReadingFrom: state.sourceURL)
        defer { try? handle.close() }

        if resumeOffset > 0 {
            try handle.seek(toOffset: resumeOffset)
        }

        var currentOffset = resumeOffset
        var chunkIndex = resumeOffset / UInt64(chunkSize)
        var sentInSession: UInt64 = 0
        let total = state.totalBytes
        let startTime = Date()

        while currentOffset < total {
            guard !session.isTerminated() && !Task.isCancelled else { return }
            await flowWindow.waitForWindow(sentCount: sentInSession, maxInFlight: 16)
            guard !session.isTerminated() && !Task.isCancelled else { return }

            let bytesToRead = min(Int(chunkSize), Int(total - currentOffset))
            guard let chunkData = try handle.read(upToCount: bytesToRead), !chunkData.isEmpty else {
                break
            }

            let isFinal = (currentOffset + UInt64(chunkData.count) >= total)
            if isFinal {
                state.setExpectedFinalChunkIndex(chunkIndex)
            }

            let chunkPayload = try buildFileChunk(
                transferId: state.getTransferId(),
                chunkIndex: chunkIndex,
                offset: currentOffset,
                chunkData: chunkData,
                isFinalChunk: isFinal
            )
            try await session.sendEncrypted(plaintext: chunkPayload)
            session.refreshInactivityTimeout()

            currentOffset += UInt64(chunkData.count)
            chunkIndex += 1
            sentInSession += 1

            let elapsed = max(0.001, Date().timeIntervalSince(startTime))
            let speed = Double(currentOffset - resumeOffset) / elapsed
            progressHandler?(UploadProgress(
                bytesTransferred: currentOffset,
                totalBytes: total,
                chunkIndex: chunkIndex,
                bytesPerSecond: speed
            ))
        }
    }
}

private actor UploadFlowController {
    private var ackedChunks: UInt64 = 0
    private var finished = false
    private var waiters: [(threshold: UInt64, cont: CheckedContinuation<Void, Never>)] = []

    func waitForWindow(sentCount: UInt64, maxInFlight: UInt64 = 16) async {
        while !finished && sentCount >= ackedChunks + maxInFlight {
            let targetAck = sentCount - maxInFlight + 1
            await withCheckedContinuation { cont in
                waiters.append((targetAck, cont))
            }
        }
    }

    func recordAck() {
        ackedChunks += 1
        var remaining: [(UInt64, CheckedContinuation<Void, Never>)] = []
        for w in waiters {
            if ackedChunks >= w.threshold || finished {
                w.cont.resume()
            } else {
                remaining.append(w)
            }
        }
        waiters = remaining
    }

    func finish() {
        finished = true
        let all = waiters
        waiters.removeAll()
        for w in all {
            w.cont.resume()
        }
    }
}

private final class UploadSessionState: @unchecked Sendable {
    private let lock = NSLock()
    let totalBytes: UInt64
    let wholeFileSha: String
    let sourceURL: URL
    private var transferId: String = ""
    private var expectedFinalChunkIndex: UInt64?

    init(totalBytes: UInt64, wholeFileSha: String, sourceURL: URL) {
        self.totalBytes = totalBytes
        self.wholeFileSha = wholeFileSha
        self.sourceURL = sourceURL
    }

    func setTransferId(_ id: String) {
        lock.lock(); defer { lock.unlock() }
        self.transferId = id
    }

    func getTransferId() -> String {
        lock.lock(); defer { lock.unlock() }
        return transferId
    }

    func setExpectedFinalChunkIndex(_ idx: UInt64) {
        lock.lock(); defer { lock.unlock() }
        self.expectedFinalChunkIndex = idx
    }

    func isExpectedFinalAck(transferId ackTransferId: String, chunkIndex: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return FileClient.isExpectedFinalUploadAck(
            expectedTransferId: self.transferId,
            expectedFinalChunkIndex: self.expectedFinalChunkIndex,
            ackTransferId: ackTransferId,
            ackChunkIndex: chunkIndex
        )
    }
}

private final class DownloadSessionState: @unchecked Sendable {
    private let lock = NSLock()
    private var initResp: FileDownloadInitResponse?
    private var hasher: SHA256
    private var bytesWritten: UInt64
    private let startTime = Date()
    private var fileHandle: FileHandle?
    private let partURL: URL
    private let destinationURL: URL
    private let expectedTransferId: String

    init(hasher: SHA256, initialBytes: UInt64, partURL: URL, destinationURL: URL, expectedTransferId: String) {
        self.hasher = hasher
        self.bytesWritten = initialBytes
        self.partURL = partURL
        self.destinationURL = destinationURL
        self.expectedTransferId = expectedTransferId
    }

    func setInitResponseAndOpenFile(_ resp: FileDownloadInitResponse) throws {
        try lock.withLock {
            self.initResp = resp
            let parentDir = destinationURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            if !FileManager.default.fileExists(atPath: partURL.path) {
                guard FileManager.default.createFile(atPath: partURL.path, contents: nil) else {
                    throw AuthClientError.invalidResponse("Failed to create partial file at \(partURL.path)")
                }
            }
            let writer = try FileHandle(forWritingTo: partURL)
            try writer.seekToEnd()
            self.fileHandle = writer
        }
    }

    func finalizeEmptyFile() throws {
        try lock.withLock {
            try? fileHandle?.close()
            fileHandle = nil
            try commitPartToDestinationLocked()
        }
    }

    private func commitPartToDestinationLocked() throws {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: destinationURL.path, isDirectory: &isDir) {
            if isDir.boolValue {
                throw AuthClientError.invalidResponse("Destination path is an existing directory: \(destinationURL.path)")
            }
            _ = try FileManager.default.replaceItemAt(destinationURL, withItemAt: partURL)
        } else {
            try FileManager.default.moveItem(at: partURL, to: destinationURL)
        }
    }

    func processChunk(chunk: FileChunk) throws -> (isFinal: Bool, progress: DownloadProgress, finalSha256: String?) {
        try lock.withLock {
            guard let expectedInit = initResp else {
                throw AuthClientError.invalidResponse("Received file_chunk before file_download_init_resp")
            }
            if !expectedInit.transferId.isEmpty && !chunk.transferId.isEmpty && chunk.transferId != expectedInit.transferId {
                throw AuthClientError.invalidResponse("Unexpected transfer_id \(chunk.transferId) (expected \(expectedInit.transferId))")
            }

            try FileClient.validateDownloadChunkOffset(chunkOffset: chunk.offset, bytesWritten: bytesWritten)

            guard let chunkData = Data(base64Encoded: chunk.dataBase64) else {
                throw AuthClientError.invalidResponse("Invalid base64 payload in chunk \(chunk.chunkIndex)")
            }

            // Verify chunk checksum
            let computedSha = SHA256.hash(data: chunkData).map { String(format: "%02x", $0) }.joined()
            guard computedSha.lowercased() == chunk.chunkSha256.lowercased() else {
                throw AuthClientError.invalidResponse("STATUS_INTEGRITY_MISMATCH: Chunk \(chunk.chunkIndex) SHA-256 mismatch")
            }

            if !chunkData.isEmpty {
                try fileHandle?.write(contentsOf: chunkData)
                hasher.update(data: chunkData)
                bytesWritten += UInt64(chunkData.count)
            }

            let elapsed = max(0.001, Date().timeIntervalSince(startTime))
            let speed = Double(bytesWritten) / elapsed
            let progress = DownloadProgress(
                bytesTransferred: bytesWritten,
                totalBytes: expectedInit.totalSizeBytes,
                chunkIndex: chunk.chunkIndex,
                bytesPerSecond: speed
            )

            var finalSha: String? = nil
            if chunk.isFinalChunk {
                try fileHandle?.synchronize()
                try? fileHandle?.close()
                fileHandle = nil

                guard bytesWritten == expectedInit.totalSizeBytes else {
                    try? FileManager.default.removeItem(at: partURL)
                    throw AuthClientError.invalidResponse("Download size mismatch: received \(bytesWritten) bytes, expected \(expectedInit.totalSizeBytes)")
                }

                let digest = hasher.finalize()
                finalSha = digest.map { String(format: "%02x", $0) }.joined()

                if !expectedInit.sha256Checksum.isEmpty {
                    guard finalSha?.lowercased() == expectedInit.sha256Checksum.lowercased() else {
                        try? FileManager.default.removeItem(at: partURL)
                        throw AuthClientError.invalidResponse("STATUS_INTEGRITY_MISMATCH: Whole-file SHA-256 mismatch (expected \(expectedInit.sha256Checksum), got \(finalSha ?? ""))")
                    }
                }

                try commitPartToDestinationLocked()
            }

            return (chunk.isFinalChunk, progress, finalSha)
        }
    }

    func closeHandle() {
        lock.lock(); defer { lock.unlock() }
        try? fileHandle?.close()
        fileHandle = nil
    }
}
