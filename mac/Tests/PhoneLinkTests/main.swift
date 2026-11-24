import Foundation
import CryptoKit
import PhoneLinkKit

func assertEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String = "", file: String = #file, line: Int = #line) {
    if actual != expected {
        print("FAIL: \(file):\(line) - Expected '\(expected)' but got '\(actual)'. \(message)")
        exit(1)
    }
}

func assertTrue(_ condition: Bool, _ message: String = "", file: String = #file, line: Int = #line) {
    if !condition {
        print("FAIL: \(file):\(line) - Condition was false. \(message)")
        exit(1)
    }
}

func assertFalse(_ condition: Bool, _ message: String = "", file: String = #file, line: Int = #line) {
    if condition {
        print("FAIL: \(file):\(line) - Condition was true. \(message)")
        exit(1)
    }
}

print("=== Running PhoneLink Mac Unit Tests ===")

// Test 1: Version and Banner
assertEqual(PhoneLinkInfo.version, "1.0.0", "Version should be 1.0.0")
assertTrue(PhoneLinkInfo.banner().contains("PhoneLink Mac Client"), "Banner should contain client name")
assertTrue(PhoneLinkInfo.banner().contains("1.0.0"), "Banner should contain version")
print("PASS: testVersionAndBanner")

// Test 2: Connection States
assertEqual(ConnectionState.disconnected.rawValue, "disconnected")
assertEqual(ConnectionState.connecting.rawValue, "connecting")
assertEqual(ConnectionState.authenticated.rawValue, "authenticated")
assertEqual(ConnectionState.peerConnected.rawValue, "peerConnected")
assertEqual(ConnectionState.error.rawValue, "error")
print("PASS: testConnectionStates")

// Test 3: MAC-2 Device Identity Generation and Hex ID Derivation
let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("phonelink_mac_test_\(UUID().uuidString)")
try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: tempDir) }

let identity = DeviceIdentityManager(storageDirectory: tempDir)
let devID = identity.deviceID
assertEqual(devID.count, 64, "Device ID must be a 64-character hex string")
assertEqual(identity.deviceID, devID, "Device ID must be deterministic and persistent across calls")
assertEqual(identity.publicKeyBytes.count, 32, "Ed25519 public key must be 32 bytes")
print("PASS: testDeviceIdentityGenerationAndPersistence")

// Test 4: MAC-2 Challenge Signing and Cryptographic Verification
let serverNonce = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
let clientNonce = Data([33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64])
let timestamp: Int64 = 1774425000

let signature = try! identity.signChallenge(serverNonce: serverNonce, clientNonce: clientNonce, timestamp: timestamp)
assertEqual(signature.count, 64, "Ed25519 signature must be 64 bytes")

// Build challenge data and verify
var buffer = Data()
buffer.append(serverNonce)
buffer.append(clientNonce)
var bigEndianTimestamp = timestamp.bigEndian
withUnsafeBytes(of: &bigEndianTimestamp) { bytes in
    buffer.append(contentsOf: bytes)
}

let pubKey = try! Curve25519.Signing.PublicKey(rawRepresentation: identity.publicKeyBytes)
assertTrue(pubKey.isValidSignature(signature, for: buffer), "Signature must verify against challenge data")
print("PASS: testChallengeSigningAndVerification")

// Test 5: MAC-2 Tampered Signature Rejection
var corruptedBuffer = buffer
corruptedBuffer[0] ^= 0xFF
assertFalse(pubKey.isValidSignature(signature, for: corruptedBuffer), "Altered nonce must fail signature verification")
print("PASS: testTamperedSignatureRejection")

// Test 6: MAC-2 Credential Wipe / Re-pair Flow
identity.wipeIdentity()
let newIdentity = DeviceIdentityManager(storageDirectory: tempDir)
let newDevID = newIdentity.deviceID
assertFalse(newDevID == devID, "Wiping identity must generate a fresh keypair and distinct device ID")
print("PASS: testWipeAndRePairFlow")

// Test 7: MAC-3 Connection Manager State Representation
let manager = ConnectionManager(
    vpsBaseURL: URL(string: "http://127.0.0.1:8443")!,
    identity: newIdentity
)
assertEqual(manager.state, ConnectionManager.State.disconnected)
assertFalse(manager.state.isConnected)
print("PASS: testConnectionManagerStateRepresentation")

// Test 8: INT-1 E2E Key Agreement and AES-256-GCM Round-trip
let e2eMac = E2EEncryptionManager()
let e2eAndroid = E2EEncryptionManager()

let salt = Data([1, 2, 3, 4, 5, 6, 7, 8])
let macKeys = try! e2eMac.deriveSessionKeys(peerPublicKeyData: e2eAndroid.publicKeyRaw, salt: salt)
let androidKeys = try! e2eAndroid.deriveSessionKeys(peerPublicKeyData: e2eMac.publicKeyRaw, salt: salt)

let pingPlaintext = "PHONELINK_E2E_PING_HELLO_SWIFT".data(using: .utf8)!
let aad = "seq-1".data(using: .utf8)!

let ciphertext = try! E2EEncryptionManager.encryptAESGCM(key: macKeys.keyMacToAndroid, plaintext: pingPlaintext, aad: aad)
assertFalse(String(data: ciphertext, encoding: .isoLatin1)!.contains("PING"), "Ciphertext must not leak plaintext")

let decryptedData = try! E2EEncryptionManager.decryptAESGCM(key: androidKeys.keyMacToAndroid, payload: ciphertext, aad: aad)
let decryptedString = String(data: decryptedData, encoding: .utf8)!
assertEqual(decryptedString, "PHONELINK_E2E_PING_HELLO_SWIFT")

print("PASS: testE2EKeyAgreementAndEncryptionRoundTrip")

// Test 9: INT-2 Device Status JSON Decoding
let statusJSON = """
{
    "device_id": "mac-device-id-12345",
    "is_online": true,
    "is_paired": true,
    "peer_device_id": "android-device-id-67890",
    "peer_online": true,
    "timestamp": 1774426000
}
""".data(using: .utf8)!

let status = try! JSONDecoder().decode(AuthClient.DeviceStatus.self, from: statusJSON)
assertEqual(status.deviceId, "mac-device-id-12345")
assertTrue(status.isOnline)
assertTrue(status.isPaired)
assertEqual(status.peerDeviceId, "android-device-id-67890")
assertTrue(status.peerOnline)
assertEqual(status.timestamp, 1774426000)
print("PASS: testDeviceStatusDecoding")

// Test 10: INT-2 ConnectionManager Presence State Transitions
let onlineState = ConnectionManager.State.peerOnline(peerDeviceID: "android-device-id-67890")
let offlineState = ConnectionManager.State.peerOffline(peerDeviceID: "android-device-id-67890")
assertTrue(onlineState.isConnected, "peerOnline state must be considered connected")
assertTrue(offlineState.isConnected, "peerOffline state must be considered connected to relay")
assertEqual(onlineState, ConnectionManager.State.peerOnline(peerDeviceID: "android-device-id-67890"))
assertFalse(onlineState == offlineState)
print("PASS: testPeerOnlineAndOfflineStates")

// Test 11: FILE-2 FileListRequest Serialization
let reqData = try! FileClient.buildFileListRequest(targetDirectory: "Documents", requestId: "req-101")
let reqObj = try! JSONSerialization.jsonObject(with: reqData) as! [String: Any]
assertEqual(reqObj["schema_version"] as! Int, 1)
let fileListReq = reqObj["file_list_req"] as! [String: Any]
assertEqual(fileListReq["request_id"] as! String, "req-101")
assertEqual(fileListReq["target_directory"] as! String, "Documents")
print("PASS: testFileListRequestBuilder")

// Test 12: FILE-2 FileListResponse Parsing
let sampleRespJSON = """
{
    "schema_version": 1,
    "message_id": "msg-resp-999",
    "timestamp": 1774426500000,
    "file_list_resp": {
        "request_id": "req-101",
        "status": "STATUS_OK",
        "current_directory": "Documents",
        "items": [
            {
                "path": "Documents/report.pdf",
                "name": "report.pdf",
                "is_directory": false,
                "size_bytes": 1048576,
                "modified_time": 1774400000000,
                "mime_type": "application/pdf"
            },
            {
                "path": "Documents/Projects",
                "name": "Projects",
                "is_directory": true,
                "size_bytes": 0,
                "modified_time": 1774300000000,
                "mime_type": "inode/directory"
            }
        ]
    }
}
""".data(using: .utf8)!

let parsedResp = try! FileClient.parseFileListResponse(data: sampleRespJSON)
assertEqual(parsedResp.requestId, "req-101")
assertEqual(parsedResp.status, "STATUS_OK")
assertEqual(parsedResp.currentDirectory, "Documents")
assertEqual(parsedResp.items.count, 2)
assertEqual(parsedResp.items[0].name, "report.pdf")
assertFalse(parsedResp.items[0].isDirectory)
assertEqual(parsedResp.items[0].sizeBytes, 1048576)
assertEqual(parsedResp.items[1].name, "Projects")
assertTrue(parsedResp.items[1].isDirectory)
print("PASS: testFileListResponseParser")

// Test 13: FILE-2 Byte and Date Formatting Helpers
assertEqual(FileClient.formatByteSize(0), "0 B")
assertEqual(FileClient.formatByteSize(512), "512 B")
assertEqual(FileClient.formatByteSize(1024), "1.0 KB")
assertEqual(FileClient.formatByteSize(1048576), "1.0 MB")
assertTrue(FileClient.formatDate(1774400000000).count >= 10)
print("PASS: testByteAndDateFormatting")

// Test 14: FILE-3 FileDownloadRequest Builder
let dlReqData = try! FileClient.buildFileDownloadRequest(filePath: "Documents/report.pdf", startOffset: 65536, transferId: "dl-tx-101")
let dlReqJson = try! JSONSerialization.jsonObject(with: dlReqData) as! [String: Any]
assertEqual(dlReqJson["schema_version"] as! Int, 1)
let dlSubReq = dlReqJson["file_download_req"] as! [String: Any]
assertEqual(dlSubReq["transfer_id"] as! String, "dl-tx-101")
assertEqual(dlSubReq["file_path"] as! String, "Documents/report.pdf")
assertEqual((dlSubReq["start_offset"] as! NSNumber).uint64Value, 65536)
print("PASS: testFileDownloadRequestBuilder")

// Test 15: FILE-3 FileDownloadInitResponse Parser
let sampleDlInitJSON = """
{
    "schema_version": 1,
    "message_id": "msg-dl-init",
    "timestamp": 1774426500000,
    "file_download_init_resp": {
        "transfer_id": "dl-tx-101",
        "status": "STATUS_OK",
        "file_path": "Documents/report.pdf",
        "total_size_bytes": 1048576,
        "chunk_size_bytes": 65536,
        "sha256_checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "error_message": ""
    }
}
""".data(using: .utf8)!

let parsedDlInit = try! FileClient.parseFileDownloadInitResponse(data: sampleDlInitJSON)
assertEqual(parsedDlInit.transferId, "dl-tx-101")
assertEqual(parsedDlInit.status, "STATUS_OK")
assertEqual(parsedDlInit.filePath, "Documents/report.pdf")
assertEqual(parsedDlInit.totalSizeBytes, 1048576)
assertEqual(parsedDlInit.chunkSizeBytes, 65536)
assertEqual(parsedDlInit.sha256Checksum, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
print("PASS: testFileDownloadInitResponseParser")

// Test 16: FILE-3 FileChunk Parser and SHA-256 Verification
let sampleChunkPayload = Data("Sample File Chunk Data for PhoneLink FILE-3 Test".utf8)
let sampleChunkSha = FileClient.computeSHA256Hex(data: sampleChunkPayload)
let sampleChunkBase64 = sampleChunkPayload.base64EncodedString()

let sampleChunkJSON = """
{
    "schema_version": 1,
    "message_id": "msg-chunk-0",
    "timestamp": 1774426501000,
    "file_chunk": {
        "transfer_id": "dl-tx-101",
        "chunk_index": 0,
        "offset": 0,
        "data": "\(sampleChunkBase64)",
        "chunk_sha256": "\(sampleChunkSha)",
        "is_final_chunk": true
    }
}
""".data(using: .utf8)!

let parsedChunk = try! FileClient.parseFileChunk(data: sampleChunkJSON)
assertEqual(parsedChunk.transferId, "dl-tx-101")
assertEqual(parsedChunk.chunkIndex, 0)
assertEqual(parsedChunk.offset, 0)
assertTrue(parsedChunk.isFinalChunk)
let decodedData = Data(base64Encoded: parsedChunk.dataBase64)!
assertEqual(decodedData, sampleChunkPayload)
assertEqual(FileClient.computeSHA256Hex(data: decodedData), parsedChunk.chunkSha256)
print("PASS: testFileChunkParserAndSha256Verification")

// Test 17: FILE-3 computeFileSHA256Hex on disk file
let tempFile = tempDir.appendingPathComponent("sha_test.bin")
try! sampleChunkPayload.write(to: tempFile)
let computedFileSha = try! FileClient.computeFileSHA256Hex(at: tempFile)
assertEqual(computedFileSha, sampleChunkSha)
print("PASS: testFileSHA256HexOnDisk")

// Test 18: FILE-4 FileUploadRequest Builder
let upReqData = try! FileClient.buildFileUploadRequest(
    destinationPath: "Uploads",
    fileName: "upload_doc.pdf",
    totalSizeBytes: 204800,
    sha256Checksum: "abc123sha256hex",
    transferId: "up-tx-999"
)
let upReqJson = try! JSONSerialization.jsonObject(with: upReqData) as! [String: Any]
assertEqual(upReqJson["schema_version"] as! Int, 1)
let upSubReq = upReqJson["file_upload_req"] as! [String: Any]
assertEqual(upSubReq["transfer_id"] as! String, "up-tx-999")
assertEqual(upSubReq["destination_path"] as! String, "Uploads")
assertEqual(upSubReq["file_name"] as! String, "upload_doc.pdf")
assertEqual((upSubReq["total_size_bytes"] as! NSNumber).uint64Value, 204800)
assertEqual(upSubReq["sha256_checksum"] as! String, "abc123sha256hex")
print("PASS: testFileUploadRequestBuilder")

// Test 19: FILE-4 FileUploadInitResponse Parser
let sampleUpInitJSON = """
{
    "schema_version": 1,
    "message_id": "msg-up-init",
    "timestamp": 1774426502000,
    "file_upload_init_resp": {
        "transfer_id": "up-tx-999",
        "status": "STATUS_OK",
        "resume_offset": 65536,
        "expected_chunk_size": 65536,
        "error_message": ""
    }
}
""".data(using: .utf8)!

let parsedUpInit = try! FileClient.parseFileUploadInitResponse(data: sampleUpInitJSON)
assertEqual(parsedUpInit.transferId, "up-tx-999")
assertEqual(parsedUpInit.status, "STATUS_OK")
assertEqual(parsedUpInit.resumeOffset, 65536)
assertEqual(parsedUpInit.expectedChunkSize, 65536)
print("PASS: testFileUploadInitResponseParser")

// Test 20: FILE-4 buildFileChunk for Upload and parseFileChunkAck
let testChunkData = Data("Upload Chunk Content Payload".utf8)
let builtChunkData = try! FileClient.buildFileChunk(
    transferId: "up-tx-999",
    chunkIndex: 1,
    offset: 65536,
    chunkData: testChunkData,
    isFinalChunk: true
)
let builtChunkParsed = try! FileClient.parseFileChunk(data: builtChunkData)
assertEqual(builtChunkParsed.transferId, "up-tx-999")
assertEqual(builtChunkParsed.chunkIndex, 1)
assertEqual(builtChunkParsed.offset, 65536)
assertTrue(builtChunkParsed.isFinalChunk)
let decodedUploadedChunk = Data(base64Encoded: builtChunkParsed.dataBase64)!
assertEqual(decodedUploadedChunk, testChunkData)

let sampleAckJSON = """
{
    "schema_version": 1,
    "message_id": "msg-ack-1",
    "timestamp": 1774426503000,
    "file_chunk_ack": {
        "transfer_id": "up-tx-999",
        "chunk_index": 1,
        "status": "STATUS_OK"
    }
}
""".data(using: .utf8)!

let parsedAck = try! FileClient.parseFileChunkAck(data: sampleAckJSON)
assertEqual(parsedAck.transferId, "up-tx-999")
assertEqual(parsedAck.chunkIndex, 1)
assertEqual(parsedAck.status, "STATUS_OK")
print("PASS: testFileChunkUploadAndAckParser")

// Test 21: FILE-5 DevicePingRequest Builder
let pingReqData = try! ActionClient.buildDevicePingRequest(durationSeconds: 15, requestId: "ping-req-42")
let pingReqJson = try! JSONSerialization.jsonObject(with: pingReqData) as! [String: Any]
assertEqual(pingReqJson["schema_version"] as! Int, 1)
let pingSubReq = pingReqJson["device_ping_req"] as! [String: Any]
assertEqual(pingSubReq["request_id"] as! String, "ping-req-42")
assertEqual(pingSubReq["duration_seconds"] as! Int, 15)
print("PASS: testDevicePingRequestBuilder")

// Test 22: FILE-5 DevicePingResponse Parser
let samplePingRespJSON = """
{
    "schema_version": 1,
    "message_id": "msg-ping-resp",
    "timestamp": 1774426504000,
    "device_ping_resp": {
        "request_id": "ping-req-42",
        "status": "STATUS_OK",
        "message": "Device ping active for 15 seconds"
    }
}
""".data(using: .utf8)!
let parsedPingResp = try! ActionClient.parseDevicePingResponse(data: samplePingRespJSON)
assertEqual(parsedPingResp.requestId, "ping-req-42")
assertEqual(parsedPingResp.status, "STATUS_OK")
assertEqual(parsedPingResp.message, "Device ping active for 15 seconds")
print("PASS: testDevicePingResponseParser")

// Test 23: FILE-5 DeviceInfoRequest Builder
let infoReqData = try! ActionClient.buildDeviceInfoRequest(requestId: "info-req-77")
let infoReqJson = try! JSONSerialization.jsonObject(with: infoReqData) as! [String: Any]
assertEqual(infoReqJson["schema_version"] as! Int, 1)
let infoSubReq = infoReqJson["device_info_req"] as! [String: Any]
assertEqual(infoSubReq["request_id"] as! String, "info-req-77")
print("PASS: testDeviceInfoRequestBuilder")

// Test 24: FILE-5 DeviceInfoResponse Parser
let sampleInfoRespJSON = """
{
    "schema_version": 1,
    "message_id": "msg-info-resp",
    "timestamp": 1774426505000,
    "device_info_resp": {
        "request_id": "info-req-77",
        "status": "STATUS_OK",
        "model": "Google Pixel 8 Pro",
        "os_version": "Android 14 (API 34)",
        "battery_percent": 92,
        "is_charging": true,
        "total_storage_bytes": 256000000000,
        "available_storage_bytes": 180000000000,
        "app_version": "1.0.0"
    }
}
""".data(using: .utf8)!
let parsedInfoResp = try! ActionClient.parseDeviceInfoResponse(data: sampleInfoRespJSON)
assertEqual(parsedInfoResp.requestId, "info-req-77")
assertEqual(parsedInfoResp.status, "STATUS_OK")
assertEqual(parsedInfoResp.model, "Google Pixel 8 Pro")
assertEqual(parsedInfoResp.osVersion, "Android 14 (API 34)")
assertEqual(parsedInfoResp.batteryPercent, 92)
assertTrue(parsedInfoResp.isCharging)
assertEqual(parsedInfoResp.totalStorageBytes, 256000000000)
assertEqual(parsedInfoResp.availableStorageBytes, 180000000000)
assertEqual(parsedInfoResp.appVersion, "1.0.0")

// Test Action Error response parsing
let sampleActionErrJSON = """
{
    "schema_version": 1,
    "message_id": "msg-action-err",
    "timestamp": 1774426506000,
    "error": {
        "request_id": "info-req-77",
        "code": "STATUS_ACTION_NOT_PERMITTED",
        "message": "Remote device info is disabled"
    }
}
""".data(using: .utf8)!
let parsedActionErr = try! ActionClient.parseDeviceInfoResponse(data: sampleActionErrJSON)
assertEqual(parsedActionErr.status, "STATUS_ACTION_NOT_PERMITTED")
assertEqual(parsedActionErr.errorMessage, "Remote device info is disabled")
print("PASS: testDeviceInfoResponseParserAndErrorHandling")

// Test 25: CAM-2 CameraStartRequest Builder
let startReqData = try! CameraClient.buildCameraStartRequest(
    sessionId: "cam-test-1",
    lens: .front,
    targetFps: 3,
    jpegQuality: 85,
    maxWidth: 1280,
    maxHeight: 720
)
let startReqJson = try! JSONSerialization.jsonObject(with: startReqData) as! [String: Any]
assertEqual(startReqJson["schema_version"] as! Int, 1)
let startSubReq = startReqJson["camera_start_req"] as! [String: Any]
assertEqual(startSubReq["session_id"] as! String, "cam-test-1")
assertEqual(startSubReq["lens"] as! String, "LENS_FRONT")
assertEqual(startSubReq["target_fps"] as! Int, 3)
assertEqual(startSubReq["jpeg_quality"] as! Int, 85)
assertEqual(startSubReq["max_width"] as! Int, 1280)
assertEqual(startSubReq["max_height"] as! Int, 720)
print("PASS: testCameraStartRequestBuilder")

// Test 26: CAM-2 CameraStartResponse Parser
let sampleStartRespJSON = """
{
    "schema_version": 1,
    "message_id": "msg-start-resp",
    "timestamp": 1774426507000,
    "camera_start_resp": {
        "session_id": "cam-test-1",
        "status": "STATUS_OK",
        "actual_fps": 3
    }
}
""".data(using: .utf8)!
let parsedStartResp = try! CameraClient.parseCameraStartResponse(data: sampleStartRespJSON)
assertEqual(parsedStartResp.sessionId, "cam-test-1")
assertEqual(parsedStartResp.status, "STATUS_OK")
assertEqual(parsedStartResp.actualFps, 3)
print("PASS: testCameraStartResponseParser")

// Test 27: CAM-2 CameraStopRequest Builder & Response Parser
let stopReqData = try! CameraClient.buildCameraStopRequest(sessionId: "cam-test-1", reason: "user_done")
let stopReqJson = try! JSONSerialization.jsonObject(with: stopReqData) as! [String: Any]
let stopSubReq = stopReqJson["camera_stop_req"] as! [String: Any]
assertEqual(stopSubReq["session_id"] as! String, "cam-test-1")
assertEqual(stopSubReq["reason"] as! String, "user_done")

let sampleStopRespJSON = """
{
    "schema_version": 1,
    "message_id": "msg-stop-resp",
    "timestamp": 1774426508000,
    "camera_stop_resp": {
        "session_id": "cam-test-1",
        "status": "STATUS_OK"
    }
}
""".data(using: .utf8)!
let parsedStopResp = try! CameraClient.parseCameraStopResponse(data: sampleStopRespJSON)
assertEqual(parsedStopResp.sessionId, "cam-test-1")
assertEqual(parsedStopResp.status, "STATUS_OK")
print("PASS: testCameraStopRequestBuilderAndResponseParser")

// Test 28: CAM-2 CameraFrame Parser
let mockJpegBytes = Data([0xFF, 0xD8, 0x01, 0x02])
let sampleFrameJSON = """
{
    "schema_version": 1,
    "message_id": "msg-frame-1",
    "timestamp": 1774426509000,
    "camera_frame": {
        "session_id": "cam-test-1",
        "frame_number": 1,
        "timestamp_ms": 1774426509000,
        "data": "\(mockJpegBytes.base64EncodedString())",
        "width": 1280,
        "height": 720,
        "lens": "LENS_FRONT"
    }
}
""".data(using: .utf8)!
let parsedFrame = try! CameraClient.parseCameraFrame(data: sampleFrameJSON)
assertEqual(parsedFrame.sessionId, "cam-test-1")
assertEqual(parsedFrame.frameNumber, 1)
assertEqual(parsedFrame.width, 1280)
assertEqual(parsedFrame.height, 720)
assertEqual(parsedFrame.lens, .front)
assertEqual(parsedFrame.jpegData, mockJpegBytes)
print("PASS: testCameraFrameParser")

// Test 29: CAM-3 CameraStreamStats & CameraStreamSummary
let sampleStats = CameraStreamStats(
    framesReceived: 10,
    framesDropped: 1,
    lastLatencyMs: 35,
    averageLatencyMs: 38.5,
    currentFps: 2.1,
    elapsedSeconds: 4.8
)
assertEqual(sampleStats.framesReceived, 10)
assertEqual(sampleStats.framesDropped, 1)
assertEqual(sampleStats.lastLatencyMs, 35)
assert(sampleStats.averageLatencyMs > 38.0 && sampleStats.averageLatencyMs < 39.0)
assert(sampleStats.currentFps > 2.0 && sampleStats.currentFps < 2.2)

let summary = CameraStreamSummary(
    sessionId: "cam-sum-1",
    totalFrames: 25,
    droppedFrames: 2,
    averageLatencyMs: 42.1,
    averageFps: 2.0,
    durationSeconds: 12.5,
    stopReason: "duration_completed"
)
let encodedSummary = try! JSONEncoder().encode(summary)
let decodedSummary = try! JSONDecoder().decode(CameraStreamSummary.self, from: encodedSummary)
assertEqual(decodedSummary.sessionId, "cam-sum-1")
assertEqual(decodedSummary.totalFrames, 25)
assertEqual(decodedSummary.droppedFrames, 2)
assertEqual(decodedSummary.stopReason, "duration_completed")
print("PASS: testCameraStreamStatsAndSummaryModels")

// Test 30: CAM-3 Camera Frame Gaps & Dropped Frame Sequence Detection
var expectedFrame: UInt64 = 1
var detectedDrops: UInt64 = 0
let frameNumbers: [UInt64] = [1, 2, 4, 7] // Gaps: between 2->4 (1 dropped: 3), 4->7 (2 dropped: 5,6)
for fn in frameNumbers {
    if fn > expectedFrame {
        detectedDrops += (fn - expectedFrame)
    }
    expectedFrame = fn + 1
}
assertEqual(detectedDrops, 3)
assertEqual(expectedFrame, 8)
print("PASS: testCameraFrameGapsAndDroppedFrameSequenceDetection")

print(">>> ALL MAC CLIENT UNIT TESTS PASSED (30/30) <<<")
exit(0)
