# PhoneLink — Application Message Schema & API Contract

**DAG Node:** `ARCH-3`  
**Version:** 1.0  
**Status:** Approved Specification  
**Depends On:** ARCH-2 (COMPLETE)  
**Blocks:** VPS-4, FILE-2, CAM-3

---

## 1. Overview & Versioning Strategy

This document specifies the exact API contract and serialization schemas for all PhoneLink components (Android, macOS, VPS Relay).

### 1.1 Wire Format & Reference Schemas
Production messages between Android, macOS, and the VPS relay are exchanged as **versioned UTF-8 JSON payloads (`schema_version = 1`) over HTTPS/REST and TLS 1.3 WebSocket frames**:
- Ensures zero-dependency runtime parsing consistency across Go (`encoding/json`), Swift (`JSONSerialization` / `Codable`), and Kotlin (`org.json`).
- Abstract message fields and field types match the canonical reference contracts in `shared/schema/*.proto` (validated in CI via `tests/test_schema_roundtrip.sh`).

### 1.2 Versioning Strategy
1. **Header Version Field:** Every message envelope (`RelayMessage`, `ApplicationMessage`) includes `schema_version = 1`.
2. **Backward Compatibility Rules:**
   - Field numbers are immutable once assigned.
   - Deprecated fields are marked `[deprecated = true]` and never reassigned.
   - Unknown fields encountered by older clients are preserved or ignored without failing parsing.
   - Breaking changes require incrementing `schema_version` and maintaining fallback parsers.

---

## 2. API Contract Specification

### 2.1 Relay Outer Layer (Client ↔ VPS Relay)
*Source schema: `shared/schema/relay.proto`*

| Message | Direction | Trigger / Purpose |
|---------|-----------|-------------------|
| `AuthChallenge` | VPS $\to$ Client | Sent immediately on WebSocket connect with server nonce & timestamp |
| `AuthResponse` | Client $\to$ VPS | Client response containing Ed25519 signature of challenge nonces |
| `AuthResult` | VPS $\to$ Client | Result of authentication, including session token and peer presence |
| `PeerStatusEvent`| VPS $\to$ Client | Push notification when the paired peer connects or disconnects |
| `SessionResumeRequest` | Client $\to$ VPS | Fast reconnection request with resumption token (max 60s window) |
| `SessionResumeResponse`| VPS $\to$ Client | Acceptance or rejection of session resumption |
| `PairingClaimRequest` | Client $\to$ VPS | Mutual pairing claim during out-of-band QR code setup |
| `PairingClaimResponse`| VPS $\to$ Client | Confirmation of paired device linkage |
| `RelayMessage` | Any $\to$ Any | Envelope carrying forwarded E2E encrypted ciphertext |

---

### 2.2 End-to-End Session Layer (Mac $\leftrightarrow$ Android via VPS)
*Source schema: `shared/schema/e2e.proto`*

| Message | Direction | Trigger / Purpose |
|---------|-----------|-------------------|
| `E2EHandshakeInit` | Mac $\to$ Android | Initiates E2E session with Mac's ephemeral X25519 public key |
| `E2EHandshakeAck` | Android $\to$ Mac | Acknowledges with Android's ephemeral X25519 public key |
| `EncryptedContainer`| Either $\to$ Either | `type = "E2E_PAYLOAD"`, monotonic `seq`, and Base64 AES-256-GCM ciphertext authenticated with AAD |

---

### 2.3 Application Layer (Mac $\leftrightarrow$ Android, End-to-End Encrypted)
*Source schema: `shared/schema/app.proto`, `file.proto`, `camera.proto`, `mic.proto`, `actions.proto`*

#### A. File Operations
1. **Directory Listing:**
   - Request: `FileListRequest(target_directory: string)`
   - Response: `FileListResponse(items: repeated FileItem, status: StatusCode)`
   - Target directories are strictly scoped (e.g., `""` for root accessible storage, `"Downloads"`, `"Documents"`).
2. **File Download (Android $\to$ Mac):**
   - Request: `FileDownloadRequest(file_path: string, start_offset: uint64)`
   - Init Response: `FileDownloadInitResponse(total_size_bytes, chunk_size, sha256_checksum)`
   - Data Stream: `repeated FileChunk(chunk_index, offset, data, chunk_sha256, is_final_chunk)`
   - Acknowledgment: `FileChunkAck(chunk_index, status)`
3. **File Upload (Mac $\to$ Android):**
   - Request: `FileUploadRequest(destination_path, file_name, total_size, sha256)`
   - Init Response: `FileUploadInitResponse(resume_offset, expected_chunk_size)`
   - Data Stream: `repeated FileChunk` (Mac streams chunks, Android writes to scoped storage)

#### B. Camera Operations
1. **Camera Start:**
   - Request: `CameraStartRequest(session_id, lens, target_fps, jpeg_quality, max_width, max_height)`
   - Response: `CameraStartResponse(status, actual_fps)`
   - **Preconditions on Android:**
     - Runtime `CAMERA` permission must be granted.
     - App-level in-app toggle must be explicitly `ON`.
     - Foreground service notification is launched displaying live camera indicator.
2. **Frame Streaming:**
   - Stream: `repeated CameraFrame(session_id, frame_number, timestamp_ms, jpeg_data, width, height)`
   - Frame rate: 1 to 5 FPS.
3. **Camera Stop:**
   - Request: `CameraStopRequest(session_id, reason)`
   - Response: `CameraStopResponse(status)`
   - Causes immediate camera release and foreground camera service termination.

#### B2. Microphone Operations
1. **Microphone Start:**
   - Request: `MicStartRequest(session_id, sample_rate_hz, channels, chunk_duration_ms)`
   - Response: `MicStartResponse(session_id, status, error_message, actual_sample_rate_hz, actual_channels, bits_per_sample)`
   - **Preconditions on Android (Post-Install Dual-Gate):**
     - Runtime `RECORD_AUDIO` permission must be granted.
     - App-level **Allow Remote Microphone Access** toggle must be explicitly `ON`.
     - Foreground service elevates to `FOREGROUND_SERVICE_MICROPHONE` displaying active microphone notification + OS indicator.
2. **Audio Chunk Streaming:**
   - Stream: `repeated MicAudioChunk(session_id, chunk_number, timestamp_ms, pcm_data, sample_rate_hz, channels, bits_per_sample)`
   - Format: Mono (`channels=1`), 16-bit signed linear little-endian PCM, `8000–48000 Hz` (default `16000 Hz`, `200 ms` chunks).
3. **Microphone Stop:**
   - Request: `MicStopRequest(session_id, reason)`
   - Response: `MicStopResponse(session_id, status, error_message)`
   - Immediately stops & releases `AudioRecord` and clears microphone foreground service state.

#### C. Scoped Remote Actions
1. **Device Ping (`device.ping`):**
   - Request: `DevicePingRequest(duration_seconds)`
   - Response: `DevicePingResponse(status, message)`
   - Plays alert sound and vibrates device to locate it.
2. **Device Info (`device.info`):**
   - Request: `DeviceInfoRequest()`
   - Response: `DeviceInfoResponse(model, os_version, battery_percent, is_charging, storage, app_version)`

---

## 3. Concrete JSON Round-Trip Examples

### 3.1 Relay Envelope Example (Outer Layer)
```json
{
  "schema_version": 1,
  "type": "RELAY_FORWARD",
  "source_device_id": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "target_device_id": "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f",
  "session_id": "sess_9876543210abcdef",
  "sequence_number": 42,
  "timestamp": 1774422000000,
  "payload": "<base64_encoded_EncryptedContainer>"
}
```

### 3.2 File Listing Response Example (Decrypted Application Payload)
```json
{
  "schema_version": 1,
  "message_id": "msg_001_filelist",
  "timestamp": 1774422001500,
  "file_list_resp": {
    "request_id": "req_fl_100",
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
```

### 3.3 Camera Frame Example (Decrypted Application Payload)
```json
{
  "schema_version": 1,
  "message_id": "msg_cam_frame_1",
  "timestamp": 1774422002100,
  "camera_frame": {
    "session_id": "cam_sess_12345",
    "frame_number": 1,
    "timestamp_ms": 1774422002100,
    "jpeg_data": "<base64_encoded_jpeg_bytes>",
    "width": 1280,
    "height": 720,
    "lens": "LENS_BACK"
  }
}
```

---

## 4. Error Codes & Recovery Matrix

| Status Code | Value | Scenario | Client Action |
|-------------|-------|----------|---------------|
| `STATUS_OK` | 0 | Success | Continue processing |
| `STATUS_UNAUTHORIZED` | 2 | Bad signature / invalid token | Re-execute authentication handshake |
| `STATUS_FORBIDDEN` | 3 | Operation outside authorized pair | Terminate connection |
| `STATUS_NOT_FOUND` | 4 | Requested file or path does not exist | Report error to user |
| `STATUS_PEER_OFFLINE` | 5 | Paired device is not currently connected | Notify user; fail immediately (no queueing) |
| `STATUS_CAMERA_TOGGLE_DISABLED` | 11 | In-app camera toggle is OFF on Android | Prompt user to enable camera toggle inside Android app |
| `STATUS_CAMERA_PERMISSION_DENIED`| 10 | Android OS Camera permission missing | Prompt user to grant permission in Android settings |
| `STATUS_STORAGE_ACCESS_DENIED` | 12 | Target file path outside scoped storage | Disallow operation; security violation logged |
| `STATUS_INTEGRITY_MISMATCH` | 13 | File chunk SHA-256 does not match | Re-request chunk |
| `STATUS_ACTION_NOT_PERMITTED` | 14 | Remote action not in fixed allowlist | Reject immediately |
| `STATUS_MIC_PERMISSION_DENIED` | 15 | Android OS `RECORD_AUDIO` permission missing | Prompt owner to tap **Grant Microphone Permission** in Android app |
| `STATUS_MIC_TOGGLE_DISABLED` | 16 | In-app microphone toggle is OFF on Android | Prompt owner to switch **Allow Remote Microphone Access** ON in Android app |
