# PhoneLink — High-Level System Architecture

**DAG Node:** `ARCH-1`  
**Version:** 1.0  
**Status:** Under Review  
**Depends On:** REQ-1 (COMPLETE)

---

## 1. System Overview

PhoneLink is a three-component system:

```
┌──────────────┐     TLS 1.3      ┌──────────────┐     TLS 1.3      ┌──────────────┐
│              │◄────────────────►│              │◄────────────────►│              │
│  Android App │   WebSocket +    │  VPS Relay   │   WebSocket +    │  Mac Client  │
│  (Kotlin)    │   E2E Encrypted  │  (Go)        │   E2E Encrypted  │  (Swift CLI) │
│              │   Payloads       │              │   Payloads       │              │
└──────────────┘                  └──────────────┘                  └──────────────┘
```

**Trust boundaries:**
- **Trusted:** Android device, Mac computer (both owned by the same person)
- **Low-trust:** VPS relay (can see metadata but never plaintext payloads)
- **Untrusted:** Network paths between all components

---

## 2. Technology Stack Decisions

### 2.1 Android — Kotlin

| Decision | Choice | Justification |
|----------|--------|---------------|
| Language | **Kotlin** | Native Android runtime compatibility |
| Build system | **Gradle 8.x** with Kotlin DSL | Standard Android build tool |
| Min API | **26 (Android 8.0 Oreo)** | Broad physical device compatibility (`minSdk = 26`) |
| Target API | **34 (Android 14)** | Compliant foreground service types (`connectedDevice|dataSync|camera`) |
| Crypto | **AndroidKeyStore** + pure-Kotlin RFC 7748/8032 **Curve25519** | Hardware-wrapped AES keys + X25519 across Android 8–14+ |
| Networking | **OkHttp** + WebSocket client | Mature TLS/WebSocket transport |
| Camera | **Camera2 (`CameraCaptureModule`)** | Explicit opt-in JPEG preview streaming |
| Storage | **AndroidKeyStore-wrapped SecureStorage** + SAF/scoped files | Encrypted credentials + user-selected folder support |
| DI | **Manual** | Lightweight dependency wiring |
| Testing | **JUnit 4 + MockWebServer** | Fast local JVM verification |

### 2.2 macOS — Swift CLI

| Decision | Choice | Justification |
|----------|--------|---------------|
| Language | **Swift 6.0** | Native macOS Keychain, CryptoKit, and ImageIO integration (`macOS 15.0+`) |
| Build system | **Swift Package Manager (SPM)** | Standard Swift build tool |
| CLI framework | **Native CLI (`PhoneLinkCLI`) + `PhoneLinkKit`** | Zero external dependency footprint |
| Crypto | **Apple CryptoKit** | Native X25519, Ed25519, HKDF-SHA256, and AES-256-GCM |
| Networking | **URLSessionWebSocketTask** + `PinnedURLSessionDelegate` | Native WebSocket + SPKI certificate pinning |
| Camera viewer | **Terminal ANSI renderer (`CameraTerminalRenderer`) + `--save`** | ImageIO/CoreGraphics JPEG luminance decoding |
| Key storage | **macOS Keychain** via Security framework | Secure credential persistence |
| Testing | **`PhoneLinkTests` executable harness** | Standalone SwiftPM test runner |

### 2.3 VPS Relay — Go

| Decision | Choice | Justification |
|----------|--------|---------------|
| Language | **Go 1.26+** | Single static binary (`CGO_ENABLED=0`), low memory footprint |
| Framework | **Standard library** `net/http` + **gorilla/websocket** | Hardened headers, rate limiting, and WebSocket framing |
| TLS | **Caddy ACME TLS 1.3** or built-in `--tls-cert`/`--tls-key` | End-to-end encrypted control/relay transport |
| Auth | **Ed25519 & ECDSA P-256** challenge-response + Bearer tokens | Zero-trust device registration & revocation |
| Persistence | **Atomic JSON state (`PHONELINK_DATA_DIR`)** | Survives container/daemon restarts |
| Deployment | **Docker / systemd + Caddy** | Reproducible production deployment |
| Logging | **Go `slog`** (structured JSON logging) | Auditability with zero payload leakage |
| Testing | **Go `testing` (`-race`)** | Race-checked unit and integration suites |

### 2.4 Shared Protocol

| Decision | Choice | Justification |
|----------|--------|---------------|
| Transport | **WebSocket over TLS 1.3** | Persistent bidirectional connection; NAT-friendly |
| Wire Format | **Versioned JSON envelopes (`schema_version = 1`)** | Uniform encoding across Kotlin, Swift, and Go; mirrors `shared/schema/*.proto` reference contracts |
| E2E encryption | **X25519 key exchange** + **AES-256-GCM** with sequence AAD | Identity-authenticated E2E session setup; VPS never has keys |
| Reference Schemas | `shared/schema/*.proto` | Canonical schema definitions verified via `protoc` round-trip tests |

---

## 3. Component Architecture

### 3.1 Android App

```
android/
├── app/
│   └── src/main/
│       ├── kotlin/com/phonelink/
│       │   ├── PhoneLinkApp.kt              # Application class
│       │   ├── identity/                     # AND-2: Device identity
│       │   │   └── DeviceIdentityManager.kt
│       │   ├── crypto/                       # AND-3: Key management & E2E
│       │   │   ├── Curve25519Primitives.kt
│       │   │   ├── E2EEncryptionManager.kt
│       │   │   ├── E2EPeerSession.kt
│       │   │   └── KeyManager.kt
│       │   ├── storage/                      # AND-4: Secure storage
│       │   │   └── SecureStorage.kt
│       │   ├── transport/                    # AND-5 / AND-8: Transport
│       │   │   ├── NetworkTransport.kt
│       │   │   ├── ReconnectionManager.kt
│       │   │   └── RelayUrlHelper.kt
│       │   ├── auth/                         # AND-6: Authentication
│       │   │   └── AuthClient.kt
│       │   ├── service/                      # AND-7: Foreground service
│       │   │   └── ConnectionForegroundService.kt
│       │   ├── receiver/                     # AND-9: Boot recovery
│       │   │   └── BootReceiver.kt
│       │   ├── files/                        # FILE-1–4: Storage & transfer
│       │   │   ├── FileOperationHandler.kt
│       │   │   └── StorageAccessLayer.kt
│       │   ├── camera/                       # CAM-1/CAM-2: Camera
│       │   │   ├── CameraAuthorizationGate.kt
│       │   │   └── CameraCaptureModule.kt
│       │   ├── mic/                          # FS-13: Remote Microphone
│       │   │   ├── MicAuthorizationGate.kt
│       │   │   └── MicCaptureModule.kt
│       │   ├── actions/                      # FILE-5: Scoped actions
│       │   │   └── RemoteActionRegistry.kt
│       │   └── ui/                           # Minimal UI
│       │       └── MainActivity.kt
│       └── AndroidManifest.xml
├── build.gradle.kts
└── settings.gradle.kts
```

### 3.2 Mac Client

```
mac/
├── Package.swift
├── Sources/
│   ├── PhoneLinkCLI/
│   │   └── main.swift                       # MAC-4: CLI entry point & subcommands
│   └── PhoneLinkKit/
│       ├── ActionClient.swift               # Device ping / telemetry client
│       ├── AuthClient.swift                 # MAC-2: Auth, pairing, revoke HTTP client
│       ├── CameraClient.swift               # CAM-3: Camera stream consumer
│       ├── CameraViewer.swift               # CAM-4: Terminal ASCII renderer & state machine
│       ├── ConnectionManager.swift          # MAC-3: WebSocket, backoff, SPKI pinning
│       ├── DeviceIdentity.swift             # MAC-2: Keychain Ed25519 identity
│       ├── E2EEncryptionManager.swift       # X25519 + HKDF + AES-256-GCM + AAD
│       ├── E2ESessionHelper.swift           # Authenticated E2E session transport
│       ├── FileClient.swift                 # FILE-2/3/4: Listing, chunked download & upload
│       ├── MicAudioEngine.swift             # FS-13: WAV writer & AVAudioEngine playback
│       ├── MicClient.swift                  # FS-13: Remote microphone stream client
│       └── ReplayProtection.swift         # SEC-1: Replay protection filter
├── Tests/
│   └── PhoneLinkTests/
└── README.md
```

### 3.3 VPS Relay

```
vps/
├── cmd/
│   └── relay/
│       └── main.go                          # Entry point
├── internal/
│   ├── server/                              # HTTP/WS server
│   │   └── server.go
│   ├── auth/                                # VPS-2: Device auth registry
│   │   ├── registry.go
│   │   └── verifier.go
│   ├── session/                             # VPS-3: Session coordination
│   │   ├── coordinator.go
│   │   └── pairing.go
│   ├── relay/                               # VPS-4: Data relay
│   │   └── relay.go
│   ├── security/                            # VPS-5: Hardening
│   │   ├── ratelimit.go
│   │   └── middleware.go
│   ├── resume/                              # VPS-6: Session resumption
│   │   └── resumption.go
│   └── logging/                             # VPS-7: Structured logging
│       └── logger.go
├── deploy/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── deploy.sh
├── go.mod
├── go.sum
└── README.md
```

---

## 4. Data Flow Diagrams

### 4.1 Authentication Flow

```
Android                          VPS                              Mac
   │                              │                                │
   │  1. TLS connect              │                                │
   │─────────────────────────────►│                                │
   │                              │                                │
   │  2. Auth request             │                                │
   │  (device_id, timestamp,     │                                │
   │   Ed25519 signature)         │                                │
   │─────────────────────────────►│                                │
   │                              │  3. Verify signature           │
   │                              │  against device registry       │
   │  4. Auth response            │                                │
   │  (session_token, challenge)  │                                │
   │◄─────────────────────────────│                                │
   │                              │                                │
   │                              │  5. TLS connect                │
   │                              │◄────────────────────────────────│
   │                              │                                │
   │                              │  6. Mac auth request           │
   │                              │◄────────────────────────────────│
   │                              │  7. Verify & pair              │
   │                              │  8. Mac auth response          │
   │                              │────────────────────────────────►│
   │                              │                                │
   │  9. E2E key exchange         │  (relayed as opaque bytes)     │
   │◄═════════════════════════════╪════════════════════════════════►│
   │                              │                                │
   │  10. E2E encrypted session established                        │
   │◄═══════════════════════════════════════════════════════════════►│
```

### 4.2 File Transfer Flow (Download)

```
Mac CLI                          VPS Relay                        Android
   │                              │                                │
   │  1. file.list_request        │                                │
   │  (E2E encrypted)            │  2. Forward opaque bytes       │
   │─────────────────────────────►│───────────────────────────────►│
   │                              │                                │
   │                              │                3. Decrypt, check auth
   │                              │                4. Read SAF/MediaStore
   │                              │                5. Encrypt response
   │                              │  6. Forward opaque bytes       │
   │  7. file.list_response       │◄───────────────────────────────│
   │◄─────────────────────────────│                                │
   │  8. Decrypt, display listing │                                │
   │                              │                                │
   │  9. file.download_request    │                                │
   │  (E2E encrypted)            │  10. Forward                   │
   │─────────────────────────────►│───────────────────────────────►│
   │                              │                                │
   │                              │               11. Read file chunks
   │                              │               12. Encrypt each chunk
   │  13. Encrypted chunks        │  14. Forward chunks            │
   │◄─────────────────────────────│◄───────────────────────────────│
   │  15. Decrypt, write,         │                                │
   │      verify checksum         │                                │
```

### 4.3 Camera Flow

```
Mac CLI                          VPS Relay                        Android
   │                              │                                │
   │  1. camera.start_request     │                                │
   │  (E2E encrypted)            │  2. Forward                    │
   │─────────────────────────────►│───────────────────────────────►│
   │                              │                                │
   │                              │             3. Check dual-gate auth
   │                              │             4. If authorized:
   │                              │                Start foreground camera
   │  5. camera.start_response   │  6. Forward                    │
   │  (accepted/denied)          │◄───────────────────────────────│
   │◄─────────────────────────────│                                │
   │                              │                                │
   │  7. camera.frame (periodic JPEG, E2E encrypted)               │
   │◄═════════════════════════════╪════════════════════════════════│
   │  8. Display frames           │   (VPS sees ciphertext only)   │
   │                              │                                │
   │  9. camera.stop_request      │                                │
   │─────────────────────────────►│───────────────────────────────►│
   │                              │               10. Stop camera   │
   │                              │               11. Remove FG svc │
```

### 4.3b Microphone Streaming Flow

```
Mac CLI                          VPS Relay                        Android
   │                              │                                │
   │  1. mic_start_req            │                                │
   │  (E2E encrypted)            │  2. Forward                    │
   │─────────────────────────────►│───────────────────────────────►│
   │                              │                                │
   │                              │             3. Check dual-gate auth
   │                              │             4. If authorized:
   │                              │                Elevate FGS_MICROPHONE
   │                              │                Start AudioRecord PCM
   │  5. mic_start_resp           │  6. Forward                    │
   │  (accepted/denied + rate)   │◄───────────────────────────────│
   │◄─────────────────────────────│                                │
   │                              │                                │
   │  7. mic_chunk (200ms 16-bit PCM, E2E encrypted)              │
   │◄═════════════════════════════╪════════════════════════════════│
   │  8. Play audio / write WAV   │   (VPS sees ciphertext only)   │
   │                              │                                │
   │  9. mic_stop_req (or Ctrl+C / offline)                       │
   │─────────────────────────────►│───────────────────────────────►│
   │                              │               10. Release mic   │
   │                              │               11. Revert FGS    │
```

---

## 5. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        TRUSTED DOMAIN (Owner)                          │
│  ┌─────────────────┐                          ┌─────────────────┐     │
│  │  Android Device  │                          │   Mac Computer  │     │
│  │  ───────────────│                          │  ───────────────│     │
│  │  • Private keys  │                          │  • Private keys │     │
│  │  • Plaintext data│                          │  • Plaintext    │     │
│  │  • Camera/Mic    │                          │  • File storage │     │
│  │  • Auth decisions│                          │  • CLI commands │     │
│  └────────┬─────────┘                          └────────┬────────┘     │
└───────────┼──────────────────────────────────────────────┼─────────────┘
            │ TLS 1.3 + E2E payload                       │ TLS 1.3 + E2E payload
┌───────────┼──────────────────────────────────────────────┼─────────────┐
│           ▼              LOW-TRUST DOMAIN                ▼             │
│  ┌────────────────────────────────────────────────────────────┐        │
│  │                      VPS Relay                             │        │
│  │  ─────────────────────────────────────────────────────────│        │
│  │  CAN see:  device IDs, connection times, message sizes    │        │
│  │  CANNOT see:  file contents, camera frames, mic PCM audio │        │
│  │  CANNOT do:  decrypt E2E payloads, forge auth, store data │        │
│  └────────────────────────────────────────────────────────────┘        │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 6. Requirements Traceability

| REQ-1 Requirement | Architecture Component | DAG Nodes |
|--------------------|----------------------|-----------|
| FS-01 Device Pairing | QR/code pairing via VPS | ARCH-2, VPS-2, AND-6, MAC-2 |
| FS-02 Authentication | Ed25519 + Keystore/Keychain | AND-2/3, VPS-2, MAC-2 |
| FS-03 Bidirectional Connectivity | WebSocket relay | AND-5, VPS-4, MAC-3 |
| FS-04 Device Status | VPS presence tracking | VPS-3, INT-2 |
| FS-05/06/07 Files | SAF/MediaStore + E2E chunks | FILE-1–4 |
| FS-08 Camera | CameraX + JPEG frames | CAM-1–4 |
| FS-13 Microphone | AudioRecord + 16-bit PCM + AVAudioEngine/WAV | mic.proto, MicCaptureModule, MicClient |
| FS-09 Recovery | Resumption tokens + backoff | AND-8, VPS-6, INT-3 |
| FS-10 Revocation | VPS registry removal | VPS-2, MAC-4 |
| FS-12 Scoped Actions | Fixed allowlist in RemoteActionRegistry | FILE-5 |
| VPS as low-trust relay | E2E encryption layer above TLS | ARCH-2, VPS-4 |
| Zero payload retention | No-persist relay design | VPS-4, VPS-7 |

---

*End of architecture specification.*
