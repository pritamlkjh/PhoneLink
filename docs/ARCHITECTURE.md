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
| Language | **Kotlin** | DAG and requirements prefer native Android; Kotlin is the official language |
| Build system | **Gradle 8.x** with Kotlin DSL | Standard Android build tool |
| Min API | **33 (Android 13)** | Per REQ-1 |
| Target API | **35 (Android 15)** | Current stable target |
| Crypto | **Android Keystore** + **Tink** (Google's crypto library) | Hardware-backed keys; Tink provides safe NaCl-compatible E2E primitives |
| Networking | **OkHttp** + custom WebSocket client | Mature, well-tested TLS/WebSocket library |
| Camera | **CameraX** | Jetpack camera library, handles lifecycle and foreground-service integration |
| Storage | **EncryptedSharedPreferences** (Tink-backed) | For secrets; SAF/MediaStore for file access |
| DI | **Manual** (constructor injection) | Avoid unnecessary framework weight for a focused app |
| Testing | **JUnit 5** + **Espresso** + **Robolectric** | Standard Android testing stack |

### 2.2 macOS — Swift CLI

| Decision | Choice | Justification |
|----------|--------|---------------|
| Language | **Swift 5.9+** | Native macOS; excellent Keychain and system integration |
| Build system | **Swift Package Manager (SPM)** | Standard Swift build tool, no Xcode project needed for CLI |
| CLI framework | **swift-argument-parser** | Apple's official CLI argument parsing library |
| Crypto | **CryptoKit** + **swift-crypto** | Native Apple crypto; swift-crypto for cross-platform NaCl-style ops |
| Networking | **URLSessionWebSocketTask** (Foundation) | Built-in WebSocket support, no dependencies |
| Camera viewer | **SwiftUI** minimal window (CLI-launched) | Lightweight way to display JPEG frames |
| Key storage | **macOS Keychain** via Security framework | Hardware-backed key storage |
| Testing | **XCTest** + **Swift Testing** | Standard Swift testing frameworks |

### 2.3 VPS Relay — Go

| Decision | Choice | Justification |
|----------|--------|---------------|
| Language | **Go 1.22+** | Single static binary, low memory (~10–20MB), excellent for relay servers; ideal for free-tier VPS |
| Framework | **Standard library** `net/http` + **gorilla/websocket** | Minimal dependencies, battle-tested WebSocket support |
| TLS | **Go `crypto/tls`** with Let's Encrypt via **certmagic** | Free TLS certificates, automatic renewal |
| Auth | **Ed25519** signature verification | Verifies device identity; Go stdlib has ed25519 support |
| Config | **Environment variables** + `.env` file | 12-factor style, no secrets in code |
| Deployment | **Docker** container + **shell scripts** | Reproducible; works locally and on any Linux VPS |
| Logging | **Go `slog`** (structured logging, stdlib) | Built-in, structured, easy to filter payloads |
| Testing | **Go `testing`** package | Standard; includes benchmarking and race detection |

### 2.4 Shared Protocol

| Decision | Choice | Justification |
|----------|--------|---------------|
| Transport | **WebSocket over TLS 1.3** | Persistent bidirectional connection; NAT-friendly |
| Serialization | **Protocol Buffers v3** | Compact binary format; type-safe; polyglot code generation |
| E2E encryption | **X25519 key exchange** + **XChaCha20-Poly1305** AEAD | Via Tink (Android), CryptoKit (Mac); VPS never has keys |
| Schema location | `shared/schema/*.proto` | Single source of truth for all message types |
| Versioning | **Semver** in protocol header | Each message carries a schema version field |

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
│       │   │   └── DeviceIdentity.kt
│       │   ├── crypto/                       # AND-3: Key management
│       │   │   └── KeyManager.kt
│       │   ├── storage/                      # AND-4: Secure storage
│       │   │   └── SecureStorage.kt
│       │   ├── network/                      # AND-5: Transport
│       │   │   ├── NetworkTransport.kt
│       │   │   └── WebSocketClient.kt
│       │   ├── auth/                         # AND-6: Authentication
│       │   │   └── AuthClient.kt
│       │   ├── service/                      # AND-7: Foreground service
│       │   │   ├── ConnectionService.kt
│       │   │   └── ReconnectionManager.kt    # AND-8
│       │   ├── boot/                         # AND-9: Boot recovery
│       │   │   └── BootReceiver.kt
│       │   ├── files/                        # FILE-1: Storage access
│       │   │   └── StorageAccessLayer.kt
│       │   ├── camera/                       # CAM-1/CAM-2: Camera
│       │   │   ├── CameraAuthGate.kt
│       │   │   └── CameraCaptureModule.kt
│       │   ├── actions/                      # FILE-5: Scoped actions
│       │   │   └── RemoteActionRegistry.kt
│       │   └── ui/                           # Minimal UI
│       │       └── MainActivity.kt
│       ├── proto/                            # Generated protobuf
│       └── AndroidManifest.xml
├── build.gradle.kts
└── settings.gradle.kts
```

### 3.2 Mac Client

```
mac/
├── Package.swift
├── Sources/
│   └── PhoneLink/
│       ├── PhoneLink.swift                  # CLI entry point
│       ├── Commands/                        # MAC-4: CLI commands
│       │   ├── StatusCommand.swift
│       │   ├── PairCommand.swift
│       │   ├── FilesCommand.swift
│       │   ├── CameraCommand.swift
│       │   └── RevokeCommand.swift
│       ├── Auth/                            # MAC-2: Authentication
│       │   ├── MacIdentity.swift
│       │   └── AuthClient.swift
│       ├── Connection/                      # MAC-3: Connection manager
│       │   └── ConnectionManager.swift
│       ├── Crypto/                          # E2E encryption
│       │   └── E2ECrypto.swift
│       ├── Files/                           # File transfer
│       │   └── FileTransferClient.swift
│       ├── Camera/                          # CAM-4: Camera viewer
│       │   └── CameraViewer.swift
│       └── Proto/                           # Generated protobuf
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
│  │  • Camera access │                          │  • File storage │     │
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
│  │  CANNOT see:  file contents, camera frames, app payloads  │        │
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
| FS-09 Recovery | Resumption tokens + backoff | AND-8, VPS-6, INT-3 |
| FS-10 Revocation | VPS registry removal | VPS-2, MAC-4 |
| FS-12 Scoped Actions | Fixed allowlist in RemoteActionRegistry | FILE-5 |
| VPS as low-trust relay | E2E encryption layer above TLS | ARCH-2, VPS-4 |
| Zero payload retention | No-persist relay design | VPS-4, VPS-7 |

---

*End of architecture specification.*
