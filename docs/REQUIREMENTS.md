# PhoneLink — Requirements, Scope & Threat Boundary

**DAG Node:** `REQ-1`  
**Version:** 1.0  
**Status:** Under Review  
**Date:** 2026-11-23

---

## 1. Product Summary

PhoneLink is a personal, owner-authorized remote-access system connecting a single Android phone and a single macOS computer through a self-managed Linux VPS that acts as a low-trust encrypted relay. All three components are owned and operated by the same person.

The system enables the authorized owner to:
- Securely connect their Android phone and Mac across different networks.
- Browse, download, and upload files between the two devices.
- View the phone's camera feed remotely with explicit authorization.
- See device online/offline status.

---

## 2. Functional Scope

### 2.1 In Scope

| ID | Capability | Description |
|----|-----------|-------------|
| FS-01 | Device Pairing | Explicit, secure initial pairing of one Android device and one Mac |
| FS-02 | Authentication | Cryptographic device identity, handshake, and session management |
| FS-03 | Bidirectional Connectivity | Android↔Mac communication through the VPS relay |
| FS-04 | Device Status | Online/offline presence reporting via the relay |
| FS-05 | Remote File Browsing | List files on the Android device from the Mac |
| FS-06 | File Download | Transfer files from Android to Mac with integrity verification |
| FS-07 | File Upload | Transfer files from Mac to Android with integrity verification |
| FS-08 | Remote Camera Viewing | View periodic JPEG frames from the Android camera on the Mac, with explicit dual-gate authorization |
| FS-09 | Connection Recovery | Automatic reconnection after network interruptions |
| FS-10 | Device Revocation | Ability to revoke a paired device's access |
| FS-11 | Secure Installation | Signed APK and packaged Mac release |
| FS-12 | Scoped Remote Actions | A fixed, build-time allowlist of safe remote actions (no arbitrary commands) |
| FS-13 | Remote Microphone Listening & Recording | Stream live encrypted PCM audio or save WAV recordings from the Android microphone with post-install dual-gate owner authorization |

### 2.2 Explicitly Out of Scope (Non-Goals)

The following are **not** part of the current project and must **not** be implemented without explicit owner approval:

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG-01 | Stealth or hidden operation | Violates consent-first design |
| NG-02 | Silent camera or mic activation | Requires dual-gate explicit auth |
| NG-03 | Bypassing Android/macOS security | Binding constraint |
| NG-04 | Arbitrary remote shell/command execution | Security risk; FILE-5 allowlist only |
| NG-05 | Screen mirroring/sharing | Out of scope |
| NG-06 | Clipboard synchronization | Out of scope |
| NG-07 | Unconsented / background covert audio streaming | Out of scope; remote mic access (`FS-13`) strictly requires post-install dual-gate owner consent + foreground service indicator |
| NG-08 | Automatic folder synchronization | Out of scope |
| NG-09 | Multi-phone or multi-Mac support | Current scope is one pair |
| NG-10 | Browser-based fallback client | Out of scope |
| NG-11 | Full native Mac GUI | CLI-based interface is the approved scope |
| NG-12 | Continuous low-latency video/telepresence | Periodic JPEG frames only |
| NG-13 | Offline file-request queueing | Not specified; requests fail immediately if offline |
| NG-14 | Google Play Store publication | Direct APK distribution only |
| NG-15 | Paid services or subscriptions | Zero-budget constraint |

---

## 3. Device and OS Targets

### 3.1 Android

| Parameter | Value |
|-----------|-------|
| Minimum API Level | **33 (Android 13)** |
| Supported Range | API 33 through the current stable release |
| Language | Kotlin (native Android) |
| Distribution | Direct APK (sideloading) |
| Play Store | Not required |
| Signing | Required — properly signed release APK |
| Play Protect | Must never ask user to disable |
| Permissions | Follow Android scoped storage, runtime permissions, foreground-service restrictions |

### 3.2 macOS

| Parameter | Value |
|-----------|-------|
| Minimum Version | **macOS Sequoia (15.0)** |
| Interface | CLI-based with a CLI-launched camera viewer window |
| Full GUI | Explicitly out of scope |
| Signing/Notarization | Required if distributed outside a fully controlled environment |

### 3.3 VPS

| Parameter | Value |
|-----------|-------|
| Operating System | Linux (self-managed) |
| Role | Low-trust encrypted relay — **never** a data store |
| Hosting Model | Self-managed VPS, prefer free tier / zero-cost options |
| Budget | \$0 — no paid services, domains, certificates, APIs, or subscriptions |
| Fallback | If no suitable free VPS exists, continue with local development and document the blocker |

---

## 4. Device Scope

| Parameter | Value |
|-----------|-------|
| Android devices | Exactly **one** |
| Mac devices | Exactly **one** |
| Owner | **Same person** owns and operates all components |
| Multi-device support | Not required in current scope |
| Multi-owner support | Not required |
| Pairing | Must be explicit — no automatic or implicit pairing |

---

## 5. VPS Data-Retention Policy

This section defines the VPS data-retention policy in **testable terms** as required by REQ-1's acceptance criteria.

### 5.1 Application Payloads (Zero Retention)

| Data Type | May be persisted to VPS disk? | May be held in VPS memory? | Test |
|-----------|-------------------------------|---------------------------|------|
| File contents | **NO** | Only during active relay (transit buffer) | Audit: no file bytes found on VPS disk after relay completes |
| Camera frames | **NO** | Only during active relay (transit buffer) | Audit: no frame data on VPS disk after relay completes |
| Encrypted message payloads | **NO** | Only during active relay (transit buffer) | Audit: no payload bytes on VPS disk post-relay |
| Plaintext application data | **NEVER** — VPS must never possess decryption keys | **NEVER** | Instrumentation confirms ciphertext-only relay |

**Testable statement:** After any relay operation completes, zero bytes of file content, camera frame data, or encrypted message payload exist on VPS persistent storage. The VPS never possesses the keys to decrypt application-layer payloads.

### 5.2 Operational Metadata (Minimal Retention)

| Data Type | May be retained? | Maximum Retention | Test |
|-----------|-----------------|-------------------|------|
| Authentication event logs (success/failure, device ID, timestamp) | Yes | **7 days** | Log rotation configured and verified |
| Connection event logs (connect, disconnect, error) | Yes | **7 days** | Log rotation configured and verified |
| Device registry (public keys, device fingerprints) | Yes | Until explicitly revoked | Revocation test removes the entry |
| Session tokens | Yes (in memory only) | Until session end or token expiry, **max 24 hours** | Token rejected after expiry window |

> [!IMPORTANT]
> **No log entry may ever contain:** file contents, camera frame data, message payloads, private keys, session secrets, or any user-generated content. This must be verified by log audit under both normal and error conditions.

### 5.3 VPS Data-Retention Decision Rationale

- **7-day operational metadata retention** balances debugging needs against data minimization. This is long enough to investigate connection issues but short enough to limit exposure.
- **24-hour session token maximum** bounds the window during which a stolen resumption token could be replayed.
- These values are **initial decisions** subject to revision during ARCH-4 threat modeling if the analysis identifies a need for shorter windows.

---

## 6. Security and Privacy Requirements

These are **binding constraints**, not aspirational goals. Each is stated as a testable acceptance criterion.

### 6.1 End-to-End Encryption

| Requirement | Test |
|-------------|------|
| Android and Mac are the cryptographic endpoints | Key exchange occurs directly between Android and Mac |
| VPS relays ciphertext only | VPS instrumentation confirms it never sees plaintext |
| VPS-terminated TLS alone is insufficient | Protocol design must include an application-layer E2E encryption on top of transport TLS |
| Reviewed cryptographic libraries only | No custom cryptographic primitives; use established libraries (e.g., libsodium/NaCl, Tink, Signal Protocol) |

### 6.2 Device Identity and Authentication

| Requirement | Test |
|-------------|------|
| Cryptographic device identity (Keystore/Keychain-backed) | Private key never leaves hardware security boundary |
| Authentication handshake with replay protection | Replayed handshake messages are rejected |
| Session token with bounded validity | Expired tokens are rejected |
| Immediate-effect revocation | Revoked device cannot authenticate on the next attempt |
| Pairing must be explicit | No automatic/silent device registration |

### 6.3 Camera Authorization (Dual-Gate)

| Requirement | Test |
|-------------|------|
| Camera is OFF by default | Fresh install: in-app toggle is OFF |
| Gate 1: Android OS runtime camera permission | Camera capture fails if OS permission not granted |
| Gate 2: Separate in-app opt-in toggle, defaults OFF | Camera capture fails if in-app toggle is OFF, even with OS permission |
| No silent activation | Remote camera request never auto-approved |
| Visible camera-use indicator | OS-mandated indicator present for entire capture duration |
| Foreground service during capture | Camera runs in a foreground service with persistent notification |
| Auto-deactivation on session end/timeout | Camera stops within 1 second of session termination |
| Authorization enforced on Android, not by trusting Mac/VPS | Crafted raw protocol message cannot bypass the Android-side gates |

### 6.3b Microphone Authorization (Dual-Gate)

| Requirement | Test |
|-------------|------|
| Microphone is OFF by default | Fresh install: `Allow Remote Microphone Access` toggle is `OFF` |
| Gate 1: Android OS runtime `RECORD_AUDIO` permission | Mic capture fails (`STATUS_MIC_PERMISSION_DENIED`) until owner grants runtime permission post-install |
| Gate 2: Separate in-app opt-in toggle, defaults `OFF` | Mic capture fails (`STATUS_MIC_TOGGLE_DISABLED`) if toggle is `OFF`, even with OS permission |
| No silent or remote activation | Remote start request never enables the in-app toggle |
| Visible mic-use indicator | Android OS mic indicator + `FOREGROUND_SERVICE_MICROPHONE` ongoing notification active for entire stream |
| Auto-deactivation on stop, disconnect, or max duration | `AudioRecord` stops & releases immediately on `mic_stop_req`, WebSocket disconnect, peer offline, or watchdog timeout |

### 6.4 File Access

| Requirement | Test |
|-------------|------|
| Use Android's scoped storage APIs (SAF/MediaStore) | No legacy broad filesystem access |
| Request minimum necessary permissions | Permission audit shows no over-requesting |
| Validate every file operation server-side (Android) | Path-traversal attempt is rejected |
| Restrict writes to permitted destinations | Write outside granted scope is rejected |
| No arbitrary shell commands | No code path accepts a free-form command string |

### 6.5 Abuse Prevention

| Scenario | Required Structural Prevention |
|----------|-------------------------------|
| Hidden camera activation | Dual-gate auth + OS indicator + foreground service notification |
| Hidden microphone activation | Post-install dual-gate auth + OS mic indicator + `FOREGROUND_SERVICE_MICROPHONE` notification |
| Silent remote file access | Visible foreground-service notification whenever data flows |
| Unapproved pairing | Explicit pairing ceremony required |
| Authorization bypass via raw protocol messages | Authorization enforced on the Android device, not merely by client behavior |
| Arbitrary remote command execution | FILE-5 uses a fixed build-time allowlist; no shell/eval code paths |
| Non-consensual monitoring | App icon always visible; persistent notification; camera indicator; no hidden mode |

### 6.6 General Security

| Requirement |
|-------------|
| No secrets in source control (Git history included) |
| No secrets in log output |
| No TLS verification bypass left in release builds |
| Input validation on all received messages (treat as adversarial) |
| Dependency vulnerability scanning in CI |
| Rate limiting on VPS authentication endpoints |
| Message size limits enforced |

---

## 7. Camera Streaming Target

**Decision:** Periodic JPEG frames for a preview use case.

- Not continuous low-latency video.
- Not real-time telepresence.
- Frame rate target: **1–5 FPS** (adjustable, best-effort).
- Frame format: JPEG.
- Quality: Acceptable for identifying contents, not broadcast quality.

This decision constrains CAM-3's scope and prevents scope creep into video codec engineering.

---

## 8. Offline Request Behavior

**Decision:** Requests fail immediately if the target device is offline.

- Mac requests a file listing while Android is offline → immediate failure with a clear error.
- Mac requests camera activation while Android is offline → immediate failure with a clear error.
- No request queueing. No deferred delivery.

This simplifies VPS-4, FILE-3, and CAM-3 design and avoids the complexity of a durable message queue.

---

## 9. FILE-5 Remote Action Allowlist

**Decision:** The initial fixed allowlist is:

| Action ID | Action | Description | User-Visible Effect |
|-----------|--------|-------------|---------------------|
| `device.ping` | Ping/Locate | Make the Android device play a sound and/or vibrate | Sound/vibration on the device |
| `device.info` | Device Info | Retrieve basic device information (model, OS version, battery level, storage summary) | Information displayed on Mac CLI |

This is deliberately minimal. Each action is:
- Fixed at build time (not configurable remotely).
- Independently permission-gated on the Android side.
- User-visible when triggered.
- Harmless if triggered accidentally.

**No action in this list executes arbitrary commands, scripts, or shell input.** No code path in the system accepts a free-form command string.

New actions require: (1) explicit owner approval, (2) ARCH-4 threat-model update, (3) SEC-2 re-validation.

---

## 10. Initial Pairing Method

**Decision (Recommendation):** QR-code-based pairing.

**Flow:**
1. Mac CLI generates a short-lived pairing invitation containing the Mac's public key fingerprint and a one-time pairing token.
2. The invitation is displayed as a QR code in the Mac terminal (using Unicode block characters) and also as a manually-typeable short code.
3. The Android app scans the QR code (or the user manually enters the short code).
4. Both devices exchange and verify public keys through the VPS relay.
5. The VPS records both devices as a paired set.

**Security trade-offs:**
- QR code prevents remote-only pairing attacks (requires physical proximity).
- Short code as fallback for accessibility.
- One-time token expires in 5 minutes.
- Pairing token is single-use.
- If intercepted, the pairing can be revoked immediately.

**This decision will be finalized in ARCH-2.** The recommendation is recorded here for downstream nodes to plan against.

---

## 11. Revocation UX

**Decision:** Mac CLI command.

```
phonelink revoke
```

This command:
1. Instructs the VPS to immediately revoke the paired device's authorization.
2. The VPS removes the device from its registry.
3. Any active sessions are terminated.
4. The revoked device cannot reconnect without a new pairing ceremony.

A secondary path (direct VPS access via SSH) is available as a fallback if the Mac CLI is unavailable.

---

## 12. Single Device Pair vs. Registry

**Decision:** Single device pair.

- VPS-2's registry stores exactly one Android device and one Mac device.
- The registry schema supports this as a pair, not an open-ended list.
- Multi-device support is explicitly out of scope (NG-09).
- If multi-device support is added later, the registry schema will need to be extended — this is an accepted future cost of keeping the current implementation simple.

---

## 13. Mac GUI Scope

**Decision:** CLI only through FINAL-1.

- `MAC-4` implements a CLI command framework.
- `CAM-4` implements a CLI-launched window for camera viewing.
- No full native macOS GUI is in scope.
- A GUI may be considered as a Phase 2 effort after FINAL-1.

---

## 14. VPS Hosting Choice

**Decision:** Deferred to ARCH-1, with the following constraints:

- Must be self-managed Linux.
- Must be zero-cost (free tier or free hosting).
- If no suitable free VPS exists, development continues locally with Docker-based simulation.
- The VPS deployment must be reproducible via scripts (IaC or equivalent).
- Deployment configuration must work for both local/Docker and remote VPS targets.

**Evaluated option:** VPSFree.io free tier — severely constrained (limited RAM/CPU, shared NAT, limited ports). Useful for experiments, not confirmed suitable for production relay traffic.

---

## 15. Requirements Traceability

Every requirement above traces to one or more DAG nodes:

| Requirement Area | Primary DAG Nodes |
|-----------------|------------------|
| Device pairing | ARCH-2, VPS-2, AND-6, MAC-2 |
| Authentication | AND-2, AND-3, AND-6, VPS-2, MAC-2 |
| E2E encryption | ARCH-2, AND-5, VPS-4, INT-1 |
| File operations | FILE-1, FILE-2, FILE-3, FILE-4 |
| Camera operations | CAM-1, CAM-2, CAM-3, CAM-4 |
| Microphone operations | FS-13 (`mic.proto`, `MicCaptureModule`, `MicClient`) |
| Scoped remote actions | FILE-5 |
| Connection recovery | AND-8, VPS-6, MAC-3, INT-3 |
| Device revocation | VPS-2, MAC-4 |
| VPS data retention | VPS-4, VPS-7 |
| Abuse prevention | ARCH-4, CAM-1, FILE-5, SEC-1, SEC-2 |
| Security hardening | VPS-5, SEC-1, SEC-2 |
| Testing | TEST-1, TEST-2, TEST-3, TEST-4 |
| Release | REL-1, REL-2, REL-3 |
| Documentation | DOC-1 |

---

## 16. Sign-Off

This requirements document must be reviewed and approved before `ARCH-1` and `ARCH-4` can begin.

**Approval status:** Pending owner review.

| Reviewer | Date | Decision |
|----------|------|----------|
| Owner | — | Pending |

---

*End of requirements specification.*
