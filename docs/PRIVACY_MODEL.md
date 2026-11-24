# PhoneLink - Privacy, Security & Consent Model (`PRIVACY_MODEL.md`)

**Classification:** Public Specification  
**Design Principle:** Personal Authorized Remote Access with Structural Anti-Stalkerware Guarantees  
**Target Audience:** Users, Security Auditors, Device Administrators

---

## 1. Core Purpose & Intended Use

PhoneLink is built exclusively for a **single owner operating their own personal devices**:
1. Exactly one Android smartphone owned by the user.
2. Exactly one macOS computer owned by the user.
3. Exactly one lightweight Linux VPS acting strictly as an untrusted encrypted frame relay.

PhoneLink is **explicitly not designed for, and architecturally prohibits**:
- Covert surveillance or location tracking.
- Remote monitoring of employees, family members, or third parties.
- Bypassing operating system security controls or consent prompts.
- Silent background audio/video recording.

---

## 2. Structural Anti-Stalkerware Guarantees (`ARCH-4` / `AND-2` / `CAM-1`)

PhoneLink incorporates hardware and operating-system-level constraints that make covert surveillance structurally impossible:

### A. Permanent, Un-dismissible Foreground Notification
Whenever PhoneLink is running, connected, or listening on Android:
- Android requires a persistent Ongoing Foreground Notification in the system tray (`ConnectionForegroundService`).
- If data is actively streaming (file transfer or camera preview), the notification text immediately updates to reflect the active operation (e.g. `Streaming camera preview to paired Mac...`).
- The notification cannot be swiped away or hidden.

### B. Visible App Launcher Icon
- PhoneLink maintains a visible application icon on the Android launcher screen.
- It contains no stealth mode, zero stealth intent receivers, and zero hidden admin modes.
- It does not request `BIND_DEVICE_ADMIN` or device management privileges.

### C. Independent Dual-Gate Camera Activation (`CAM-1` / `CAM-2`)
Remote camera activation cannot occur silently:
1. **Gate 1 (OS Permission):** The app must hold Android's runtime camera permission (`android.permission.CAMERA`).
2. **Gate 2 (Explicit Local In-App Toggle):** The user must physically toggle "Allow Remote Camera Access" inside the PhoneLink Android app.
   - **Default:** Always `OFF` upon fresh install.
   - **No Remote Toggle:** The toggle can **never** be enabled remotely via Mac commands.
3. **Immediate Hardware Release:** When the Mac stops viewing or the session drops, the camera hardware session is immediately closed and the lens released.

### D. Scoped Remote Actions Allowlist (`FILE-5`)
Remote execution is restricted to a hardcoded enum:
- `PING`: Network round-trip check and battery level report.
- `LOCATE`: Plays an audible ringtone on the phone at maximum volume to find a misplaced device.
- **Zero Arbitrary Execution:** Shell execution, arbitrary intent broadcasting, package installation, and script evaluation are rejected cryptographically.

---

## 3. Cryptographic Threat Boundary & Zero-Plaintext Guarantee

```
[ macOS Client ] <==== End-to-End Encrypted Tunnel (AES-256-GCM) ====> [ Android Phone ]
       \                                                                     /
        \---> TLS 1.3 ---> [ Untrusted Linux VPS Relay ] <--- TLS 1.3 <-----/
                             (Zero Plaintext Access)
```

1. **VPS Untrusted Relay Model:**
   - The VPS relay terminates only the outer TLS transport.
   - The payload itself is encrypted using symmetric session keys derived via ECDH (secp256r1) key agreement directly between Mac and Android.
   - The VPS holds no private keys, derives no session keys, and possesses zero cryptographic ability to decrypt relayed files, file listings, camera frames, or action payloads.

2. **Zero Plaintext Persistence at Rest:**
   - The VPS never writes payload bytes, camera frames, or file contents to disk.
   - In-flight buffers reside only in transient volatile memory.
   - The audit log records only high-level transport metadata (source device ID, target device ID, byte counts, and timestamps).

3. **Replay & MITM Protection (`SEC-1`):**
   - Every packet carries a 64-bit monotonic sequence counter, timestamp, and unique 96-bit nonce.
   - Any replay, frame truncation, or ciphertext tampering triggers immediate AEAD authentication rejection (`cipher: message authentication failed`).

---

## 4. Initial Bootstrap & Pairing Consent (`MAC-2` / `AND-6`)

1. **Short-Lived Out-of-Band Pairing Ceremony:**
   - The Mac requests a 6-digit numeric pairing token with a strict 10-minute expiration window.
   - The user must manually enter this pairing code into the Android application.
   - Once paired, both devices record each other's cryptographic public key fingerprint (`DeviceID = SHA-256(PublicKey)`).
2. **Immediate Revocation:**
   - Either device can revoke pairing instantly from local settings or CLI (`phonelink unpair`).
   - Revocation invalidates all active session tokens and resumption tokens immediately across the VPS coordinator.
