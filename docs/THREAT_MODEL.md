# PhoneLink — Threat Model & Abuse-Case Analysis

**DAG Node:** `ARCH-4`  
**Version:** 1.0  
**Depends On:** REQ-1 (COMPLETE)

---

## 1. Threat Model Scope

This document analyzes threats to PhoneLink across four categories:
1. **Infrastructure threats** — VPS compromise, network attacks
2. **Device threats** — device loss/theft, malware
3. **Protocol threats** — replay, MITM, token theft
4. **Abuse-case threats** — non-consensual use, surveillance

Each threat maps to a mitigating DAG node or an explicitly accepted risk.

---

## 2. Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **Network attacker** | Passive eavesdropping, active MITM on untrusted networks | Data theft, session hijacking |
| **VPS attacker** | Full root access to VPS after compromise | Access device data, monitor communications |
| **Physical attacker** | Physical access to a lost/stolen Android or Mac | Extract keys, access data, impersonate device |
| **Malicious insider** | Access to the VPS hosting account | Monitor traffic, modify relay |
| **Abusive user** | Installs PhoneLink on someone else's device without consent | Covert surveillance, stalking |

---

## 3. Threat Analysis

### T-01: VPS Compromise (Full Root Access)

**Impact:** HIGH  
**Likelihood:** MEDIUM (single-instance VPS with free hosting)

**Attack:** Attacker gains root access to VPS via OS vulnerability, SSH brute-force, or hosting provider breach.

**What attacker CAN do:**
- See device IDs, connection times, IP addresses, message sizes
- Block or drop connections
- Attempt to inject messages (rejected by E2E encryption)
- Read operational logs

**What attacker CANNOT do (by design):**
- Decrypt file contents, camera frames, or application payloads (E2E encrypted with keys only on Android/Mac)
- Forge authentication (devices authenticate with Ed25519 signatures; VPS stores only public keys)
- Access Android filesystem or camera (authorization enforced on-device)

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| E2E encryption (VPS relays ciphertext only) | ARCH-2, VPS-4, INT-1 |
| VPS host hardening (firewall, SSH keys, minimal ports) | VPS-5 |
| No payload persistence on VPS | VPS-4, VPS-7 |
| 7-day metadata log rotation | VPS-7 |
| Device-side authorization for all sensitive ops | AND-6, CAM-1, FILE-1 |

**Residual risk:** ACCEPTED — metadata exposure (device IDs, connection times, IP addresses) is inherent to any relay model. Minimized by short log retention.

---

### T-02: Device Loss or Theft (Android)

**Impact:** HIGH  
**Likelihood:** LOW-MEDIUM

**Attack:** Attacker physically possesses the unlocked Android device.

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| Keys stored in Android Keystore (hardware-backed) | AND-3 |
| Keystore keys require device unlock to use | AND-3 |
| Immediate revocation via Mac CLI or VPS SSH | VPS-2 |
| Reinstall generates fresh identity (old keys invalid) | AND-2 |
| Session tokens encrypted at rest | AND-4 |

**If device is locked:** Keys in hardware-backed Keystore are not extractable. Attacker cannot authenticate.

**If device is unlocked:** Attacker could use the running app. Owner must revoke the device immediately via `phonelink revoke` on Mac or direct VPS access.

**Residual risk:** ACCEPTED — an unlocked, unrevoked device is equivalent to giving someone your phone. Revocation procedure must be prominently documented (DOC-1).

---

### T-03: Device Loss or Theft (Mac)

**Impact:** HIGH  
**Likelihood:** LOW-MEDIUM

**Attack:** Attacker possesses the Mac.

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| Keys stored in macOS Keychain (Secure Enclave where available) | MAC-2 |
| Keychain access requires user authentication | MAC-2 |
| Re-pairing generates fresh identity | MAC-2 |
| Revocation via VPS SSH | VPS-2 |

**Residual risk:** Same as T-02 — an unlocked, unrevoked Mac is equivalent to giving someone your computer.

---

### T-04: Replay Attack

**Impact:** MEDIUM-HIGH  
**Likelihood:** LOW (requires network access)

**Attack:** Attacker captures a valid authentication or command message and re-sends it.

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| Nonce + timestamp in every auth message | AND-6, MAC-2 |
| Server rejects duplicate nonces within validity window | VPS-2 |
| Session tokens have bounded validity (max 24h) | VPS-6 |
| E2E encrypted payload includes sequence numbers | ARCH-2 |
| Replay-attack simulation test | SEC-1 |

**Residual risk:** MITIGATED — replay window bounded by nonce tracking and timestamp validation.

---

### T-05: Man-in-the-Middle (MITM)

**Impact:** HIGH  
**Likelihood:** LOW (requires network position)

**Attack:** Attacker intercepts and modifies traffic between device and VPS.

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| TLS 1.3 for transport (certificate validation required) | AND-5, MAC-3, VPS-1 |
| E2E encryption above TLS (double protection) | ARCH-2 |
| Certificate/key pinning | SEC-1 |
| No TLS verification bypass in release builds | AND-5 |

**Residual risk:** MITIGATED — dual-layer encryption makes MITM ineffective even if one layer is compromised.

---

### T-06: Token Theft / Session Hijacking

**Impact:** MEDIUM-HIGH  
**Likelihood:** LOW

**Attack:** Attacker steals a session or resumption token.

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| Tokens stored in encrypted storage | AND-4, MAC-2 |
| Tokens bound to device identity (non-transferable) | VPS-2 |
| Session tokens expire (max 24h) | VPS-6 |
| Resumption tokens single-use | VPS-6 |
| Token never logged or transmitted in plaintext | AND-4, VPS-7 |

**Residual risk:** MITIGATED.

---

### T-07: Malformed / Oversized Messages

**Impact:** MEDIUM (DoS, potential crash)  
**Likelihood:** MEDIUM

**Attack:** Attacker sends crafted messages to crash or exploit a component.

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| Protocol Buffers with strict schema validation | ARCH-3 |
| Message size limits enforced at VPS | VPS-4 |
| Rate limiting per connection | VPS-5 |
| Fuzz testing of message parsers | SEC-1 |
| Input validation on all received messages | SEC-1 |

**Residual risk:** MITIGATED.

---

### T-08: Unauthorized Camera Activation

**Impact:** CRITICAL (privacy violation)  
**Likelihood:** LOW (requires auth bypass)

**Attack:** Someone activates the camera without the device owner's knowledge or consent.

**Mitigations (Dual-Gate):**
| Mitigation | DAG Node |
|-----------|----------|
| **Gate 1:** Android OS runtime camera permission required | CAM-1 |
| **Gate 2:** Separate in-app toggle, defaults OFF | CAM-1 |
| Remote requests never auto-approved | CAM-1 |
| OS-mandated camera-use indicator visible | CAM-2 |
| Foreground service with persistent notification | AND-7, CAM-2 |
| Authorization enforced on Android, not by trusting Mac/VPS | CAM-1 |
| Auto-deactivation on session end/timeout | CAM-2 |
| Raw protocol bypass test in SEC-2 | SEC-2 |

**Design constraints derived from this threat:**
1. Camera toggle MUST default to OFF on fresh install
2. No code path may activate camera without checking BOTH gates
3. The Android device is the sole authority — VPS and Mac cannot override
4. Persistent notification MUST be visible for entire capture duration
5. Camera MUST stop within 1 second of session termination

**Residual risk:** MITIGATED by defense-in-depth (two independent gates + OS indicator + foreground service + auto-timeout).

---

### T-09: Unauthorized File Access

**Impact:** HIGH (privacy violation)  
**Likelihood:** LOW (requires auth bypass)

**Attack:** Someone accesses files outside the granted storage scope, or accesses files without authorization.

**Mitigations:**
| Mitigation | DAG Node |
|-----------|----------|
| Android scoped storage (SAF/MediaStore) | FILE-1 |
| Path traversal validation on all file operations | FILE-1, FILE-2 |
| Write scope enforcement on Android side | FILE-4 |
| Authorization checked per-request on Android | FILE-2, FILE-3, FILE-4 |
| Raw protocol bypass test | SEC-2 |

**Residual risk:** MITIGATED.

---

## 4. Abuse-Case Analysis: Non-Consensual Use

**This is the highest-priority abuse case.** PhoneLink could theoretically be misused to monitor someone without their knowledge.

### Abuse Scenario

> An attacker installs PhoneLink on a victim's Android phone, pairs it with the attacker's Mac, and uses it to monitor the victim's files and camera without consent.

### Structural Preventions

| Prevention | How It Works | Verification |
|-----------|-------------|--------------|
| **Visible app icon** | PhoneLink appears in the app drawer like any normal app. No hidden-app mode. | Fresh-install test: app icon visible |
| **Persistent notification** | Whenever PhoneLink's foreground service is running, a non-dismissible notification is visible in the status bar | AND-7: notification visible for entire service lifetime |
| **Camera indicator** | OS-mandated camera indicator (green dot on Android 12+) visible whenever camera is active | CAM-2: indicator present for entire capture |
| **Camera defaults OFF** | In-app camera toggle defaults to OFF. Even with OS permission, remote activation requires explicit in-app opt-in | CAM-1: fresh-install test |
| **No silent activation** | Remote camera requests require the in-app toggle AND OS permission. Neither can be granted remotely | CAM-1: cannot activate remotely while toggle OFF |
| **Pairing requires physical access** | QR code / short code pairing requires physical proximity to both devices | ARCH-2: pairing flow |
| **No hidden background mode** | App cannot hide its notification or suppress its icon. No "invisible mode" exists in the codebase | SEC-2: code audit confirms no hidden mode |
| **Foreground service type declaration** | Android enforces foreground-service-type restrictions. Camera use requires a declared camera-type foreground service with a visible notification | AND-7, CAM-2 |

### Design Constraints Derived from This Analysis

These are **binding** on all downstream implementation nodes:

1. **DC-01:** No code path in the application may suppress, hide, or make dismissible the foreground-service notification.
2. **DC-02:** No code path may activate the camera without BOTH Gate 1 (OS permission) AND Gate 2 (in-app toggle) being satisfied.
3. **DC-03:** The in-app camera toggle MUST persist as OFF across app updates and MUST default to OFF on fresh install.
4. **DC-04:** No "stealth mode", "invisible mode", or "hide app" feature may exist in the codebase, even as dead code.
5. **DC-05:** The app icon MUST be a standard launcher icon visible in the app drawer.
6. **DC-06:** FILE-5's remote action system MUST use a fixed build-time allowlist. No code path may accept or execute arbitrary commands.
7. **DC-07:** Authorization for sensitive operations (camera, file access) MUST be enforced on the Android device, not by trusting the Mac client or VPS relay.

---

## 5. Threat-to-Node Mapping

| Threat | Mitigating Nodes |
|--------|-----------------|
| T-01 VPS compromise | ARCH-2, VPS-4, VPS-5, VPS-7, INT-1 |
| T-02 Android device loss | AND-2, AND-3, AND-4, VPS-2 |
| T-03 Mac device loss | MAC-2, VPS-2 |
| T-04 Replay attack | AND-6, MAC-2, VPS-2, VPS-6, SEC-1 |
| T-05 MITM | AND-5, MAC-3, VPS-1, ARCH-2, SEC-1 |
| T-06 Token theft | AND-4, MAC-2, VPS-2, VPS-6, VPS-7 |
| T-07 Malformed messages | ARCH-3, VPS-4, VPS-5, SEC-1 |
| T-08 Unauthorized camera | CAM-1, CAM-2, AND-7, SEC-2 |
| T-09 Unauthorized files | FILE-1, FILE-2, FILE-3, FILE-4, SEC-2 |
| Abuse: non-consensual use | CAM-1, AND-7, FILE-5, ARCH-2, SEC-2 |

**Verification:** Every security-relevant downstream node (AND-2, AND-3, AND-4, AND-6, VPS-2, VPS-5, MAC-2, FILE-1, FILE-5, CAM-1, CAM-2, SEC-1, SEC-2) has a corresponding entry in this threat model.

---

## 6. Accepted Risks

| Risk | Justification |
|------|--------------|
| Metadata exposure on VPS compromise | Inherent to relay model; minimized by 7-day retention |
| Unlocked, unrevoked stolen device grants access | Same as any app on an unlocked phone; revocation is the mitigation |
| Free-tier VPS reliability | Zero-budget constraint; documented in REQ-1 |
| Single point of failure (one VPS) | Acceptable for single-owner personal use |

---

*End of threat model. This document is a dependency for: ARCH-2, AND-2, AND-3, VPS-2, FILE-1, FILE-5, CAM-1.*
