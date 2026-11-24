# PhoneLink

> **Personal authorized remote-access system connecting 1 Android phone, 1 macOS client, and 1 low-trust Linux VPS relay.**

[![Test Suite](https://img.shields.io/badge/regression%20tests-26%2F26%20passing-brightgreen)](#testing--verification)
[![DAG Status](https://img.shields.io/badge/DAG%20progress-93.9%25%20(46%2F49)-blue)](#development-dag)
[![Security Policy](https://img.shields.io/badge/privacy-anti--stalkerware%20enforced-success)](docs/PRIVACY_MODEL.md)

PhoneLink allows you to securely access files, inspect device status, locate your phone, and preview the camera from your Mac without third-party cloud intermediaries. The relay runs on your own Linux VPS, while payload data is strictly end-to-end encrypted between your Mac and phone.

---

## Architecture & Trust Model

```
+---------------+         End-to-End Encrypted Tunnel (AES-256-GCM)        +---------------+
|   macOS CLI   | <=====================================================> | Android Phone |
+---------------+                                                         +---------------+
        \                                                                         /
         \---> TLS 1.3 ----> [ Low-Trust Linux VPS Relay ] <---- TLS 1.3 --------/
                              (Zero Plaintext Visibility)
```

- **Untrusted VPS Relay:** The server acts purely as a stateless frame broker. All files, file lists, camera streams, and action payloads are encrypted via ephemeral AES-256-GCM keys negotiated directly between Mac and Android (ECDH secp256r1). The VPS cannot read, store, or tamper with your data.
- **Zero Inbound Ports on Client Devices:** Android connects outbound to the VPS; Mac connects outbound to the VPS. No static public IP or port forwarding is required on phone or home networks.
- **Anti-Stalkerware Design Invariants:**
  - **Ongoing Persistent Notification:** Whenever PhoneLink is active, Android displays an un-dismissible foreground notification.
  - **No Hidden Mode:** Launcher icon is always visible; zero stealth admin or background tracking capabilities.
  - **Dual-Gate Camera Access:** Camera preview requires both OS runtime permission AND an in-app physical toggle (defaults to OFF). Camera hardware is instantly released when viewing stops.
  - **Scoped Remote Actions:** Only fixed allowlisted actions (`PING`, `LOCATE`) are supported. Arbitrary shell command execution is structurally blocked.

---

## Documentation Index

- **[Setup & Pairing Guide](docs/SETUP_GUIDE.md):** Complete walkthrough for deploying the VPS relay, installing the Android app, and setting up the Mac CLI.
- **[User Manual](docs/USER_MANUAL.md):** Comprehensive reference for CLI commands (`status`, `files`, `camera`, `actions`, `unpair`).
- **[Privacy & Security Model](docs/PRIVACY_MODEL.md):** Architectural anti-stalkerware guarantees, threat boundary analysis, and data retention policies.
- **[VPS Production Deployment Runbook](docs/VPS_PRODUCTION_DEPLOYMENT.md):** Hardened systemd unit, Caddy TLS reverse proxy, atomic deployment, and rollback procedures.
- **[Chaos Testing Results](docs/CHAOS_TEST_RESULTS.md):** Network fault injection reports (packet loss, latency, zombie TCP, VPS restart SLA < 3000ms).
- **[Android Compatibility Report](docs/ANDROID_COMPATIBILITY_REPORT.md):** OEM & OS compatibility matrix validation (Android 13 & 14 across Pixel, Samsung, Xiaomi, OnePlus).
- **[Penetration Testing & Security Audit](docs/SECURITY_VALIDATION_REPORT.md):** Fuzzing, path traversal prevention, and cryptographic leak audit results.

---

## Quick Start (Mac CLI)

### 1. Build and Install
```bash
./mac/scripts/package_mac_release.sh
sudo cp mac/release/PhoneLink-v1.0.0-macos-arm64/bin/phonelink /usr/local/bin/
phonelink --version
```

### 2. Pair with Phone
```bash
phonelink pair --relay https://relay.example.com
# Enter the generated 6-digit code into your Android PhoneLink app
```

### 3. Core Commands
```bash
# Check device status & battery
phonelink status

# List & download remote files
phonelink files list /Downloads
phonelink files download /Downloads/document.pdf ./document.pdf

# Upload a file to phone
phonelink files upload ./image.png /Downloads/image.png

# Find a misplaced phone (rings aloud)
phonelink actions locate

# Preview camera
phonelink camera preview
```

---

## Testing & Verification

The repository maintains an automated end-to-end regression test suite covering every completed DAG node:

```bash
# Run full 26-step unified regression test suite
./scripts/run_all_tests.sh
```

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.
