# PhoneLink - User Manual (`USER_MANUAL.md`)

Comprehensive reference manual for the PhoneLink command-line client (`phonelink`) and Android companion app.

---

## 1. Mac Command Line Interface (CLI)

### Global Syntax
```bash
phonelink <subcommand> [options] [arguments]
```

### Global Options
- `--vps <url>`: Override the VPS relay URL (default: `PHONELINK_RELAY_URL` or `http://127.0.0.1:8443`).
- `--tls-pin <sha256>`: Enforce HTTPS/WSS SPKI certificate fingerprint pinning (or set `PHONELINK_TLS_PIN`).
- `--json`: Format output as machine-readable JSON.
- `-h, --help`: Show usage help.
- `-v, --version`: Show CLI version.

### Available Subcommands

| Subcommand | Description | Example |
|---|---|---|
| `info` | Shows local Mac Device ID/public key, or phone info with `--device` | `phonelink info --device --vps https://relay.example.com` |
| `device info` | Fetches phone model, OS version, battery, and storage | `phonelink device info --vps https://relay.example.com` |
| `device ping` | Rings/vibrates phone to locate a misplaced device | `phonelink device ping --duration 5 --vps https://relay.example.com` |
| `pair` | Authenticates with VPS and generates pairing token + 8-char code | `phonelink pair --vps https://relay.example.com` |
| `status` | Checks relay connectivity, phone presence (`--watch`), and RTT | `phonelink status --vps https://relay.example.com` |
| `ping` | Measures E2E ping RTT (`--count <n>`) or relay RTT (`--relay`) | `phonelink ping --count 3 --vps https://relay.example.com` |
| `files ls` | Lists accessible files in Android scoped/shared folder | `phonelink files ls Downloads --vps https://relay.example.com` |
| `files get` | Downloads a file securely with `.part` resume and SHA-256 verification | `phonelink files get Downloads/receipt.pdf ./receipt.pdf` |
| `files put` | Uploads a local file to an Android directory (`remote_directory`) | `phonelink files put ./photo.jpg Downloads` |
| `camera view` | Captures live JPEG frames and renders terminal ASCII preview | `phonelink camera view --fps 2 --duration 10` |
| `camera stream` | Streams encrypted JPEG frames to stdout / `--save <dir>` without UI | `phonelink camera stream --save ./frames --max-frames 30` |
| `revoke` | Immediately revokes the paired Android device (or `--self --confirm`) | `phonelink revoke --vps https://relay.example.com` |
| `wipe` | Wipes local Keychain identity credentials and generates a new keypair | `phonelink wipe --confirm` |
| `install-phone` | Prints `/install` URL or starts `--local` Wi-Fi QR OTA installer | `phonelink install-phone --local` |

---

## 2. Feature Walkthroughs

### A. Secure File Transfers (`FILE-2` / `FILE-3` / `FILE-4`)

#### Listing Remote Files
```bash
phonelink files ls Downloads --vps https://relay.example.com
```

#### Downloading a File
```bash
phonelink files get Downloads/travel_invoice.pdf ~/Downloads/travel_invoice.pdf --vps https://relay.example.com
```
- Download chunks are transmitted in 64 KB encrypted AEAD blocks to `<destination>.part`.
- Interrupted transfers automatically resume from the partial file's byte offset unless `--no-resume` is passed.
- On completion, the full-file SHA-256 is verified before renaming to the final path.

#### Uploading a File
```bash
phonelink files put ~/Documents/contract.pdf Downloads --vps https://relay.example.com
```
- Notice the second positional argument is the **destination directory** on Android (e.g., `Downloads` or `""` for root), not a renamed target file.
- Uploads stage atomically into `<filename>.part` on Android and rename only after final whole-file SHA-256 verification succeeds.

---

### B. Remote Camera Viewing (`CAM-3` / `CAM-4`)

#### Requirements
1. Open PhoneLink on Android and grant Android Camera permission.
2. Switch **Remote Camera Access** to **ON** in the PhoneLink app (defaults to **OFF** on every fresh launch/boot).
3. Keep the persistent foreground notification active.

#### Starting Camera Stream
```bash
phonelink camera view --lens back --fps 2 --duration 10 --vps https://relay.example.com
```
- Use `--lens front|back`, `--fps 1..5`, `--quality <10..95>`, `--duration <seconds>`, `--max-frames <N>`, or `--save <dir>`.
- The Android notification visibly indicates `Camera Streaming` (`FOREGROUND_SERVICE_CAMERA`).
- Press `Ctrl+C` or wait for `--duration` / `--max-frames` completion; PhoneLink immediately sends `camera_stop_req` and releases the Android camera hardware.

---

### C. Finding a Misplaced Device (`FILE-5`)

If your phone is lost nearby:
```bash
phonelink device ping --duration 5 --vps https://relay.example.com
# or:
phonelink ping --device --duration 5 --vps https://relay.example.com
```
- Plays the Android system ringtone/alarm chime for the requested duration (`1..30` seconds, automatically stopping when the timer completes) and vibrates (`VIBRATE` permission), accompanied by an action notification showing that a ring was triggered.

---

### D. Revoking Access (`revoke` & `wipe`)

To revoke a lost or stolen phone immediately:
```bash
phonelink revoke --vps https://relay.example.com
```
- Authenticates with your Mac's key, revokes the paired phone on the VPS, terminates its WebSocket session, and invalidates all session/resumption tokens.
- To also revoke the Mac itself and wipe Keychain keys:
```bash
phonelink revoke --self --confirm --vps https://relay.example.com
```

---

## 3. Android Companion App Controls

- **Connection Status & Status Badge:** Displays current pairing/session state and this device's SHA-256 Device ID.
- **VPS Relay Server URL:** Supports `https://...`, `wss://...`, `http://...`, or `host:port` (normalized safely).
- **8-Character Pairing Code:** Enter the 8-character short code (or full token) printed by `phonelink pair` and tap **Connect & Pair**.
- **Remote Camera Access Toggle:** Master opt-in switch; always defaults to **OFF**.
- **Select Shared Folder (SAF):** Optionally grant Storage Access Framework (`ACTION_OPEN_DOCUMENT_TREE`) access to a user-chosen folder (such as Downloads or Documents) in addition to app-scoped external storage.
- **Notification Permission & Background Access:** Grant Notification permission and adjust OEM battery optimization in App Info settings so Android preserves the foreground connection.

---

## 4. Troubleshooting & FAQ

### Problem 1: Mac shows `Paired Android device is OFFLINE`
- Ensure the PhoneLink foreground notification is visible in Android's notification shade. Open the PhoneLink app if the background service was stopped by the OS.
- Tap **Disable Battery Optimization** (opens App Details / Battery settings) and set battery usage to **Unrestricted**.

### Problem 2: Camera preview fails with camera permission/toggle denied
- Grant the Android Camera runtime permission when prompted.
- Turn **Remote Camera Access** ON inside the Android PhoneLink app.

### Problem 3: Reconnection after Wi-Fi / cellular handoff
- PhoneLink uses full-jitter exponential backoff (`ReconnectionManager` on Android, `ConnectionManager` on Mac) and single-use session resumption tokens (`POST /api/v1/auth/resume`).
- Run `phonelink status --vps <url>` from your Mac to verify live connectivity and peer online status.
