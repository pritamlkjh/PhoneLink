# PhoneLink - User Manual (`USER_MANUAL.md`)

Comprehensive reference manual for the PhoneLink command-line client (`phonelink`) and Android companion app.

---

## 1. Mac Command Line Interface (CLI)

### Global Syntax
```bash
phonelink <subcommand> [flags] [arguments]
```

### Available Subcommands

| Subcommand | Description | Example |
|---|---|---|
| `status` | Checks real-time connection status, peer battery, and storage | `phonelink status` |
| `files list` | Lists accessible files on Android in Downloads or scoped folders | `phonelink files list /Downloads` |
| `files download` | Downloads a file securely with SHA256 chunk verification | `phonelink files download /Downloads/receipt.pdf ./receipt.pdf` |
| `files upload` | Uploads a local file to the phone's scoped storage | `phonelink files upload ./photo.jpg /Downloads/photo.jpg` |
| `actions ping` | Pings the phone and measures end-to-end round-trip latency | `phonelink actions ping` |
| `actions locate` | Rings phone at maximum volume to locate misplaced device | `phonelink actions locate` |
| `camera preview` | Starts terminal or windowed camera frame stream | `phonelink camera preview --fps 15` |
| `unpair` | Revokes pairing and wipes local credentials | `phonelink unpair` |

---

## 2. Feature Walkthroughs

### A. Secure File Transfers (`FILE-3` / `FILE-4`)

#### Listing Remote Files
```bash
phonelink files list /Downloads
```
Output:
```
Permissions: Scoped Storage (Downloads)
[FILE]  2026-11-20 14:12  4.2 MB   travel_invoice.pdf
[FILE]  2026-11-22 09:30  12.8 MB  recording_2026.m4a
[DIR]   2026-11-24 10:00  -        Documents/
```

#### Downloading a File
```bash
phonelink files download /Downloads/travel_invoice.pdf ~/Downloads/travel_invoice.pdf
```
- Download chunks are transmitted in 64 KB encrypted AEAD blocks.
- On completion, SHA-256 is verified locally against the source checksum.

#### Uploading a File
```bash
phonelink files upload ~/Documents/contract.pdf /Downloads/contract.pdf
```
- Upload uses atomic temporary file writes on Android (`contract.pdf.tmp`) and renames upon full payload verification to prevent partial files.

---

### B. Remote Camera Viewing (`CAM-3` / `CAM-4`)

#### Requirements:
1. In the Android PhoneLink app: Switch "Allow Remote Camera Access" to **ON**.
2. Keep the persistent notification running.

#### Starting Camera Stream:
```bash
phonelink camera preview
```
- Streams low-latency still frames or video preview directly to the Mac terminal or viewer.
- The Android status notification visibly displays: `Streaming camera preview to Mac...`
- Stop the stream at any time by pressing `Ctrl+C` or running:
```bash
phonelink camera stop
```

---

### C. Finding a Misplaced Device (`FILE-5`)

If your phone is lost between couch cushions or on silent:
```bash
phonelink actions locate
```
- Overrides silent/vibrate mode on Android and plays a clear audible chime for 15 seconds.
- Displays a prominent alert notification on the lock screen with a "Stop Alarm" button.

---

## 3. Android Companion App Controls

- **Connection Status:** Shows active WebSocket relay status and paired Mac Device ID.
- **Auto-Start on Boot:** Toggle to automatically launch the background service after phone reboots (`AND-9`).
- **Allow Remote Camera:** Master opt-in toggle for camera access. Defaults to OFF.
- **Unpair:** Immediately wipes identity keys and severs relay access.

---

## 4. Troubleshooting & FAQ

### Problem 1: Mac shows `State: OFFLINE (Peer not connected)`
- **Check Phone:** Verify the persistent ongoing notification is visible in the Android notification shade. If absent, tap the PhoneLink app to launch the foreground service.
- **Battery Optimization:** Ensure PhoneLink is excluded from OEM battery optimization (Settings -> Apps -> PhoneLink -> Battery -> Unrestricted).

### Problem 2: Camera preview returns `ERROR: Camera access denied by device`
- Ensure both requirements are satisfied on the phone:
  1. Camera permission granted in Android Settings.
  2. "Allow Remote Camera Access" toggle turned ON in the PhoneLink app.

### Problem 3: Reconnection after Wi-Fi / LTE handoff
- PhoneLink employs exponential jittered backoff (`AND-8` / `VPS-6`). In most cases, reconnection occurs automatically within 0.5 to 2 seconds.
- To force an immediate reconnection, run `phonelink status` on Mac or tap "Reconnect" in the Android notification.
