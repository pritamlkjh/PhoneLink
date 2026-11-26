# PhoneLink - Setup & Pairing Guide (`SETUP_GUIDE.md`)

This guide walks through deploying the Linux VPS Relay, setting up the Android client, and configuring the macOS CLI client from scratch.

---

## 1. Prerequisites

1. **Linux VPS:**
   - Operating System: Ubuntu 22.04/24.04 LTS or Debian 12
   - Open Inbound Ports: `80` (HTTP for Let's Encrypt), `443` (HTTPS/WSS), `22` (SSH)
   - DNS: A public domain pointing to your VPS IP (e.g. `relay.example.com`)

2. **Android Phone:**
   - Universal compatibility: Android 8.0 Oreo (API 26) through Android 14+ (API 34+)
   - Sideloading permissions enabled ("Install unknown apps" when prompted)

3. **Mac Client:**
   - macOS 15.0+ (Sequoia)
   - Terminal access (zsh/bash)

---

## 2. Deploying the VPS Relay

On your VPS server via SSH:

```bash
# 1. Clone repository
git clone https://github.com/pritamlkjh/PhoneLink.git /opt/phonelink/repo
cd /opt/phonelink/repo

# 2. Deploy Relay Daemon
sudo mkdir -p /opt/phonelink/relay/bin
./vps/deploy/deploy_prod.sh /opt/phonelink/relay/bin

# 3. Install Systemd Service
sudo cp vps/deploy/phonelink-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now phonelink-relay

# 4. Configure Caddy Reverse Proxy
# Edit vps/deploy/Caddyfile with your real DNS domain and ACME email
sudo cp vps/deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl restart caddy

# 5. Verify Public Health Endpoint
curl -i https://relay.example.com/healthz
# Expected: HTTP/2 200 OK {"status":"OK","service":"PhoneLink VPS Relay",...}
```

---

## 3. Installing the Mac Client

On your Mac:

```bash
# 1. Download or compile the release package
# From repo root:
./mac/scripts/package_mac_release.sh

# 2. Install binary to system PATH
sudo cp mac/release/PhoneLink-v1.0.0-macos-arm64/bin/phonelink /usr/local/bin/

# 3. Verify executable
phonelink --version
# Expected: PhoneLink Mac Client v1.0.0 (macOS Sequoia+)
```

---

## 4. Installing the Android App (1-Tap Over-The-Air or Sideload)

PhoneLink supports **1-tap instant installation** on any Android device running Android 8.0 Oreo through Android 14+ (`minSdk = 26`, `targetSdk = 34`).

### Option A: 1-Tap QR Code Scan (Fastest / Local Wi-Fi)
On your Mac, launch the OTA installer server:
```bash
phonelink install-phone --local
# or run directly:
./scripts/serve_phone_installer.py
```
1. An ASCII QR code is displayed in your terminal.
2. Point your Android phone camera at the terminal screen.
3. Tap the link to open the download page.
4. Tap **📥 Tap Here to Download & Install**.
5. Tap **Open** > **Install** when the download finishes.

### Option B: 1-Tap Web Download via VPS Relay (Cellular / Remote)
If your VPS relay is deployed with public HTTPS:
1. Open Chrome on your Android phone and navigate to:
   ```
   https://relay.example.com/install
   ```
2. Tap **📥 Tap Here to Download & Install**.
3. Tap **Open** > **Install**.

### Option C: USB ADB Sideload (Developers)
```bash
adb install -r android/release/PhoneLink-v1.0.0-release.apk
```

---

## 5. First-Time Pairing Ceremony

The pairing ceremony establishes mutual trust and cryptographic identity:

### Step 1: Generate Pairing Token on Mac
In your Mac terminal:
```bash
phonelink pair --vps https://relay.example.com
```
**Output:**
```
==================================================
        PHONELINK OUT-OF-BAND PAIRING
==================================================
Mac Device ID: 4c34b040a6b986b2457c79e6027aeb8ec2c18ab9d01fc87a...
Pairing Token: 39a0cef02267a855d6c1e65c52abbeeb
Short Code:    [39A0CEF0]

Scan QR code or enter this short code on your Android device.
Token expires in 300 seconds.
==================================================
```

### Step 2: Claim Pairing on Android
1. Open the **PhoneLink** app on your phone.
2. Enter the Relay URL: `https://relay.example.com`
3. Enter the 8-character pairing short code (e.g. `39A0CEF0`).
4. Tap **Connect & Pair**.
5. Grant required Android permissions:
   - **Notification Permission:** (Required on Android 13+ to display the ongoing connection status).
   - **Battery Optimization:** Open App Info -> Battery and select **Unrestricted** so the foreground connection persists when the screen is off.

### Step 3: Confirmation
On your Android app, status updates to **Connected**. On your Mac terminal:
```bash
phonelink status --vps https://relay.example.com
```

---

## 6. Verifying Connection Health

Check connection status or run remote commands from Mac:
```bash
phonelink status --vps https://relay.example.com
phonelink device info --vps https://relay.example.com
```
