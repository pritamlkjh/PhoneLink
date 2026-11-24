# PhoneLink - Setup & Pairing Guide (`SETUP_GUIDE.md`)

This guide walks through deploying the Linux VPS Relay, setting up the Android client, and configuring the macOS CLI client from scratch.

---

## 1. Prerequisites

1. **Linux VPS:**
   - Operating System: Ubuntu 22.04/24.04 LTS or Debian 12
   - Open Inbound Ports: `80` (HTTP for Let's Encrypt), `443` (HTTPS/WSS), `22` (SSH)
   - DNS: A public domain pointing to your VPS IP (e.g. `relay.example.com`)

2. **Android Phone:**
   - Android 13 (API 33) or Android 14 (API 34)+
   - Sideloading permissions enabled (Developer Options or "Install unknown apps")

3. **Mac Client:**
   - macOS 14.0 (Sonoma) or macOS 15.0+ (Sequoia)
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
# Edit vps/deploy/Caddyfile with your domain and email:
# replace relay.phonelink.local with relay.example.com
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

## 4. Installing the Android App

On your Android phone:

```bash
# 1. Build the signed release APK on your dev machine:
./android/scripts/build_release_apk.sh

# 2. Transfer and install onto phone:
adb install -r android/release/PhoneLink-v1.0.0-release.apk

# 3. Launch "PhoneLink" from the app drawer.
```

---

## 5. First-Time Pairing Ceremony

The pairing ceremony establishes mutual trust and cryptographic identity:

### Step 1: Generate Pairing Token on Mac
In your Mac terminal:
```bash
phonelink pair --relay https://relay.example.com
```
**Output:**
```
PhoneLink Pairing Ceremony
==========================
Device ID: 4c34b040a6b986b2457c79e6027aeb8ec2c18ab9d01fc87a
Relay URL: https://relay.example.com

Pairing Token: 849201
Expiration: 10 minutes

Enter this 6-digit code into your Android PhoneLink app.
Listening for Android claimant...
```

### Step 2: Claim Pairing on Android
1. Open the **PhoneLink** app on your phone.
2. Enter the Relay URL: `https://relay.example.com`
3. Enter the 6-digit pairing code: `849201`
4. Tap **Connect & Pair**.
5. Grant required Android permissions:
   - **Notification Permission:** (Required on Android 13+ to display the ongoing connection status).
   - **Battery Optimization:** (Tap "Allow" so the connection persists when phone screen is off).

### Step 3: Confirmation
On your Mac terminal:
```
[SUCCESS] Android phone paired successfully!
Paired Device: a8f09d...17c
Session Key Established via ECDH.
End-to-End Encrypted Tunnel ACTIVE.
```

---

## 6. Verifying Connection Health

Check connection status from Mac:
```bash
phonelink status
```
**Output:**
```
PhoneLink Status
================
Relay:        https://relay.example.com (Connected, TLS 1.3)
Local Mac:    4c34b0...d787
Paired Phone: 7d3c39...7d4e
State:        ONLINE (Ping RTT: 42ms)
Battery:      87% (Charging)
Storage:      128.4 GB free
```
You are now ready to explore file transfers, remote camera viewing, and scoped actions!
