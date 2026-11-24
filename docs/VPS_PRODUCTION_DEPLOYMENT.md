# PhoneLink - VPS Production Deployment & Rollback Runbook (`REL-1`)

**Document Version:** 1.0.0  
**Target Architecture:** Linux x86_64 / arm64 (Ubuntu 22.04 / 24.04 LTS or Debian 12)  
**Security Profile:** Minimal Attack Surface, Unprivileged Process, No Inbound SSH needed for client sync

---

## 1. Overview & Architecture

The PhoneLink VPS Relay is designed to operate on a low-trust public Linux server. It acts purely as a stateless coordinator and encrypted frame broker:
- **Zero Plaintext Access:** Payload ciphertext is end-to-end encrypted with keys known only to the Android phone and Mac.
- **Minimal Storage:** Zero camera frames or file bytes are ever written to disk. The audit logger records structured operational logs only.
- **Hardened Systemd Unit:** Runs under a dedicated unprivileged user `phonelink` with `ProtectSystem=strict`, `NoNewPrivileges=true`, and `MemoryDenyWriteExecute=true`.
- **Automatic TLS:** Caddy reverse proxy terminates external HTTPS/WSS with automated Let's Encrypt certificates.

---

## 2. Directory Layout & User Setup

On the production server:

```bash
# 1. Create dedicated system user
sudo useradd -r -s /usr/sbin/nologin -d /opt/phonelink phonelink

# 2. Setup directory hierarchy
sudo mkdir -p /opt/phonelink/relay/bin
sudo mkdir -p /opt/phonelink/relay/config
sudo mkdir -p /var/log/phonelink
sudo mkdir -p /var/log/caddy

sudo chown -R phonelink:phonelink /opt/phonelink /var/log/phonelink
sudo chmod 750 /opt/phonelink /var/log/phonelink
```

---

## 3. Production Deployment Procedure

Deploying a new release uses the automated atomic deployment script:

```bash
# Run atomic deployment
./vps/deploy/deploy_prod.sh /opt/phonelink/relay/bin
```

### What `deploy_prod.sh` executes:
1. **Pre-flight Testing:** Runs all Go unit tests before compiling.
2. **Hardened Compilation:** Compiles with `-ldflags="-w -s"` stripping all symbols and debugging data.
3. **Atomic Swap & Backup:**
   - Previous working binary copied to `phonelink-relay.prev`.
   - New binary moved into place (`phonelink-relay`).
4. **Smoke / Health Check:** Probes `http://127.0.0.1:8443/healthz` to confirm operational health.
5. **Auto-Rollback on Failure:** If `/healthz` fails to return `{"status":"ok"}`, the script automatically rolls back to `phonelink-relay.prev`.

---

## 4. Systemd Service Configuration

Install the hardened systemd unit:

```bash
sudo cp vps/deploy/phonelink-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable phonelink-relay
sudo systemctl start phonelink-relay
```

### Checking Daemon Status & Logs
```bash
sudo systemctl status phonelink-relay
journalctl -u phonelink-relay -f -o json
```

---

## 5. Reverse Proxy Configuration (Caddy)

Caddy provides automatic zero-touch TLS certificates:

```bash
sudo cp vps/deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl restart caddy
```

Verify TLS endpoint:
```bash
curl -i https://relay.yourdomain.com/healthz
# Expected: HTTP/2 200 OK
# {"status":"ok","version":"1.0.0"}
```

---

## 6. Rollback Drill & Emergency Procedure

In the event of an operational regression, unhandled panic, or corrupted update:

### Option A: Automated Rollback Script
```bash
/opt/phonelink/relay/bin/rollback_prod.sh /opt/phonelink/relay/bin
sudo systemctl restart phonelink-relay
```

### Option B: Manual Rollback
```bash
cd /opt/phonelink/relay/bin
sudo cp phonelink-relay.prev phonelink-relay
sudo systemctl restart phonelink-relay
curl http://127.0.0.1:8443/healthz
```

---

## 7. Monitoring & Operational Health

- **Health Endpoint:** `GET /healthz` -> returns `200 OK`
- **Metrics Endpoint:** `GET /metrics` -> returns active sessions, relayed frame count, latency histograms
- **Audit Logging:** Structured JSON emitted to `journald` and `/var/log/phonelink/relay.log`
