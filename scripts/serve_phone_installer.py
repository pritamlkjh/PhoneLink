#!/usr/bin/env python3
"""
PhoneLink 1-Tap Over-The-Air (OTA) Phone Installer

Serves the universal Android release APK (minSdk 26: Android 8.0 to 14+) over HTTP.
Prints a terminal QR code for instant camera scanning from any phone on local Wi-Fi,
and serves a mobile-friendly 1-tap download & install web page.
"""

import argparse
import http.server
import os
import socket
import socketserver
import sys
from pathlib import Path

# Embedded HTML landing page template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Install PhoneLink on Android</title>
    <style>
        :root {
            --primary: #1a73e8;
            --primary-dark: #1557b0;
            --bg: #f8f9fa;
            --card-bg: #ffffff;
            --text-main: #202124;
            --text-sub: #5f6368;
            --border: #dadce0;
            --success: #1e8e3e;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --primary: #8ab4f8;
                --primary-dark: #669df6;
                --bg: #121212;
                --card-bg: #1e1e1e;
                --text-main: #e8eaed;
                --text-sub: #9aa0a6;
                --border: #3c4043;
                --success: #81c995;
            }
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            width: 100%;
            max-width: 440px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px 24px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08);
            text-align: center;
        }
        .app-icon {
            font-size: 56px;
            margin-bottom: 12px;
            display: inline-block;
        }
        h1 {
            font-size: 24px;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 6px;
        }
        .subtitle {
            font-size: 14px;
            color: var(--text-sub);
            margin-bottom: 20px;
        }
        .badge {
            display: inline-block;
            background: rgba(26, 115, 232, 0.12);
            color: var(--primary);
            font-size: 12px;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 12px;
            margin-bottom: 24px;
        }
        .btn-install {
            display: block;
            width: 100%;
            background: var(--primary);
            color: #ffffff !important;
            text-decoration: none;
            font-size: 17px;
            font-weight: 600;
            padding: 16px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(26, 115, 232, 0.3);
            transition: all 0.2s ease;
            margin-bottom: 16px;
        }
        .btn-install:active {
            transform: scale(0.98);
            background: var(--primary-dark);
        }
        .meta-info {
            font-size: 12px;
            color: var(--text-sub);
            margin-bottom: 28px;
        }
        .steps-card {
            text-align: left;
            background: var(--bg);
            border-radius: 12px;
            padding: 16px 18px;
            margin-bottom: 20px;
        }
        .steps-title {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 12px;
            color: var(--text-main);
        }
        .step {
            display: flex;
            align-items: flex-start;
            margin-bottom: 12px;
            font-size: 13px;
            line-height: 1.4;
            color: var(--text-sub);
        }
        .step:last-child { margin-bottom: 0; }
        .step-num {
            background: var(--primary);
            color: #ffffff;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            margin-right: 10px;
            flex-shrink: 0;
            margin-top: 1px;
        }
        .step-text strong {
            color: var(--text-main);
        }
        .security-footer {
            font-size: 11px;
            color: var(--text-sub);
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="app-icon">📱</div>
        <h1>PhoneLink</h1>
        <div class="subtitle">Personal Authorized Remote Access</div>
        <div class="badge">Universal Build • Android 8.0 to 14+</div>

        <a href="/download/PhoneLink.apk" class="btn-install" id="installBtn">
            📥 Tap Here to Download &amp; Install
        </a>

        <div class="meta-info">
            Package: <strong>PhoneLink-v1.0.0.apk</strong> (~__APK_SIZE__)
        </div>

        <div class="steps-card">
            <div class="steps-title">🚀 3-Step Setup Guide:</div>
            <div class="step">
                <div class="step-num">1</div>
                <div class="step-text"><strong>Tap Download:</strong> Tap the blue button above. Chrome will download the installation package.</div>
            </div>
            <div class="step">
                <div class="step-num">2</div>
                <div class="step-text"><strong>Tap Open &amp; Install:</strong> If prompted <em>"File might be harmful"</em>, tap <strong>Download anyway</strong>, then tap <strong>Open</strong> &gt; <strong>Install</strong>.</div>
            </div>
            <div class="step">
                <div class="step-num">3</div>
                <div class="step-text"><strong>Pair with Mac:</strong> Open the app, enter the 8-character code shown by running <code>phonelink pair</code> on your Mac, and tap <strong>Connect &amp; Pair</strong>.</div>
            </div>
        </div>

        <div class="security-footer">
            🔒 <strong>Zero Plaintext Leakage:</strong> Protected by end-to-end ECDH + AES-256-GCM encryption. Built exclusively for your personal devices.
        </div>
    </div>
</body>
</html>
"""


def detect_lan_ip():
    """Detects primary local network IP address, including offline LAN setups."""
    for target in (("10.255.255.255", 1), ("192.168.1.1", 80), ("8.8.8.8", 80)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(target)
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
        finally:
            s.close()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "127.0.0.1"


def render_ascii_qr(url):
    """Renders ANSI / ASCII QR code for terminal scanning."""
    try:
        import cv2
        import numpy as np
        enc = cv2.QRCodeEncoder.create()
        mat = enc.encode(url)
        if mat is not None:
            pad = 2
            h, w = mat.shape
            padded = np.zeros((h + 2 * pad, w + 2 * pad), dtype=np.uint8)
            padded[pad:pad + h, pad:pad + w] = mat

            lines = []
            total_h, total_w = padded.shape
            for y in range(0, total_h, 2):
                row = ""
                for x in range(total_w):
                    top_dark = (padded[y, x] != 0)
                    bot_dark = (padded[y + 1, x] != 0) if (y + 1 < total_h) else False

                    fg = "30" if top_dark else "37"
                    bg = "40" if bot_dark else "47"
                    row += f"\033[{fg};{bg}m▀\033[0m"
                lines.append(row)
            return "\n".join(lines)
    except Exception:
        pass

    # Fallback to standard block representation if qrcode/cv2 is unavailable
    return None


def find_release_apk(base_dir):
    """Finds the release APK file in the repository."""
    candidates = [
        base_dir / "android" / "release" / "PhoneLink-v1.0.0-release.apk",
        base_dir / "android" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk",
        base_dir / "PhoneLink.apk",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


class PhoneInstallerHandler(http.server.BaseHTTPRequestHandler):
    apk_path = None
    apk_size_str = "2.1 MB"

    def _send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'")

    def do_HEAD(self):
        route = self.path.split("?", 1)[0]
        if route in ("/", "/install", "/install/"):
            content = HTML_TEMPLATE.replace("__APK_SIZE__", self.apk_size_str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self._send_security_headers()
            self.end_headers()
            return
        if route.startswith("/download/") or route.endswith(".apk"):
            if not self.apk_path or not self.apk_path.exists():
                self.send_error(404, "APK file not found.")
                return
            file_size = self.apk_path.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Disposition", 'attachment; filename="PhoneLink.apk"')
            self.send_header("Content-Length", str(file_size))
            self.send_header("Cache-Control", "no-cache")
            self._send_security_headers()
            self.end_headers()
            return
        self.send_error(404, "Not Found")

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route in ("/", "/install", "/install/"):
            content = HTML_TEMPLATE.replace("__APK_SIZE__", self.apk_size_str).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(content)
            return

        if route.startswith("/download/") or route.endswith(".apk"):
            if not self.apk_path or not self.apk_path.exists():
                self.send_error(404, "APK file not found. Please build the APK first with ./android/scripts/build_release_apk.sh")
                return

            headers_sent = False
            try:
                file_size = self.apk_path.stat().st_size
                self.send_response(200)
                # Android MIME type for package installer
                self.send_header("Content-Type", "application/vnd.android.package-archive")
                self.send_header("Content-Disposition", 'attachment; filename="PhoneLink.apk"')
                self.send_header("Content-Length", str(file_size))
                self.send_header("Cache-Control", "no-cache")
                self._send_security_headers()
                self.end_headers()
                headers_sent = True

                with open(self.apk_path, "rb") as f:
                    while chunk := f.read(64 * 1024):
                        self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                if not headers_sent:
                    self.send_error(500, f"Error streaming APK: {e}")
            return

        self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        # Format friendly log output
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")


def run_installer_server(host, port, apk_path):
    base_dir = Path(__file__).resolve().parent.parent
    if not apk_path:
        apk_path = find_release_apk(base_dir)

    if not apk_path or not apk_path.exists():
        print(f"Error: Release APK not found at {apk_path or 'default paths'}.", file=sys.stderr)
        print("Please build it first: ./android/scripts/build_release_apk.sh", file=sys.stderr)
        sys.exit(1)

    size_mb = apk_path.stat().st_size / (1024 * 1024)
    size_str = f"{size_mb:.1f} MB"
    PhoneInstallerHandler.apk_path = apk_path
    PhoneInstallerHandler.apk_size_str = size_str

    install_url = f"http://{host}:{port}/install"

    print("=" * 64)
    print("  📱 PhoneLink 1-Tap OTA Phone Installer")
    print("=" * 64)
    print(f"Serving APK: {apk_path.name} ({size_str})")
    print(f"Target:      Android 8.0 to 14+ (minSdk 26, targetSdk 34)")
    print(f"Install URL: {install_url}")
    print("-" * 64)

    qr_art = render_ascii_qr(install_url)
    if qr_art:
        print("Scan this QR code with your phone camera:")
        print(qr_art)
    else:
        print(f"Open this URL on your phone's browser:\n  {install_url}")

    print("-" * 64)
    print("Ready! Tap the link on your phone to download & install.")
    print("Press Ctrl+C to stop the server.")
    print("=" * 64)

    class ThreadingInstallerServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    with ThreadingInstallerServer(("0.0.0.0", port), PhoneInstallerHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down installer server.")


def main():
    parser = argparse.ArgumentParser(description="PhoneLink 1-Tap OTA Phone Installer")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port to listen on (default: 8080)")
    parser.add_argument("--ip", type=str, default=None, help="LAN IP address override")
    parser.add_argument("--apk", type=Path, default=None, help="Path to PhoneLink release APK")
    args = parser.parse_args()
    if args.port < 1 or args.port > 65535:
        parser.error(f"invalid --port {args.port} (must be 1..65535)")

    host = args.ip or detect_lan_ip()
    run_installer_server(host, args.port, args.apk)


if __name__ == "__main__":
    main()
