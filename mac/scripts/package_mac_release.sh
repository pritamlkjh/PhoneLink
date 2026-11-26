#!/usr/bin/env bash
# PhoneLink - Mac Client Release Packaging Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$MAC_DIR")"
RELEASE_DIR="$MAC_DIR/release"
PACKAGE_NAME="PhoneLink-v1.0.0-macos-arm64"
DIST_DIR="$RELEASE_DIR/$PACKAGE_NAME"

echo "=========================================================="
echo "PhoneLink: Mac Client Release Packaging"
echo "=========================================================="

cd "$MAC_DIR"

# 1. Build release binary
echo "[1/5] Compiling release binary with SwiftPM..."
swift build -c release

RELEASE_BIN="$MAC_DIR/.build/release/phonelink"
if [ ! -f "$RELEASE_BIN" ]; then
    # In some SwiftPM configs, it might be in .build/arm64-apple-macosx/release/phonelink
    RELEASE_BIN=$(find "$MAC_DIR/.build" -type f -name "phonelink" -perm +111 | grep -v "PhoneLinkCLI" | head -n 1)
fi

if [ -z "$RELEASE_BIN" ] || [ ! -f "$RELEASE_BIN" ]; then
    echo "ERROR: Compiled release binary 'phonelink' not found."
    exit 1
fi

echo "  -> Found release binary: $RELEASE_BIN"

# 2. Apply hardened runtime code signature
echo "[2/5] Applying hardened runtime signature (ad-hoc / developer)..."
SIGNING_IDENTITY="${MAC_SIGNING_IDENTITY:--}"
codesign --force --options runtime --timestamp=none -s "$SIGNING_IDENTITY" "$RELEASE_BIN"
codesign -v "$RELEASE_BIN"
echo "  -> Signature verified successfully."

# 3. Create distribution bundle layout
echo "[3/5] Creating release distribution directory layout..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/bin"
mkdir -p "$DIST_DIR/docs"

cp "$RELEASE_BIN" "$DIST_DIR/bin/phonelink"
chmod +x "$DIST_DIR/bin/phonelink"

cat <<'EOF' > "$DIST_DIR/README.txt"
PhoneLink Mac Client (v1.0.0)
=============================

Quick Install:
1. Copy 'bin/phonelink' to a directory in your PATH (e.g. /usr/local/bin or ~/bin):
   sudo cp bin/phonelink /usr/local/bin/

2. Verify installation:
   phonelink --version

3. Pair with your Android phone:
   phonelink pair --vps https://<your-vps-domain>
   (Scan the QR code or enter the 8-character short code on your phone)

4. Inspect connected device:
   phonelink status --vps https://<your-vps-domain>
EOF

# 4. Create tarball archive
echo "[4/5] Generating distribution tarball archive..."
mkdir -p "$RELEASE_DIR"
cd "$RELEASE_DIR"
tar -czf "$PACKAGE_NAME.tar.gz" "$PACKAGE_NAME"

# 5. Generate SHA256 checksums
echo "[5/5] Generating SHA256 checksums..."
shasum -a 256 "$PACKAGE_NAME.tar.gz" > "$PACKAGE_NAME.tar.gz.sha256"

TAR_SIZE=$(ls -lh "$PACKAGE_NAME.tar.gz" | awk '{print $5}')
SHA256_HASH=$(cat "$PACKAGE_NAME.tar.gz.sha256" | awk '{print $1}')

echo "=========================================================="
echo "SUCCESS: Mac Release Package Created!"
echo "Archive: $RELEASE_DIR/$PACKAGE_NAME.tar.gz"
echo "Size: $TAR_SIZE"
echo "SHA256: $SHA256_HASH"
echo "=========================================================="
