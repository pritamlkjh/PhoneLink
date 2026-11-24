#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - REL-3 Mac Release Build & Packaging Test Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: REL-3 Mac Release Build & Packaging Suite"
echo "=========================================================="

echo "[1/4] Executing Mac client release packaging script..."
"$PROJECT_ROOT/mac/scripts/package_mac_release.sh"

RELEASE_DIR="$PROJECT_ROOT/mac/release"
PACKAGE_NAME="PhoneLink-v1.0.0-macos-arm64"
TARBALL="$RELEASE_DIR/$PACKAGE_NAME.tar.gz"
CHECKSUM="$RELEASE_DIR/$PACKAGE_NAME.tar.gz.sha256"

echo "[2/4] Verifying archive artifacts and SHA256 checksum..."
test -f "$TARBALL"
test -f "$CHECKSUM"

cd "$RELEASE_DIR"
shasum -a 256 -c "$PACKAGE_NAME.tar.gz.sha256"

echo "[3/4] Testing fresh extraction and clean install smoke test..."
TEMP_INSTALL_DIR="/tmp/phonelink_mac_install_test"
rm -rf "$TEMP_INSTALL_DIR"
mkdir -p "$TEMP_INSTALL_DIR"

tar -xzf "$TARBALL" -C "$TEMP_INSTALL_DIR"

INSTALLED_BIN="$TEMP_INSTALL_DIR/$PACKAGE_NAME/bin/phonelink"
test -x "$INSTALLED_BIN"

# Execute smoke commands
VERSION_OUTPUT=$("$INSTALLED_BIN" --version)
echo "  -> Installed binary output: $VERSION_OUTPUT"
if ! echo "$VERSION_OUTPUT" | grep -q "PhoneLink Mac Client"; then
    echo "ERROR: Version output did not match expected banner."
    exit 1
fi

echo "[4/4] Verifying code signature of extracted release binary..."
codesign -v "$INSTALLED_BIN"

rm -rf "$TEMP_INSTALL_DIR"

echo "=========================================================="
echo "REL-3 Mac Release Build & Packaging: ALL CHECKS PASSED"
echo "=========================================================="
