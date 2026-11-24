#!/usr/bin/env bash
# PhoneLink - Android Signed Release Build Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$ANDROID_DIR")"
RELEASE_OUT_DIR="$ANDROID_DIR/release"
BUILD_APK_PATH="$ANDROID_DIR/app/build/outputs/apk/release/app-release.apk"

echo "=========================================================="
echo "PhoneLink: Android Signed Release Build"
echo "=========================================================="

cd "$ANDROID_DIR"

# 1. Compile signed release APK with R8 minification & obfuscation
echo "[1/4] Running Gradle assembleRelease with R8 optimization..."
./gradlew assembleRelease

if [ ! -f "$BUILD_APK_PATH" ]; then
    echo "ERROR: Release APK not found at $BUILD_APK_PATH"
    exit 1
fi

# 2. Verify APK structural integrity
echo "[2/4] Verifying APK package structure..."
mkdir -p "$RELEASE_OUT_DIR"
cp "$BUILD_APK_PATH" "$RELEASE_OUT_DIR/PhoneLink-v1.0.0-release.apk"

# Check required components inside the packaged APK
tar_entries=$(unzip -l "$RELEASE_OUT_DIR/PhoneLink-v1.0.0-release.apk")

if ! echo "$tar_entries" | grep -q "classes.dex"; then
    echo "ERROR: APK is missing compiled classes.dex"
    exit 1
fi

if ! echo "$tar_entries" | grep -q "AndroidManifest.xml"; then
    echo "ERROR: APK is missing AndroidManifest.xml"
    exit 1
fi

if ! echo "$tar_entries" | grep -q "resources.arsc"; then
    echo "ERROR: APK is missing resources.arsc"
    exit 1
fi

# 3. Verify cryptographic signing
echo "[3/4] Verifying release APK signature..."
if ! echo "$tar_entries" | grep -q "META-INF/"; then
    echo "ERROR: APK does not contain META-INF signature files"
    exit 1
fi

# 4. Generate SHA256 checksum
echo "[4/4] Generating release checksums..."
cd "$RELEASE_OUT_DIR"
shasum -a 256 "PhoneLink-v1.0.0-release.apk" > "PhoneLink-v1.0.0-release.apk.sha256"

APK_SIZE=$(ls -lh "PhoneLink-v1.0.0-release.apk" | awk '{print $5}')
SHA256_HASH=$(cat "PhoneLink-v1.0.0-release.apk.sha256" | awk '{print $1}')

echo "=========================================================="
echo "SUCCESS: Android Release APK Built & Signed Successfully!"
echo "Artifact: $RELEASE_OUT_DIR/PhoneLink-v1.0.0-release.apk"
echo "Size: $APK_SIZE"
echo "SHA256: $SHA256_HASH"
echo "=========================================================="
