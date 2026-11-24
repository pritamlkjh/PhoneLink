#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - REL-2 Android Release Build & Signing Test Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: REL-2 Android Release Build & Signing Suite"
echo "=========================================================="

echo "[1/3] Verifying release build configuration & ProGuard rules..."
test -f "$PROJECT_ROOT/android/app/proguard-rules.pro"
grep -q "com.phonelink.crypto" "$PROJECT_ROOT/android/app/proguard-rules.pro"
grep -q "com.phonelink.service" "$PROJECT_ROOT/android/app/proguard-rules.pro"
grep -q "signingConfigs" "$PROJECT_ROOT/android/app/build.gradle.kts"
grep -q "isMinifyEnabled = true" "$PROJECT_ROOT/android/app/build.gradle.kts"

echo "[2/3] Executing release build packaging script..."
"$PROJECT_ROOT/android/scripts/build_release_apk.sh"

echo "[3/3] Verifying release APK artifact & SHA256 integrity..."
test -f "$PROJECT_ROOT/android/release/PhoneLink-v1.0.0-release.apk"
test -f "$PROJECT_ROOT/android/release/PhoneLink-v1.0.0-release.apk.sha256"

cd "$PROJECT_ROOT/android/release"
shasum -a 256 -c "PhoneLink-v1.0.0-release.apk.sha256"

echo "=========================================================="
echo "REL-2 Android Release Build & Signing: ALL CHECKS PASSED"
echo "=========================================================="
