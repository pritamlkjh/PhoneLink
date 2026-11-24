#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - TEST-4 Android Compatibility Matrix Testing Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: TEST-4 Android Compatibility Matrix Test Suite"
echo "=========================================================="

cd "${PROJECT_ROOT}/android"

echo "[1/1] Executing Android OEM & OS version compatibility matrix..."
./gradlew testDebugUnitTest --tests "com.phonelink.compatibility.AndroidCompatibilityMatrixTest"

echo "=========================================================="
echo "TEST-4 Android Compatibility Matrix: ALL FLOWS PASSED"
echo "=========================================================="
