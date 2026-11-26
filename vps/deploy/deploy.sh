#!/usr/bin/env bash
# PhoneLink VPS Relay Deployment & Verification Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPS_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== PhoneLink VPS Relay Deployment ==="

# 1. Check Go environment
if command -v go >/dev/null 2>&1; then
    echo "Found local Go: $(go version)"
    echo "Running unit tests..."
    (cd "$VPS_DIR" && go test -v ./...)
    echo "Building binary..."
    (cd "$VPS_DIR" && go build -o bin/phonelink-relay ./cmd/relay)
    echo "PASS: Local Go build succeeded: bin/phonelink-relay"
else
    echo "Go not installed locally. Checking Docker..."
fi

# 2. Check Docker environment
if command -v docker >/dev/null 2>&1; then
    echo "Found Docker: $(docker --version)"
    APK_SRC="$VPS_DIR/../android/release/PhoneLink-v1.0.0-release.apk"
    STAGED_APK=0
    if [ -f "$APK_SRC" ] && [ ! -f "$VPS_DIR/PhoneLink.apk" ]; then
        cp "$APK_SRC" "$VPS_DIR/PhoneLink.apk"
        STAGED_APK=1
    fi
    echo "Building Docker container..."
    docker build -t phonelink-relay -f "$SCRIPT_DIR/Dockerfile" "$VPS_DIR"
    if [ "$STAGED_APK" -eq 1 ]; then
        rm -f "$VPS_DIR/PhoneLink.apk"
    fi
    echo "PASS: Docker container build succeeded."
else
    echo "Docker not found; skipping container build."
fi

echo "=== Deployment Skeleton Ready ==="
