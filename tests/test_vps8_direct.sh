#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - VPS-8 VPS Direct-Connection Optimization Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: VPS-8 Direct-Connection Optimization Suite"
echo "=========================================================="

cd "${PROJECT_ROOT}/vps"

echo "[1/1] Running direct connection & seamless fallback tests..."
go test -v -run TestVPS8 ./test/integration

echo "=========================================================="
echo "VPS-8 Direct Connection & Seamless Fallback: ALL PASSED"
echo "=========================================================="
