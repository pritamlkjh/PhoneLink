#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - TEST-3 Network Failure & Chaos Testing Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: TEST-3 Network Failure & Chaos Test Suite"
echo "=========================================================="

cd "${PROJECT_ROOT}/vps"

echo "[1/1] Running comprehensive network chaos scenarios in Go..."
go test -v -run TestTEST3 ./test/integration

echo "=========================================================="
echo "TEST-3 Network Failure & Chaos Tests: ALL 6 SCENARIOS PASSED"
echo "=========================================================="
