#!/usr/bin/env bash
# PhoneLink Unified Regression Test Suite Runner
# Runs automated unit and contract tests across all 3 components + shared protocol.
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "   PHONELINK UNIFIED REGRESSION TEST SUITE"
echo "=========================================================="
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Repo Root: $REPO_ROOT"
echo ""

FAILURES=0

run_step() {
    local name="$1"
    local cmd="$2"
    echo "----------------------------------------------------------"
    echo ">> [STEP] $name"
    echo "----------------------------------------------------------"
    if eval "$cmd"; then
        echo ">> [SUCCESS] $name passed."
    else
        echo ">> [FAILURE] $name FAILED!"
        FAILURES=$((FAILURES + 1))
    fi
    echo ""
}

# 1. Shared Protocol Schemas
run_step "Shared Protobuf Schema Validation & Round-Trip" \
    "$REPO_ROOT/tests/test_schema_roundtrip.sh"

# 2. Mac Client Unit Tests
run_step "Mac Client (Swift) Tests" \
    "cd $REPO_ROOT/mac && swift build && swift run PhoneLinkTests"

# 3. VPS Relay Unit Tests
run_step "VPS Relay (Go) Tests" \
    "cd $REPO_ROOT/vps && /opt/homebrew/bin/go test -v ./..."

# 4. Android Unit Tests
run_step "Android Client (Gradle) Tests" \
    "cd $REPO_ROOT/android && ./gradlew testDebugUnitTest"

echo "=========================================================="
if [ $FAILURES -eq 0 ]; then
    echo "   ALL REGRESSION SUITES PASSED (4/4)"
    echo "=========================================================="
    exit 0
else
    echo "   SUITE FAILED WITH $FAILURES FAILURE(S)"
    echo "=========================================================="
    exit 1
fi
