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

# 2. Secret & Credential Scanning
run_step "Automated Secret & Key Scanning" \
    "$REPO_ROOT/scripts/scan_secrets.sh"

# 3. Mac Client Unit Tests
run_step "Mac Client (Swift) Tests" \
    "cd $REPO_ROOT/mac && swift build && swift run PhoneLinkTests"

# 3. VPS Relay Unit Tests
run_step "VPS Relay (Go) Tests" \
    "cd $REPO_ROOT/vps && /opt/homebrew/bin/go test -v ./..."

# 4. Android Unit Tests
run_step "Android Client (Gradle) Tests" \
    "cd $REPO_ROOT/android && ./gradlew testDebugUnitTest"

# 5. INT-1 End-to-End Relay Integration Tests
run_step "INT-1 End-to-End Encrypted Relay Integration Test" \
    "$REPO_ROOT/tests/test_int1_e2e.sh"

# 6. INT-2 Device Discovery & Status Reporting Integration Tests
run_step "INT-2 Device Discovery & Status Reporting Test" \
    "$REPO_ROOT/tests/test_int2_status.sh"

# 7. FILE-2 Remote File Listing Integration Tests
run_step "FILE-2 Remote File Listing Test" \
    "$REPO_ROOT/tests/test_file2_ls.sh"

# 8. FILE-3 Secure File Download Integration Tests
run_step "FILE-3 Secure File Download Test" \
    "$REPO_ROOT/tests/test_file3_download.sh"

# 9. FILE-4 Secure File Upload Integration Tests
run_step "FILE-4 Secure File Upload Test" \
    "$REPO_ROOT/tests/test_file4_upload.sh"

# 10. FILE-5 Scoped Remote Action System Integration Tests
run_step "FILE-5 Scoped Remote Action System Test" \
    "$REPO_ROOT/tests/test_file5_actions.sh"

# 11. CAM-2 Android Camera Capture Module Integration Tests
run_step "CAM-2 Android Camera Capture Module Test" \
    "$REPO_ROOT/tests/test_cam2_camera.sh"

# 12. CAM-3 Camera Frame Streaming Protocol Integration Tests
run_step "CAM-3 Camera Frame Streaming Protocol Test" \
    "$REPO_ROOT/tests/test_cam3_streaming.sh"

# 13. CAM-4 Mac Camera Viewer Client Integration Tests
run_step "CAM-4 Mac Camera Viewer Client Test" \
    "$REPO_ROOT/tests/test_cam4_viewer.sh"

# 14. SEC-1 Cross-Component Security Hardening Integration Tests
run_step "SEC-1 Cross-Component Security Hardening Test" \
    "$REPO_ROOT/tests/test_sec1_hardening.sh"

# 15. TEST-2 Cross-Component Integration Test Suite
run_step "TEST-2 Cross-Component Integration Suite (2x & Regression Check)" \
    "$REPO_ROOT/tests/test_test2_cross_component.sh"

# 16. VPS-7 VPS Logging & Monitoring Integration Tests
run_step "VPS-7 VPS Logging & Monitoring Test" \
    "$REPO_ROOT/tests/test_vps7_logging.sh"

# 17. SEC-2 Security Validation & Penetration Testing Suite
run_step "SEC-2 Security Validation & Penetration Testing Suite" \
    "$REPO_ROOT/tests/test_sec2_pentest.sh"

# 18. VPS-6 VPS Session Resumption & Reconnection
run_step "VPS-6 VPS Session Resumption & Reconnection" \
    "$REPO_ROOT/tests/test_vps6_resumption.sh"

# 19. AND-8 Android Reconnection & Network-Change Handling
run_step "AND-8 Android Reconnection & Network-Change Handling" \
    "$REPO_ROOT/tests/test_and8_reconnection.sh"

# 20. INT-3 End-to-End Connection Recovery
run_step "INT-3 End-to-End Connection Recovery" \
    "$REPO_ROOT/tests/test_int3_recovery.sh"

echo "=========================================================="
if [ $FAILURES -eq 0 ]; then
    echo "   ALL REGRESSION SUITES PASSED (20/20)"
    echo "=========================================================="
    exit 0
else
    echo "   SUITE FAILED WITH $FAILURES FAILURE(S)"
    echo "=========================================================="
    exit 1
fi
