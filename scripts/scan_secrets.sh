#!/usr/bin/env bash
# PhoneLink Automated Secret & Credential Scanner
# Scans working directory and tracked git files for private keys, keystores, tokens, and hardcoded passwords.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Running PhoneLink Automated Secret Scanner ==="

FAILURES=0

check_pattern() {
    local desc="$1"
    local pattern="$2"
    echo -n "Scanning for $desc... "
    local matches
    matches=$(cd "$REPO_ROOT" && git grep -i -I -E --untracked -e "$pattern" -- ':(exclude)*.png' ':(exclude)*.svg' ':(exclude)*.desc' ':(exclude)*.bin' ':(exclude)scripts/scan_secrets.sh' || true)

    if [ -n "$matches" ]; then
        echo "FAILED!"
        echo "$matches"
        FAILURES=$((FAILURES + 1))
    else
        echo "CLEAN"
    fi
}

check_tracked_keyfiles() {
    echo -n "Scanning for tracked or untracked keystores and private key files... "
    local keyfiles
    keyfiles=$(cd "$REPO_ROOT" && git ls-files --cached --others --exclude-standard '*.keystore' '*.jks' '*.p12' '*.pfx' '*.pem' '*.key' || true)
    if [ -n "$keyfiles" ]; then
        echo "FAILED!"
        echo "$keyfiles"
        FAILURES=$((FAILURES + 1))
    else
        echo "CLEAN"
    fi
}

check_tracked_keyfiles
check_pattern "Private Key PEM Headers" "-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
check_pattern "Hardcoded AWS / Cloud Secrets" "(AKIA[0-9A-Z]{16}|aws_secret_access_key)"
check_pattern "Hardcoded Slack / GitHub Tokens" "(ghp_[a-zA-Z0-9]{36}|xoxb-[0-9]{11})"
check_pattern "Hardcoded Passwords or Fallback Secrets in Code" "(password|passphrase|key_?password|store_?password)\s*([:=]|\?:)\s*[\"'][^\"']{8,}[\"']"

echo "--------------------------------------------------"
if [ $FAILURES -eq 0 ]; then
    echo "PASS: Zero secrets or private keys detected in repository."
    exit 0
else
    echo "FAIL: $FAILURES potential secret violation(s) found!"
    exit 1
fi
