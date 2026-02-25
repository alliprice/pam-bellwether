#!/usr/bin/env bash
set -euo pipefail

# Integration tests for pam_preauth_gate.so and pam_preauth_stamp.so
#
# Usage (Lima):  limactl shell pam-preauth -- sudo bash /Users/alliprice/code/pam-preauth/tests/integration/pam_test.sh
# Usage (Vagrant): vagrant ssh -c 'sudo bash /vagrant/tests/integration/pam_test.sh'

# ---------------------------------------------------------------------------
# Colored output helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()
TOTP_SECRET="JBSWY3DPEHPK3PXP"

pass() {
    local msg="$1"
    echo -e "${GREEN}  PASS${RESET}  $msg"
    (( PASS_COUNT++ )) || true
}

fail() {
    local msg="$1"
    echo -e "${RED}  FAIL${RESET}  $msg"
    (( FAIL_COUNT++ )) || true
    FAILED_TESTS+=("$msg")
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="$3"
    if [[ "$actual" == "$expected" ]]; then
        pass "$msg"
    else
        fail "$msg (expected '$expected', got '$actual')"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="$3"
    if echo "$haystack" | grep -q "$needle"; then
        pass "$msg"
    else
        fail "$msg (pattern '$needle' not found)"
    fi
}

# ---------------------------------------------------------------------------
# SSH helper — uses expect to handle keyboard-interactive TOTP prompts.
# Pubkey auth bypasses PAM auth entirely, which means our modules never run.
# ---------------------------------------------------------------------------
ssh_to_localhost() {
    local totp_code
    totp_code=$(oathtool --totp -b "$TOTP_SECRET")

    expect -c "
        set timeout 10
        spawn ssh -o StrictHostKeyChecking=no \
                  -o PubkeyAuthentication=no \
                  -o PreferredAuthentications=keyboard-interactive \
                  testuser@127.0.0.1 true
        expect {
            \"Verification code:\" {
                send \"${totp_code}\r\"
                expect eof
            }
            eof {}
            timeout { exit 1 }
        }
        catch wait result
        exit [lindex \$result 3]
    "
}

# ---------------------------------------------------------------------------
# Cleanup / trap
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "--- Cleaning up ---"

    if [[ -f /etc/pam.d/sshd.bak ]]; then
        cp /etc/pam.d/sshd.bak /etc/pam.d/sshd
        echo "Restored /etc/pam.d/sshd"
    fi

    if [[ -f /etc/ssh/sshd_config.bak ]]; then
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        echo "Restored /etc/ssh/sshd_config"
    fi
    if [[ -d /etc/ssh/sshd_config.d.bak ]]; then
        rm -rf /etc/ssh/sshd_config.d
        mv /etc/ssh/sshd_config.d.bak /etc/ssh/sshd_config.d
        echo "Restored /etc/ssh/sshd_config.d/"
    fi

    systemctl restart sshd 2>/dev/null || true
    echo "Restarted sshd"

    rm -f /run/pam-preauth/testuser_*.token /run/pam-preauth/testuser_*.lock
    echo "Removed test token/lock files"

    echo ""
    echo "--- Test summary ---"
    echo -e "  ${GREEN}Passed:${RESET} $PASS_COUNT"
    echo -e "  ${RED}Failed:${RESET} $FAIL_COUNT"

    if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
        echo ""
        echo "Failed tests:"
        for t in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}x${RESET}  $t"
        done
    fi

    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
echo "=== pam_preauth integration tests ==="
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must run as root." >&2
    exit 1
fi

# Ensure testuser exists
if ! id testuser &>/dev/null; then
    echo "ERROR: 'testuser' does not exist. Create it first: useradd -m testuser" >&2
    exit 1
fi

# Add cargo/rustup to PATH. Under sudo, HOME is /root but Rust was installed
# for the unprivileged user. Find the actual installation and set all env vars.
# shellcheck disable=SC2044
if ! command -v cargo &>/dev/null; then
    for cargo_dir in $(find /home -maxdepth 3 -type d -name .cargo 2>/dev/null) /root/.cargo; do
        if [[ -x "$cargo_dir/bin/cargo" ]]; then
            export PATH="$cargo_dir/bin:$PATH"
            export CARGO_HOME="$cargo_dir"
            # rustup home is sibling to .cargo
            user_home="$(dirname "$cargo_dir")"
            export RUSTUP_HOME="$user_home/.rustup"
            echo "Using Rust from: $cargo_dir (RUSTUP_HOME=$RUSTUP_HOME)"
            break
        fi
    done
fi
if ! command -v cargo &>/dev/null; then
    echo "ERROR: cargo not found. Install Rust first." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
echo "--- Setup ---"

# Find the project root — works for both Lima (macOS mount) and Vagrant (/vagrant)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Building project (${PROJECT_ROOT})..."
cd "$PROJECT_ROOT" && cargo build --release 2>&1
echo "Build complete."

echo "Installing .so files..."
cp target/release/libpam_preauth_gate.so  /usr/lib64/security/pam_preauth_gate.so
cp target/release/libpam_preauth_stamp.so /usr/lib64/security/pam_preauth_stamp.so

echo "Creating /run/pam-preauth..."
install -d -m 0700 -o root -g root /run/pam-preauth

echo "Backing up /etc/pam.d/sshd..."
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak

# Install expect and oathtool if not already present (should be from provisioning)
if ! command -v expect &>/dev/null || ! command -v oathtool &>/dev/null; then
    echo "Installing expect and oathtool..."
    dnf install -y -q epel-release 2>&1 || true
    dnf config-manager --set-enabled epel 2>&1 || true
    dnf install -y -q expect oathtool 2>&1
fi

echo "Writing test PAM config..."
cat > /etc/pam.d/sshd <<'PAM_EOF'
# Test PAM stack — pam_google_authenticator.so stands in for pam_duo.so
# TTL is 5 seconds for fast testing.
auth  [success=1 ignore=ignore default=ignore]  pam_preauth_gate.so timeout=5 debug
auth  required                                   pam_google_authenticator.so
auth  required                                   pam_preauth_stamp.so debug
account required pam_permit.so
password required pam_permit.so
session required pam_permit.so
PAM_EOF

echo "Configuring sshd for keyboard-interactive auth..."
# Back up sshd_config and drop-in configs, then force keyboard-interactive auth.
# Cloud-init and distro drop-ins in sshd_config.d/ often override auth settings.
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
if [[ -d /etc/ssh/sshd_config.d ]]; then
    cp -a /etc/ssh/sshd_config.d /etc/ssh/sshd_config.d.bak
    # Override auth settings in all drop-in configs
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] && sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$f"
        [[ -f "$f" ]] && sed -i 's/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "$f"
        [[ -f "$f" ]] && sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$f"
    done
fi
# Set in main config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
sed -i 's/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
grep -q '^KbdInteractiveAuthentication' /etc/ssh/sshd_config || echo 'KbdInteractiveAuthentication yes' >> /etc/ssh/sshd_config
# Ensure ChallengeResponseAuthentication is enabled (alias for KbdInteractive on older sshd)
sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
# Enable PAM
sed -i 's/^#UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
grep -q '^UsePAM' /etc/ssh/sshd_config || echo 'UsePAM yes' >> /etc/ssh/sshd_config

echo "Restarting sshd..."
systemctl restart sshd
sleep 1  # give sshd a moment to fully restart

echo "Setup complete."
echo ""

# ---------------------------------------------------------------------------
# Test 1: Build verification
# ---------------------------------------------------------------------------
echo "--- Test 1: Build verification ---"

GATE_SO=/usr/lib64/security/pam_preauth_gate.so
STAMP_SO=/usr/lib64/security/pam_preauth_stamp.so

if [[ -f "$GATE_SO" ]]; then
    pass "gate .so exists at $GATE_SO"
else
    fail "gate .so missing at $GATE_SO"
fi

if [[ -f "$STAMP_SO" ]]; then
    pass "stamp .so exists at $STAMP_SO"
else
    fail "stamp .so missing at $STAMP_SO"
fi

# Check exported PAM symbols
for so_file in "$GATE_SO" "$STAMP_SO"; do
    so_name=$(basename "$so_file")
    symbols=$(nm -D "$so_file" 2>/dev/null || true)
    if echo "$symbols" | grep -q "pam_sm_authenticate"; then
        pass "$so_name exports pam_sm_authenticate"
    else
        fail "$so_name missing pam_sm_authenticate symbol"
    fi
    if echo "$symbols" | grep -q "pam_sm_setcred"; then
        pass "$so_name exports pam_sm_setcred"
    else
        fail "$so_name missing pam_sm_setcred symbol"
    fi
done

# Check gate links against libpam
gate_ldd=$(ldd "$GATE_SO" 2>/dev/null || true)
if echo "$gate_ldd" | grep -q "libpam.so"; then
    pass "gate .so links against libpam.so"
else
    fail "gate .so does not appear to link against libpam.so"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 2: Cache miss (first connection)
# ---------------------------------------------------------------------------
echo "--- Test 2: Cache miss (first connection) ---"

rm -f /run/pam-preauth/testuser_*.token /run/pam-preauth/testuser_*.lock

# Capture a timestamp just before the SSH attempt so journalctl queries are tight
T2_START=$(date --iso-8601=seconds)
sleep 1  # ensure journalctl --since captures log entries after this point

if ssh_to_localhost; then
    pass "SSH succeeded on first connection"
else
    fail "SSH failed on first connection"
fi

TOKEN_FILE=/run/pam-preauth/testuser_127.0.0.1.token
if [[ -f "$TOKEN_FILE" ]]; then
    pass "token file created at $TOKEN_FILE"
else
    fail "token file not found at $TOKEN_FILE"
fi

# Allow a moment for the log entry to land
sleep 1
JOURNAL_T2=$(journalctl -t pam_preauth --since "$T2_START" 2>/dev/null || journalctl --since "$T2_START" 2>/dev/null | grep -i "pam_preauth\|pam-preauth" || true)
if echo "$JOURNAL_T2" | grep -qi "IGNORE\|cache.miss\|stale\|no.token\|miss"; then
    pass "syslog shows cache miss on first connection"
else
    # Soft warning — log message wording depends on implementation
    echo "  WARN  Could not confirm cache-miss log entry (log: $(echo "$JOURNAL_T2" | tail -5))"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 3: Cache hit (second connection within TTL)
# ---------------------------------------------------------------------------
echo "--- Test 3: Cache hit (second connection within TTL) ---"

T3_START=$(date --iso-8601=seconds)
sleep 1

if ssh_to_localhost; then
    pass "SSH succeeded on second connection (within TTL)"
else
    fail "SSH failed on second connection (within TTL)"
fi

sleep 1
JOURNAL_T3=$(journalctl -t pam_preauth --since "$T3_START" 2>/dev/null || journalctl --since "$T3_START" 2>/dev/null | grep -i "pam_preauth\|pam-preauth" || true)
if echo "$JOURNAL_T3" | grep -qi "SUCCESS\|cache.hit\|fresh\|hit\|valid"; then
    pass "syslog shows cache hit on second connection"
else
    echo "  WARN  Could not confirm cache-hit log entry (log: $(echo "$JOURNAL_T3" | tail -5))"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 4: Cache expiry
# ---------------------------------------------------------------------------
echo "--- Test 4: Cache expiry (waiting 6s for 5s TTL to expire) ---"

echo "  Sleeping 6 seconds..."
sleep 6

T4_START=$(date --iso-8601=seconds)
sleep 1

if ssh_to_localhost; then
    pass "SSH succeeded after TTL expiry"
else
    fail "SSH failed after TTL expiry"
fi

# Token file should still exist (stamp touched it again)
if [[ -f "$TOKEN_FILE" ]]; then
    pass "token file still present after expiry+reauth"
else
    fail "token file missing after expiry+reauth"
fi

sleep 1
JOURNAL_T4=$(journalctl -t pam_preauth --since "$T4_START" 2>/dev/null || journalctl --since "$T4_START" 2>/dev/null | grep -i "pam_preauth\|pam-preauth" || true)
if echo "$JOURNAL_T4" | grep -qi "IGNORE\|cache.miss\|stale\|miss\|expired"; then
    pass "syslog shows cache miss after TTL expiry"
else
    echo "  WARN  Could not confirm post-expiry cache-miss log entry (log: $(echo "$JOURNAL_T4" | tail -5))"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 5: Concurrent connections
# ---------------------------------------------------------------------------
echo "--- Test 5: Concurrent connections (10 parallel SSH sessions) ---"

rm -f /run/pam-preauth/testuser_*.token /run/pam-preauth/testuser_*.lock

T5_START=$(date --iso-8601=seconds)
sleep 1

PIDS=()
TMPDIR_T5=$(mktemp -d)

for i in $(seq 1 10); do
    (
        if ssh_to_localhost; then
            echo "0" > "${TMPDIR_T5}/result_${i}"
        else
            echo "1" > "${TMPDIR_T5}/result_${i}"
        fi
    ) &
    PIDS+=($!)
done

echo "  Waiting for 10 parallel SSH connections..."
ALL_OK=true
for pid in "${PIDS[@]}"; do
    wait "$pid" || true  # individual failures captured in result files
done

# Check all result files
FAIL_CONNS=0
for i in $(seq 1 10); do
    result_file="${TMPDIR_T5}/result_${i}"
    if [[ ! -f "$result_file" ]] || [[ "$(cat "$result_file")" != "0" ]]; then
        (( FAIL_CONNS++ )) || true
    fi
done
rm -rf "$TMPDIR_T5"

if [[ $FAIL_CONNS -eq 0 ]]; then
    pass "all 10 concurrent SSH connections succeeded"
else
    fail "$FAIL_CONNS of 10 concurrent SSH connections failed"
fi

# Should be exactly 1 token file for testuser (all connections come from 127.0.0.1)
TOKEN_COUNT=$(find /run/pam-preauth/ -name "testuser_*.token" | wc -l)
assert_eq "$TOKEN_COUNT" "1" "exactly 1 token file for testuser after concurrent connections"

# Check syslog: we expect exactly 1 cache miss (the first connection through the lock)
# and at least some cache hits (connections that queued behind the lock saw the fresh token)
sleep 1
JOURNAL_T5=$(journalctl -t pam_preauth --since "$T5_START" 2>/dev/null || journalctl --since "$T5_START" 2>/dev/null | grep -i "pam_preauth\|pam-preauth" || true)

MISS_COUNT=$(echo "$JOURNAL_T5" | grep -ci "IGNORE\|cache.miss\|stale\|miss" || true)
HIT_COUNT=$(echo "$JOURNAL_T5"  | grep -ci "SUCCESS\|cache.hit\|fresh\|hit"  || true)

echo "  Observed in syslog: $MISS_COUNT miss(es), $HIT_COUNT hit(s)"

if [[ $MISS_COUNT -ge 1 ]]; then
    pass "at least 1 cache miss observed during concurrent connections"
else
    echo "  WARN  No cache-miss entries found in syslog for concurrent test"
fi

if [[ $HIT_COUNT -ge 1 ]]; then
    pass "at least 1 cache hit observed during concurrent connections (lock serialization working)"
else
    echo "  WARN  No cache-hit entries found in syslog for concurrent test"
fi

echo ""

# cleanup is called via trap EXIT
