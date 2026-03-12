#!/usr/bin/env bash
set -euo pipefail

# Integration tests for pam_bellwether_gate.so and pam_bellwether_stamp.so
#
# Usage (Lima):  limactl shell pam-bellwether -- sudo bash /Users/alliprice/code/pam-preauth/tests/integration/pam_test.sh
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

    # Handle multiple "Verification code:" prompts — if the first code is
    # rejected (e.g., near a TOTP period boundary), generate a fresh code
    # for the retry. Uses the oathtool binary path to regenerate inside expect.
    local oathtool_path
    oathtool_path=$(command -v oathtool)

    expect -c "
        set timeout 15
        spawn ssh -o StrictHostKeyChecking=no \
                  -o PubkeyAuthentication=no \
                  -o PreferredAuthentications=keyboard-interactive \
                  testuser@127.0.0.1 true
        expect {
            \"Verification code:\" {
                send \"${totp_code}\r\"
                expect {
                    eof {}
                    \"Verification code:\" {
                        set code [exec ${oathtool_path} --totp -b ${TOTP_SECRET}]
                        send \"\$code\r\"
                        expect eof
                    }
                    timeout { exit 1 }
                }
            }
            eof {}
            timeout { exit 1 }
        }
        catch wait result
        exit [lindex \$result 3]
    "
}

# TOTP codes are valid for 30 seconds. If we're near a period boundary,
# the code may expire during the SSH handshake. Wait for a safe window.
wait_for_safe_totp_window() {
    local epoch_mod=$(( $(date +%s) % 30 ))
    if [[ $epoch_mod -gt 20 ]]; then
        local wait_time=$(( 31 - epoch_mod ))
        echo "  (waiting ${wait_time}s for safe TOTP window)"
        sleep "$wait_time"
    fi
}

# SSH with deliberately wrong TOTP codes — for testing failure paths.
# Uses exp_continue to handle any number of prompts (sshd may retry the
# full PAM stack up to MaxAuthTries times, each triggering new prompts).
ssh_to_localhost_fail() {
    expect -c "
        set timeout 30
        spawn ssh -o StrictHostKeyChecking=no \
                  -o PubkeyAuthentication=no \
                  -o PreferredAuthentications=keyboard-interactive \
                  testuser@127.0.0.1 true
        expect {
            \"Verification code:\" { send \"000000\r\"; exp_continue }
            eof {}
            timeout { exit 1 }
        }
        catch wait result
        exit [lindex \$result 3]
    "
}

# SSH session that captures all output to a file — for checking messages
# received by a follower connection during failure propagation.
# Handles unexpected prompts with wrong codes to prevent hanging if sshd
# retries auth (MaxAuthTries > 1) after failure propagation.
ssh_capture_output() {
    local output_file="$1"
    expect -c "
        set timeout 30
        spawn ssh -o StrictHostKeyChecking=no \
                  -o PubkeyAuthentication=no \
                  -o PreferredAuthentications=keyboard-interactive \
                  testuser@127.0.0.1 true
        expect {
            \"Verification code:\" { send \"000000\r\"; exp_continue }
            eof {}
            timeout {}
        }
        catch wait result
        exit [lindex \$result 3]
    " > "$output_file" 2>&1
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

    if [[ -f /home/testuser/.google_authenticator.bak ]]; then
        cp -p /home/testuser/.google_authenticator.bak /home/testuser/.google_authenticator
        rm -f /home/testuser/.google_authenticator.bak
        echo "Restored .google_authenticator"
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

    rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock
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
echo "=== pam_bellwether integration tests ==="
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
cp target/release/libpam_bellwether_gate.so  /usr/lib64/security/pam_bellwether_gate.so
cp target/release/libpam_bellwether_stamp.so /usr/lib64/security/pam_bellwether_stamp.so

echo "Creating /run/pam-bellwether..."
install -d -m 0700 -o root -g root /run/pam-bellwether

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
auth  [success=1 ignore=ignore auth_err=die default=ignore]  pam_bellwether_gate.so timeout=5 debug
auth  requisite                                  pam_google_authenticator.so
auth  required                                   pam_bellwether_stamp.so debug
account required pam_permit.so
password required pam_permit.so
session required pam_permit.so
PAM_EOF

# Disable DISALLOW_REUSE — pam_google_authenticator rejects reused TOTP codes
# within a 30-second window. Since multiple tests use fresh MFA challenges,
# they can collide within the same TOTP period. We're testing bellwether's
# cache/lock behavior, not pam_google_authenticator's replay protection.
echo "Disabling DISALLOW_REUSE for test reliability..."
cp -p /home/testuser/.google_authenticator /home/testuser/.google_authenticator.bak
sed -i '/" DISALLOW_REUSE/d' /home/testuser/.google_authenticator

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
# Limit auth retries — default 6 means up to 6 × (MFA + 2s penalty) per
# failed connection. MaxAuthTries 3 is enough to exercise retry-safety code
# in gate (anti-deadlock on sshd retry) without excessive test duration.
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config

echo "Restarting sshd..."
systemctl restart sshd
sleep 1  # give sshd a moment to fully restart

echo "Setup complete."
echo ""

# ---------------------------------------------------------------------------
# Test 1: Build verification
# ---------------------------------------------------------------------------
echo "--- Test 1: Build verification ---"

GATE_SO=/usr/lib64/security/pam_bellwether_gate.so
STAMP_SO=/usr/lib64/security/pam_bellwether_stamp.so

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
    if echo "$symbols" | grep -q "pam_sm_open_session"; then
        pass "$so_name exports pam_sm_open_session"
    else
        fail "$so_name missing pam_sm_open_session symbol"
    fi
    if echo "$symbols" | grep -q "pam_sm_close_session"; then
        pass "$so_name exports pam_sm_close_session"
    else
        fail "$so_name missing pam_sm_close_session symbol"
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

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

# Capture a timestamp just before the SSH attempt so journalctl queries are tight
T2_START=$(date --iso-8601=seconds)
sleep 1  # ensure journalctl --since captures log entries after this point

wait_for_safe_totp_window
if ssh_to_localhost; then
    pass "SSH succeeded on first connection"
else
    fail "SSH failed on first connection"
fi

TOKEN_FILE=/run/pam-bellwether/testuser_127.0.0.1.token
if [[ -f "$TOKEN_FILE" ]]; then
    pass "token file created at $TOKEN_FILE"
else
    fail "token file not found at $TOKEN_FILE"
fi

# Allow a moment for the log entry to land
sleep 1
JOURNAL_T2=$(journalctl -t pam_bellwether --since "$T2_START" 2>/dev/null || journalctl --since "$T2_START" 2>/dev/null | grep -i "pam_bellwether\|pam-bellwether" || true)
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

wait_for_safe_totp_window
if ssh_to_localhost; then
    pass "SSH succeeded on second connection (within TTL)"
else
    fail "SSH failed on second connection (within TTL)"
fi

sleep 1
JOURNAL_T3=$(journalctl -t pam_bellwether --since "$T3_START" 2>/dev/null || journalctl --since "$T3_START" 2>/dev/null | grep -i "pam_bellwether\|pam-bellwether" || true)
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

wait_for_safe_totp_window
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
JOURNAL_T4=$(journalctl -t pam_bellwether --since "$T4_START" 2>/dev/null || journalctl --since "$T4_START" 2>/dev/null | grep -i "pam_bellwether\|pam-bellwether" || true)
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

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

T5_START=$(date --iso-8601=seconds)
sleep 1

wait_for_safe_totp_window
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
TOKEN_COUNT=$(find /run/pam-bellwether/ -name "testuser_*.token" | wc -l)
assert_eq "$TOKEN_COUNT" "1" "exactly 1 token file for testuser after concurrent connections"

# Check syslog: we expect exactly 1 cache miss (the first connection through the lock)
# and at least some cache hits (connections that queued behind the lock saw the fresh token)
sleep 1
JOURNAL_T5=$(journalctl -t pam_bellwether --since "$T5_START" 2>/dev/null || journalctl --since "$T5_START" 2>/dev/null | grep -i "pam_bellwether\|pam-bellwether" || true)

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

# ---------------------------------------------------------------------------
# Test 6: Failure propagation (follower sees fail marker, denied without MFA)
# ---------------------------------------------------------------------------
echo "--- Test 6: Failure propagation ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

# Temporarily set MaxAuthTries 1 so sshd doesn't retry after the first
# PAM_AUTH_ERR from failure propagation. With MaxAuthTries > 1, sshd retries
# the entire PAM stack, and on retry gate no longer sees the fail marker.
sed -i 's/^MaxAuthTries.*/MaxAuthTries 1/' /etc/ssh/sshd_config
systemctl restart sshd
sleep 1

TMPDIR_T6=$(mktemp -d)

# Use a real SSH leader to hold the flock. The leader sits at the MFA prompt
# (gate has acquired the flock and written the fail marker). A follower
# connects and blocks behind the leader's flock. When the leader is killed,
# lock_cleanup fires (fail marker persists since stamp never ran), releases
# the flock, and the follower sees the "F" marker.
#
# Why a real SSH leader instead of a shell flock: SELinux on Rocky 9 assigns
# different contexts to files created by sshd_t vs unconfined_t. Gate can't
# open files created outside sshd's context.
expect -c "
    set timeout 30
    spawn ssh -o StrictHostKeyChecking=no \
              -o PubkeyAuthentication=no \
              -o PreferredAuthentications=keyboard-interactive \
              testuser@127.0.0.1 true
    expect \"Verification code:\"
    # Sitting at the MFA prompt holds the flock via gate
    sleep 30
" > /dev/null 2>&1 &
LEADER_PID=$!

# Wait for leader to reach the MFA prompt (gate has acquired the flock)
sleep 2

# Start follower — it will block behind the leader's flock
ssh_capture_output "${TMPDIR_T6}/follower.out" &
FOLLOWER_PID=$!

# Give follower time to connect and block on flock, then kill the leader.
# When the leader is killed: sshd worker exits → pam_end → lock_cleanup →
# has_fail_marker (marker was never cleared since MFA never succeeded) →
# 2-second penalty delay → release_lock → follower wakes up, reads "F".
sleep 3
kill $LEADER_PID 2>/dev/null
wait $LEADER_PID 2>/dev/null || true

echo "  Waiting for follower..."
wait $FOLLOWER_PID || true

FOLLOWER_OUT=$(cat "${TMPDIR_T6}/follower.out")

if echo "$FOLLOWER_OUT" | grep -q "MFA failed in another session"; then
    pass "follower received failure propagation message"
else
    # Info messages require the OpenSSH PAM patch — soft check
    echo "  WARN  follower did not receive 'MFA failed in another session' (may need OpenSSH patch)"
fi

if echo "$FOLLOWER_OUT" | grep -q "Verification code:"; then
    fail "follower got its own MFA prompt (failure did NOT propagate)"
else
    pass "follower did not get an MFA prompt (correctly denied without prompt)"
fi

rm -rf "$TMPDIR_T6"

# Explicit: no token should exist after failure propagation
TOKEN_FILE_T6=/run/pam-bellwether/testuser_127.0.0.1.token
if [[ ! -f "$TOKEN_FILE_T6" ]]; then
    pass "no token file created after MFA failure"
else
    fail "token file exists after MFA failure (stamp should not have run)"
fi

echo ""

# Restore MaxAuthTries 3 for remaining tests
sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl restart sshd
sleep 1

# ---------------------------------------------------------------------------
# Test 7: Recovery after failure (fresh attempt succeeds normally)
# ---------------------------------------------------------------------------
echo "--- Test 7: Recovery after failure ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

wait_for_safe_totp_window
if ssh_to_localhost; then
    pass "SSH succeeded after previous failure (no marker poisoning)"
else
    fail "SSH failed after previous failure (marker may have poisoned state)"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 8: Concurrent connections with warm cache (all should get cache hits)
# ---------------------------------------------------------------------------
echo "--- Test 8: Concurrent connections with warm cache ---"

# Cache is warm from Test 7 (token was just stamped)

T8_START=$(date --iso-8601=seconds)
sleep 1

PIDS_T8=()
TMPDIR_T8=$(mktemp -d)

for i in $(seq 1 10); do
    (
        if ssh_to_localhost; then
            echo "0" > "${TMPDIR_T8}/result_${i}"
        else
            echo "1" > "${TMPDIR_T8}/result_${i}"
        fi
    ) &
    PIDS_T8+=($!)
done

echo "  Waiting for 10 parallel SSH connections (all should be cache hits)..."
for pid in "${PIDS_T8[@]}"; do
    wait "$pid" || true
done

FAIL_CONNS_T8=0
for i in $(seq 1 10); do
    result_file="${TMPDIR_T8}/result_${i}"
    if [[ ! -f "$result_file" ]] || [[ "$(cat "$result_file")" != "0" ]]; then
        (( FAIL_CONNS_T8++ )) || true
    fi
done
rm -rf "$TMPDIR_T8"

if [[ $FAIL_CONNS_T8 -eq 0 ]]; then
    pass "all 10 concurrent SSH connections succeeded with warm cache"
else
    fail "$FAIL_CONNS_T8 of 10 concurrent SSH connections failed with warm cache"
fi

sleep 1
JOURNAL_T8=$(journalctl -t pam_bellwether --since "$T8_START" 2>/dev/null || journalctl --since "$T8_START" 2>/dev/null | grep -i "pam_bellwether\|pam-bellwether" || true)
HIT_COUNT_T8=$(echo "$JOURNAL_T8" | grep -ci "SUCCESS\|cache.hit\|fresh\|hit" || true)
MISS_COUNT_T8=$(echo "$JOURNAL_T8" | grep -ci "IGNORE\|cache.miss\|stale\|miss" || true)

echo "  Observed in syslog: $MISS_COUNT_T8 miss(es), $HIT_COUNT_T8 hit(s)"

if [[ $MISS_COUNT_T8 -eq 0 ]]; then
    pass "zero cache misses with warm cache (all connections served from cache)"
else
    echo "  WARN  $MISS_COUNT_T8 cache miss(es) with warm cache — may be a timing issue"
fi

echo ""

# ---------------------------------------------------------------------------
# Test 9: Runtime dir missing (degrade gracefully — MFA still works)
# ---------------------------------------------------------------------------
echo "--- Test 9: Runtime dir missing ---"

# Remove the runtime directory entirely
rm -rf /run/pam-bellwether

wait_for_safe_totp_window
if ssh_to_localhost; then
    pass "SSH succeeded with runtime dir missing (graceful degradation)"
else
    fail "SSH failed with runtime dir missing (should fall through to MFA)"
fi

# Verify no token was created (can't write without the directory)
if [[ ! -f /run/pam-bellwether/testuser_127.0.0.1.token ]]; then
    pass "no token file created (expected — directory missing)"
else
    fail "token file created despite missing runtime dir"
fi

# Restore the directory for cleanup
install -d -m 0700 -o root -g root /run/pam-bellwether

echo ""

# ---------------------------------------------------------------------------
# Test 10: Leader aborts mid-auth (follower not stuck forever)
# ---------------------------------------------------------------------------
echo "--- Test 10: Leader abort (follower must not hang) ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

# Start a leader that grabs the flock but never answers MFA
expect -c "
    set timeout 60
    spawn ssh -o StrictHostKeyChecking=no \
              -o PubkeyAuthentication=no \
              -o PreferredAuthentications=keyboard-interactive \
              testuser@127.0.0.1 true
    expect \"Verification code:\"
    # Hold the flock by sitting at the MFA prompt
    sleep 60
" > /dev/null 2>&1 &
ABORT_LEADER_PID=$!

sleep 2  # give leader time to grab flock

# Start follower — it will block behind the leader's flock
ABORT_T_START=$(date +%s)
wait_for_safe_totp_window

# Run follower with a timeout — it MUST complete within 20 seconds
# The follower handles prompts with wrong codes to prevent hanging:
# after leader abort, sshd may retry and pam_google_authenticator
# sends a TOTP prompt. Without answering, the follower would hang.
(
    expect -c "
        set timeout 20
        spawn ssh -o StrictHostKeyChecking=no \
                  -o PubkeyAuthentication=no \
                  -o PreferredAuthentications=keyboard-interactive \
                  testuser@127.0.0.1 true
        expect {
            \"Verification code:\" { send \"000000\r\"; exp_continue }
            eof {}
            timeout {}
        }
        catch wait result
        exit [lindex \$result 3]
    " > /dev/null 2>&1
) &
ABORT_FOLLOWER_PID=$!

# Kill the leader after 2 seconds — simulates client abort
sleep 2
kill $ABORT_LEADER_PID 2>/dev/null
wait $ABORT_LEADER_PID 2>/dev/null || true

# Wait for follower to complete
wait $ABORT_FOLLOWER_PID 2>/dev/null || true
ABORT_T_END=$(date +%s)
ABORT_ELAPSED=$(( ABORT_T_END - ABORT_T_START ))

if [[ $ABORT_ELAPSED -lt 30 ]]; then
    pass "follower completed in ${ABORT_ELAPSED}s after leader abort (not stuck)"
else
    fail "follower took ${ABORT_ELAPSED}s after leader abort (may be stuck on flock)"
fi

echo ""

# cleanup is called via trap EXIT
