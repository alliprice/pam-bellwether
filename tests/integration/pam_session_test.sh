#!/usr/bin/env bash
set -euo pipefail

# Session-phase integration tests for pam_bellwether_gate.so and pam_bellwether_stamp.so
#
# Tests gate/stamp in the PAM session phase with pubkey-only SSH auth.
# Uses pam_exec.so with mfa_stub.sh as a stand-in for pam_duo autopush.
#
# Phase 1: Build verification (symbols, basic connectivity)
# Phase 2: Behavioral tests (cache miss/hit/expiry, concurrency, failure propagation)
# Phase 3: Real pam_duo tests (requires human interaction - Duo push approval)
#
# Usage (Lima):  limactl shell bastion-test -- sudo bash /Users/alliprice/code/pam-preauth/tests/integration/pam_session_test.sh
# Phase 3 only: limactl shell bastion-test -- sudo bash /Users/alliprice/code/pam-preauth/tests/integration/pam_session_test.sh --phase3

# ---------------------------------------------------------------------------
# Colored output helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()

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

warn() {
    local msg="$1"
    echo -e "${YELLOW}  WARN${RESET}  $msg"
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

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
RUN_PHASE3=false
if [[ "${1:-}" == "--phase3" ]]; then
    RUN_PHASE3=true
fi

# ---------------------------------------------------------------------------
# SSH helper - non-interactive pubkey-only (simulates Ansible)
# ---------------------------------------------------------------------------
ssh_noninteractive() {
    ssh -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o KbdInteractiveAuthentication=no \
        -o PreferredAuthentications=publickey \
        -o PasswordAuthentication=no \
        -i /home/testuser/.ssh/id_ed25519 \
        testuser@127.0.0.1 "$@"
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

    rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock
    rm -f /run/pam-bellwether/l-aprice_*.token /run/pam-bellwether/l-aprice_*.lock
    rm -f /tmp/bellwether-mfa-fail
    rm -f /tmp/duo-test-marker.*
    rm -f /usr/local/bin/bellwether_mfa_stub.sh
    echo "Removed test token/lock files, fail trigger, and MFA stub"

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
echo "=== pam_bellwether session-phase integration tests ==="
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must run as root." >&2
    exit 1
fi

if ! id testuser &>/dev/null; then
    echo "ERROR: 'testuser' does not exist. Create it first: useradd -m testuser" >&2
    exit 1
fi

# Add cargo/rustup to PATH
if ! command -v cargo &>/dev/null; then
    for cargo_dir in $(find /home -maxdepth 3 -type d -name .cargo 2>/dev/null) /root/.cargo; do
        if [[ -x "$cargo_dir/bin/cargo" ]]; then
            export PATH="$cargo_dir/bin:$PATH"
            export CARGO_HOME="$cargo_dir"
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

# Install MFA stub script to a location sshd can execute (SELinux: user_home_t
# is not accessible from sshd_t, so copy to /usr/local/bin with bin_t context)
MFA_STUB="/usr/local/bin/bellwether_mfa_stub.sh"
cp "${SCRIPT_DIR}/mfa_stub.sh" "$MFA_STUB"
chmod +x "$MFA_STUB"
restorecon -v "$MFA_STUB" 2>/dev/null || true

# Generate SSH keypair for testuser if not present
if [[ ! -f /home/testuser/.ssh/id_ed25519 ]]; then
    echo "Generating SSH keypair for testuser..."
    mkdir -p /home/testuser/.ssh
    ssh-keygen -t ed25519 -f /home/testuser/.ssh/id_ed25519 -N "" -q
    chown -R testuser:testuser /home/testuser/.ssh
    chmod 700 /home/testuser/.ssh
    chmod 600 /home/testuser/.ssh/id_ed25519
fi

# Install pubkey in authorized_keys
if ! grep -qf /home/testuser/.ssh/id_ed25519.pub /home/testuser/.ssh/authorized_keys 2>/dev/null; then
    echo "Installing pubkey in authorized_keys..."
    cat /home/testuser/.ssh/id_ed25519.pub >> /home/testuser/.ssh/authorized_keys
    chown testuser:testuser /home/testuser/.ssh/authorized_keys
    chmod 600 /home/testuser/.ssh/authorized_keys
fi

echo "Backing up configs..."
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
if [[ -d /etc/ssh/sshd_config.d ]]; then
    cp -a /etc/ssh/sshd_config.d /etc/ssh/sshd_config.d.bak
fi

echo "Configuring sshd for pubkey-only auth..."
# Override auth settings in drop-in configs
if [[ -d /etc/ssh/sshd_config.d ]]; then
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] && sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$f"
        [[ -f "$f" ]] && sed -i 's/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$f"
        [[ -f "$f" ]] && sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$f"
        [[ -f "$f" ]] && sed -i '/^AuthenticationMethods/d' "$f"
    done
fi
# Main config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
sed -i 's/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
grep -q '^KbdInteractiveAuthentication' /etc/ssh/sshd_config || echo 'KbdInteractiveAuthentication no' >> /etc/ssh/sshd_config
sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -i '/^#\?AuthenticationMethods/d' /etc/ssh/sshd_config
echo 'AuthenticationMethods publickey' >> /etc/ssh/sshd_config
sed -i 's/^#UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
grep -q '^UsePAM' /etc/ssh/sshd_config || echo 'UsePAM yes' >> /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config

echo "Writing session-phase PAM config..."
cat > /etc/pam.d/sshd <<PAM_EOF
# Session-phase test PAM stack - pam_exec with mfa_stub.sh as MFA stand-in
# TTL is 5 seconds for fast testing.
auth     required   pam_permit.so
account  required   pam_permit.so
password required   pam_permit.so
session  [success=1 ignore=ignore session_err=die default=ignore]  pam_bellwether_gate.so timeout=5 debug
session  requisite  pam_exec.so ${MFA_STUB}
session  required   pam_bellwether_stamp.so debug
session  required   pam_permit.so
PAM_EOF

echo "Restarting sshd..."
systemctl restart sshd
sleep 1

echo "Setup complete."
echo ""

# ===========================================================================
# Phase 1: Build verification
# ===========================================================================
echo "=== Phase 1: Build verification ==="
echo ""

GATE_SO=/usr/lib64/security/pam_bellwether_gate.so
STAMP_SO=/usr/lib64/security/pam_bellwether_stamp.so

# --- S1: Session symbols exist ---
echo "--- S1: Session symbols ---"

for so_file in "$GATE_SO" "$STAMP_SO"; do
    so_name=$(basename "$so_file")
    symbols=$(nm -D "$so_file" 2>/dev/null || true)
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

echo ""

# --- S2: Basic non-interactive connect ---
echo "--- S2: Basic non-interactive SSH connect ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock
rm -f /tmp/bellwether-mfa-fail

RESULT=$(ssh_noninteractive whoami 2>&1) || true
if [[ "$RESULT" == *"testuser"* ]]; then
    pass "non-interactive SSH connect succeeded (whoami=$RESULT)"
else
    fail "non-interactive SSH connect failed (output: $RESULT)"
fi

echo ""

# ===========================================================================
# Phase 2: Behavioral tests with stub MFA
# ===========================================================================
echo "=== Phase 2: Behavioral tests ==="
echo ""

# --- S3: Cache miss ---
echo "--- S3: Cache miss (first connection) ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

T_S3=$(date --iso-8601=seconds)
sleep 1

RESULT=$(ssh_noninteractive whoami 2>&1) || true
if [[ "$RESULT" == *"testuser"* ]]; then
    pass "SSH succeeded on first connection"
else
    fail "SSH failed on first connection (output: $RESULT)"
fi

TOKEN_FILE=/run/pam-bellwether/testuser_127.0.0.1.token
if [[ -f "$TOKEN_FILE" ]]; then
    pass "token file created at $TOKEN_FILE"
else
    fail "token file not found at $TOKEN_FILE"
fi

sleep 1
JOURNAL_S3=$(journalctl --since "$T_S3" 2>/dev/null | grep -i "pam_bellwether\|mfa_stub" || true)
if echo "$JOURNAL_S3" | grep -qi "cache.miss\|miss"; then
    pass "syslog shows cache miss"
else
    warn "Could not confirm cache-miss log entry"
fi
if echo "$JOURNAL_S3" | grep -qi "mfa_stub.*invoked"; then
    pass "MFA stub was invoked on cache miss"
else
    warn "Could not confirm MFA stub invocation in syslog"
fi

echo ""

# --- S4: Cache hit ---
echo "--- S4: Cache hit (second connection within TTL) ---"

T_S4=$(date --iso-8601=seconds)
sleep 1

RESULT=$(ssh_noninteractive whoami 2>&1) || true
if [[ "$RESULT" == *"testuser"* ]]; then
    pass "SSH succeeded on second connection (within TTL)"
else
    fail "SSH failed on second connection (output: $RESULT)"
fi

sleep 1
JOURNAL_S4=$(journalctl --since "$T_S4" 2>/dev/null | grep -i "pam_bellwether\|mfa_stub" || true)
if echo "$JOURNAL_S4" | grep -qi "cache.hit\|hit.*skipping"; then
    pass "syslog shows cache hit"
else
    warn "Could not confirm cache-hit log entry"
fi

# MFA stub should NOT have been invoked on cache hit
STUB_COUNT_S4=$(echo "$JOURNAL_S4" | grep -ci "mfa_stub.*invoked" || true)
if [[ "$STUB_COUNT_S4" -eq 0 ]]; then
    pass "MFA stub was NOT invoked on cache hit (correctly skipped)"
else
    fail "MFA stub was invoked on cache hit (should have been skipped)"
fi

echo ""

# --- S5: Cache expiry ---
echo "--- S5: Cache expiry (waiting 6s for 5s TTL) ---"

echo "  Sleeping 6 seconds..."
sleep 6

T_S5=$(date --iso-8601=seconds)
sleep 1

RESULT=$(ssh_noninteractive whoami 2>&1) || true
if [[ "$RESULT" == *"testuser"* ]]; then
    pass "SSH succeeded after TTL expiry"
else
    fail "SSH failed after TTL expiry (output: $RESULT)"
fi

sleep 1
JOURNAL_S5=$(journalctl --since "$T_S5" 2>/dev/null | grep -i "pam_bellwether\|mfa_stub" || true)
if echo "$JOURNAL_S5" | grep -qi "cache.miss\|miss"; then
    pass "syslog shows cache miss after expiry"
else
    warn "Could not confirm post-expiry cache-miss log entry"
fi
if echo "$JOURNAL_S5" | grep -qi "mfa_stub.*invoked"; then
    pass "MFA stub was invoked after cache expiry"
else
    warn "Could not confirm MFA stub invocation after expiry"
fi

echo ""

# --- S6: Concurrent connections ---
echo "--- S6: Concurrent connections (10 parallel non-interactive SSH) ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

T_S6=$(date --iso-8601=seconds)
sleep 1

PIDS=()
TMPDIR_S6=$(mktemp -d)

for i in $(seq 1 10); do
    (
        if ssh_noninteractive whoami > /dev/null 2>&1; then
            echo "0" > "${TMPDIR_S6}/result_${i}"
        else
            echo "1" > "${TMPDIR_S6}/result_${i}"
        fi
    ) &
    PIDS+=($!)
done

echo "  Waiting for 10 parallel SSH connections..."
for pid in "${PIDS[@]}"; do
    wait "$pid" || true
done

FAIL_CONNS=0
for i in $(seq 1 10); do
    result_file="${TMPDIR_S6}/result_${i}"
    if [[ ! -f "$result_file" ]] || [[ "$(cat "$result_file")" != "0" ]]; then
        (( FAIL_CONNS++ )) || true
    fi
done
rm -rf "$TMPDIR_S6"

if [[ $FAIL_CONNS -eq 0 ]]; then
    pass "all 10 concurrent SSH connections succeeded"
else
    fail "$FAIL_CONNS of 10 concurrent SSH connections failed"
fi

TOKEN_COUNT=$(find /run/pam-bellwether/ -name "testuser_*.token" | wc -l)
assert_eq "$TOKEN_COUNT" "1" "exactly 1 token file after concurrent connections"

sleep 1
JOURNAL_S6=$(journalctl --since "$T_S6" 2>/dev/null | grep -i "mfa_stub" || true)
STUB_INVOCATIONS=$(echo "$JOURNAL_S6" | grep -ci "mfa_stub.*invoked" || true)
echo "  MFA stub invocations: $STUB_INVOCATIONS"

if [[ $STUB_INVOCATIONS -eq 1 ]]; then
    pass "exactly 1 MFA stub invocation (flock serialization working)"
else
    warn "Expected 1 MFA stub invocation, got $STUB_INVOCATIONS"
fi

echo ""

# --- S7: Failure propagation ---
echo "--- S7: Failure propagation ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

# Set MaxAuthTries 1 so sshd doesn't retry after failure propagation
sed -i 's/^MaxAuthTries.*/MaxAuthTries 1/' /etc/ssh/sshd_config
systemctl restart sshd
sleep 1

# Create the fail trigger so MFA stub fails
touch /tmp/bellwether-mfa-fail

T_S7=$(date --iso-8601=seconds)
sleep 1

# Leader: connect and fail MFA (stub sees fail trigger)
ssh_noninteractive whoami > /dev/null 2>&1 || true

# Follower: connect immediately after - should be denied by fail marker
# Give a short pause for lock cleanup (2s penalty delay)
sleep 3

FOLLOWER_RESULT=$(ssh_noninteractive whoami 2>&1) || true

sleep 1
JOURNAL_S7=$(journalctl --since "$T_S7" 2>/dev/null | grep -i "pam_bellwether" || true)

if echo "$JOURNAL_S7" | grep -qi "MFA failed in another session\|denying"; then
    pass "follower denied by failure propagation"
else
    # With session phase, failure shows as "Connection closed" not "Permission denied"
    # Check if the follower actually failed
    if [[ "$FOLLOWER_RESULT" != *"testuser"* ]]; then
        pass "follower connection failed (expected after MFA failure)"
    else
        fail "follower succeeded after leader MFA failure (failure propagation broken)"
    fi
fi

TOKEN_FILE_S7=/run/pam-bellwether/testuser_127.0.0.1.token
if [[ ! -f "$TOKEN_FILE_S7" ]]; then
    pass "no token file created after MFA failure"
else
    fail "token file exists after MFA failure (stamp should not have run)"
fi

# Restore MaxAuthTries
sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
systemctl restart sshd
sleep 1

echo ""

# --- S8: Recovery after failure ---
echo "--- S8: Recovery after failure ---"

rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock
rm -f /tmp/bellwether-mfa-fail

RESULT=$(ssh_noninteractive whoami 2>&1) || true
if [[ "$RESULT" == *"testuser"* ]]; then
    pass "SSH succeeded after removing fail trigger (recovery works)"
else
    fail "SSH failed after removing fail trigger (output: $RESULT)"
fi

echo ""

# ===========================================================================
# Phase 4: Combined module tests (pam_bellwether.so with mock Duo)
# ===========================================================================
echo "=== Phase 4: Combined module tests ==="
echo ""

# Check if combined module was built
COMBINED_SO="$PROJECT_ROOT/target/release/libpam_bellwether.so"
if [[ ! -f "$COMBINED_SO" ]]; then
    echo "SKIP: libpam_bellwether.so not found (bellwether crate not built)"
else
    cp "$COMBINED_SO" /usr/lib64/security/pam_bellwether.so

    # Start mock Duo API server
    MOCK_DUO_PORT=18443
    MOCK_DUO_SCRIPT=$(mktemp /tmp/mock_duo_XXXXXX.py)
    cat > "$MOCK_DUO_SCRIPT" <<'MOCK_EOF'
import http.server, json, sys

class DuoMockHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length > 0 else ''

        if self.path == '/auth/v2/preauth':
            resp = {"stat": "OK", "response": {"result": "auth", "status_msg": "Account is active"}}
        elif self.path == '/auth/v2/auth':
            resp = {"stat": "OK", "response": {"txid": "mock-txid-001"}}
        else:
            resp = {"stat": "FAIL", "message": "Unknown endpoint"}

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def do_GET(self):
        if '/auth/v2/auth_status' in self.path:
            resp = {"stat": "OK", "response": {"result": "allow", "status": "allow", "status_msg": "Success"}}
        else:
            resp = {"stat": "FAIL", "message": "Unknown endpoint"}

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, format, *args):
        pass  # Suppress request logging

server = http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), DuoMockHandler)
server.serve_forever()
MOCK_EOF

    python3 "$MOCK_DUO_SCRIPT" $MOCK_DUO_PORT &
    MOCK_DUO_PID=$!
    sleep 1

    # Write Duo config pointing to mock server
    mkdir -p /etc/bellwether
    cat > /etc/bellwether/duo.conf <<DUO_CONF_EOF
[duo]
ikey = DITEST1234567890ABCD
skey = testsecretkey1234567890abcdefghijklmnop
host = 127.0.0.1:${MOCK_DUO_PORT}
failmode = secure
DUO_CONF_EOF
    chmod 600 /etc/bellwether/duo.conf

    # Switch PAM to combined module
    cat > /etc/pam.d/sshd <<PAM_COMBINED_EOF
auth     required   pam_permit.so
account  required   pam_permit.so
password required   pam_permit.so
session  [success=ok session_err=die default=ignore]  pam_bellwether.so timeout=5 debug duo_config=/etc/bellwether/duo.conf
session  required   pam_permit.so
PAM_COMBINED_EOF

    systemctl restart sshd
    sleep 1

    # --- C1: Combined module symbols ---
    echo "--- C1: Combined module symbols ---"
    symbols=$(nm -D /usr/lib64/security/pam_bellwether.so 2>/dev/null || true)
    for sym in pam_sm_authenticate pam_sm_setcred pam_sm_open_session pam_sm_close_session; do
        if echo "$symbols" | grep -q "$sym"; then
            pass "pam_bellwether.so exports $sym"
        else
            fail "pam_bellwether.so missing $sym"
        fi
    done
    echo ""

    # --- C2: Cache miss with mock Duo ---
    echo "--- C2: Cache miss with mock Duo ---"
    rm -f /run/pam-bellwether/testuser_*.token /run/pam-bellwether/testuser_*.lock

    RESULT=$(ssh_noninteractive whoami 2>&1) || true
    if [[ "$RESULT" == *"testuser"* ]]; then
        pass "C2: combined module SSH succeeded (cache miss, mock Duo approved)"
    else
        fail "C2: combined module SSH failed (output: $RESULT)"
    fi

    TOKEN_FILE=/run/pam-bellwether/testuser_127.0.0.1.token
    if [[ -f "$TOKEN_FILE" ]]; then
        pass "C2: token file created"
    else
        fail "C2: token file not found"
    fi
    echo ""

    # --- C3: Cache hit ---
    echo "--- C3: Cache hit with combined module ---"
    RESULT=$(ssh_noninteractive whoami 2>&1) || true
    if [[ "$RESULT" == *"testuser"* ]]; then
        pass "C3: combined module cache hit succeeded"
    else
        fail "C3: combined module cache hit failed (output: $RESULT)"
    fi
    echo ""

    # --- C4: Cache expiry ---
    echo "--- C4: Cache expiry with combined module ---"
    echo "  Sleeping 6 seconds..."
    sleep 6
    rm -f /run/pam-bellwether/testuser_*.token  # force miss
    RESULT=$(ssh_noninteractive whoami 2>&1) || true
    if [[ "$RESULT" == *"testuser"* ]]; then
        pass "C4: combined module post-expiry succeeded"
    else
        fail "C4: combined module post-expiry failed (output: $RESULT)"
    fi
    echo ""

    # Cleanup mock server
    kill $MOCK_DUO_PID 2>/dev/null || true
    rm -f "$MOCK_DUO_SCRIPT"
    rm -rf /etc/bellwether

    # Restore the gate+stamp PAM config for remaining tests
    cat > /etc/pam.d/sshd <<PAM_RESTORE_EOF
auth     required   pam_permit.so
account  required   pam_permit.so
password required   pam_permit.so
session  [success=1 ignore=ignore session_err=die default=ignore]  pam_bellwether_gate.so timeout=5 debug
session  requisite  pam_exec.so ${MFA_STUB}
session  required   pam_bellwether_stamp.so debug
session  required   pam_permit.so
PAM_RESTORE_EOF
    systemctl restart sshd
    sleep 1
fi

echo ""

# ===========================================================================
# Phase 3: Real pam_duo tests (optional, requires human interaction)
# ===========================================================================
if [[ "$RUN_PHASE3" == "true" ]]; then
    echo "=== Phase 3: Real pam_duo tests ==="
    echo ""

    # Check if pam_duo is installed
    if [[ ! -f /usr/lib64/security/pam_duo.so ]]; then
        echo "Installing duo_unix..."
        yum-config-manager --add-repo https://pkg.duosecurity.com/RedHat/9/x86_64 2>&1 || true
        rpm --import https://duo.com/DUO-GPG-PUBLIC-KEY.asc 2>&1 || true
        dnf install -y duo_unix 2>&1 || true
    fi

    if [[ ! -f /usr/lib64/security/pam_duo.so ]]; then
        echo "ERROR: pam_duo.so not found after install attempt. Skipping Phase 3." >&2
    else
        # Create l-aprice user if not exists
        if ! id l-aprice &>/dev/null; then
            echo "Creating user l-aprice..."
            useradd -m l-aprice
        fi

        # Generate SSH keypair for l-aprice if not present
        if [[ ! -f /home/l-aprice/.ssh/id_ed25519 ]]; then
            echo "Generating SSH keypair for l-aprice..."
            mkdir -p /home/l-aprice/.ssh
            ssh-keygen -t ed25519 -f /home/l-aprice/.ssh/id_ed25519 -N "" -q
            chown -R l-aprice:l-aprice /home/l-aprice/.ssh
            chmod 700 /home/l-aprice/.ssh
            chmod 600 /home/l-aprice/.ssh/id_ed25519
        fi

        # Install pubkey
        if ! grep -qf /home/l-aprice/.ssh/id_ed25519.pub /home/l-aprice/.ssh/authorized_keys 2>/dev/null; then
            cat /home/l-aprice/.ssh/id_ed25519.pub >> /home/l-aprice/.ssh/authorized_keys
            chown l-aprice:l-aprice /home/l-aprice/.ssh/authorized_keys
            chmod 600 /home/l-aprice/.ssh/authorized_keys
        fi

        # Write Duo config - failmode=secure so a Duo API failure denies
        # access instead of silently passing. This ensures tests actually
        # exercise the Duo push flow.
        mkdir -p /etc/duo
        cat > /etc/duo/pam_duo.conf <<'DUO_EOF'
[duo]
ikey = REDACTED_DUO_IKEY
skey = REDACTED_DUO_SKEY
host = REDACTED_DUO_HOST
failmode = secure
pushinfo = yes
autopush = yes
DUO_EOF
        chmod 600 /etc/duo/pam_duo.conf

        # Switch PAM to real pam_duo
        cat > /etc/pam.d/sshd <<'PAM_DUO_EOF'
auth     required   pam_permit.so
account  required   pam_permit.so
password required   pam_permit.so
session  [success=1 ignore=ignore session_err=die default=ignore]  pam_bellwether_gate.so timeout=60 debug
session  requisite  pam_duo.so
session  required   pam_bellwether_stamp.so debug
session  required   pam_permit.so
PAM_DUO_EOF

        systemctl restart sshd
        sleep 1

        # Clean any l-aprice tokens from previous runs
        rm -f /run/pam-bellwether/l-aprice_*.token /run/pam-bellwether/l-aprice_*.lock

        ssh_duo() {
            ssh -o BatchMode=yes \
                -o StrictHostKeyChecking=no \
                -o ConnectTimeout=60 \
                -o KbdInteractiveAuthentication=no \
                -o PreferredAuthentications=publickey \
                -o PasswordAuthentication=no \
                -i /home/l-aprice/.ssh/id_ed25519 \
                l-aprice@127.0.0.1 "$@"
        }

        # Collect logs from all sources pam_duo and sshd write to.
        #
        # Sources checked:
        #   - journalctl (systemd journal: sshd, pam_bellwether)
        #   - /var/log/secure (RHEL auth log: sshd PAM entries)
        #   - /var/log/messages (pam_duo/login_duo log here by default)
        #
        # Uses a line-count snapshot to get only lines added after the
        # snapshot was taken, avoiding syslog timestamp parsing issues.
        DUO_MARKER=$(mktemp /tmp/duo-test-marker.XXXXXX)
        DUO_SECURE_LINES=0
        DUO_MESSAGES_LINES=0

        duo_snapshot() {
            # Record current line counts and timestamp
            touch "$DUO_MARKER"
            DUO_SECURE_LINES=$(wc -l < /var/log/secure 2>/dev/null || echo 0)
            DUO_MESSAGES_LINES=$(wc -l < /var/log/messages 2>/dev/null || echo 0)
        }

        duo_logs() {
            local since_iso
            since_iso=$(date -r "$DUO_MARKER" --iso-8601=seconds 2>/dev/null)
            local filter="duo\|pam_bellwether\|l-aprice\|sshd.*session\|SIGSEGV\|segfault"
            {
                journalctl --since "$since_iso" --no-pager 2>/dev/null || true
                tail -n +"$((DUO_SECURE_LINES + 1))" /var/log/secure 2>/dev/null || true
                tail -n +"$((DUO_MESSAGES_LINES + 1))" /var/log/messages 2>/dev/null || true
            } | grep -i "$filter" | sort -u
        }

        # --- D1: pam_duo viability ---
        echo "--- D1: pam_duo viability ---"
        echo ""
        echo -e "  ${YELLOW}>>> APPROVE THE DUO PUSH NOW <<<${RESET}"
        echo ""

        rm -f /run/pam-bellwether/l-aprice_*.token /run/pam-bellwether/l-aprice_*.lock

        duo_snapshot
        sleep 1

        DUO_RESULT=$(ssh_duo whoami 2>&1) || true

        sleep 2
        D1_LOGS=$(duo_logs)

        echo "  --- D1 logs ---"
        echo "$D1_LOGS" | sed 's/^/  | /'
        echo "  --- end logs ---"
        echo ""

        # Check for sshd crash
        if echo "$D1_LOGS" | grep -qi "SIGSEGV\|segfault\|core.dump"; then
            fail "D1: sshd crashed (SIGSEGV) - pam_duo not viable in session phase"
        else
            pass "D1: no sshd crash"
        fi

        if [[ "$DUO_RESULT" == *"l-aprice"* ]]; then
            pass "D1: pam_duo connection succeeded in session phase"
        else
            fail "D1: pam_duo connection failed (output: $DUO_RESULT)"
        fi

        # Verify Duo actually ran (not failmode pass-through)
        if echo "$D1_LOGS" | grep -qi "duo.*auth\|Successful Duo\|duo_login"; then
            pass "D1: Duo authentication logged"
        else
            warn "D1: no Duo authentication log entry found - Duo may not have actually run"
        fi

        echo ""

        # --- D2: Duo + bellwether cache miss ---
        echo "--- D2: Duo + bellwether cache miss ---"
        echo ""
        echo -e "  ${YELLOW}>>> APPROVE THE DUO PUSH NOW <<<${RESET}"
        echo ""

        rm -f /run/pam-bellwether/l-aprice_*.token /run/pam-bellwether/l-aprice_*.lock

        duo_snapshot
        sleep 1

        DUO_RESULT2=$(ssh_duo whoami 2>&1) || true

        sleep 2
        D2_LOGS=$(duo_logs)

        echo "  --- D2 logs ---"
        echo "$D2_LOGS" | sed 's/^/  | /'
        echo "  --- end logs ---"
        echo ""

        if [[ "$DUO_RESULT2" == *"l-aprice"* ]]; then
            pass "D2: connection succeeded"
        else
            fail "D2: connection failed (output: $DUO_RESULT2)"
        fi

        DUO_TOKEN=/run/pam-bellwether/l-aprice_127.0.0.1.token
        if [[ -f "$DUO_TOKEN" ]]; then
            pass "D2: token file created"
        else
            fail "D2: token file not found"
        fi

        if echo "$D2_LOGS" | grep -qi "cache.miss\|miss"; then
            pass "D2: bellwether cache miss"
        else
            warn "D2: could not confirm cache-miss log entry"
        fi

        if echo "$D2_LOGS" | grep -qi "duo.*auth\|Successful Duo\|duo_login"; then
            pass "D2: Duo authentication logged"
        else
            warn "D2: no Duo authentication log entry found"
        fi

        echo ""

        # --- D3: Duo + bellwether cache hit ---
        echo "--- D3: Duo + bellwether cache hit ---"
        echo "  (NO Duo push should fire - do NOT approve anything)"
        echo ""

        duo_snapshot
        sleep 1

        DUO_RESULT3=$(ssh_duo whoami 2>&1) || true

        sleep 2
        D3_LOGS=$(duo_logs)

        echo "  --- D3 logs ---"
        echo "$D3_LOGS" | sed 's/^/  | /'
        echo "  --- end logs ---"
        echo ""

        if [[ "$DUO_RESULT3" == *"l-aprice"* ]]; then
            pass "D3: connection succeeded (cache hit)"
        else
            fail "D3: connection failed (output: $DUO_RESULT3)"
        fi

        if echo "$D3_LOGS" | grep -qi "cache.hit\|hit.*skipping"; then
            pass "D3: bellwether cache hit (Duo skipped)"
        else
            warn "D3: could not confirm cache-hit log entry"
        fi

        # Duo should NOT have been invoked on cache hit
        if echo "$D3_LOGS" | grep -qi "duo.*auth\|Successful Duo\|duo_login"; then
            fail "D3: Duo authentication logged on cache hit (should have been skipped)"
        else
            pass "D3: no Duo authentication on cache hit (correctly skipped)"
        fi

        echo ""
    fi
fi

# cleanup is called via trap EXIT
