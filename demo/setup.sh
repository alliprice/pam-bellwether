#!/usr/bin/env bash
set -euo pipefail

# Pre-demo setup: build, install PAM modules in Lima VM, discover SSH port.
# Run once before recording with VHS.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VM_NAME="pam-preauth"
TOTP_SECRET="JBSWY3DPEHPK3PXP"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
echo "=== pam-preauth demo setup ==="
echo ""

for cmd in vhs tmux oathtool expect limactl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Install it first." >&2
        exit 1
    fi
done

if ! limactl list --json 2>/dev/null | grep -q "\"$VM_NAME\""; then
    echo "ERROR: Lima VM '$VM_NAME' not found." >&2
    echo "Create it: limactl create --name=$VM_NAME lima-rocky9.yaml && limactl start $VM_NAME" >&2
    exit 1
fi

VM_STATUS=$(limactl list --json 2>/dev/null | python3 -c "
import sys, json
for i in json.load(sys.stdin):
    if i['name'] == '$VM_NAME':
        print(i.get('status', 'unknown'))
")

if [[ "$VM_STATUS" != "Running" ]]; then
    echo "ERROR: Lima VM '$VM_NAME' is not running (status: $VM_STATUS)." >&2
    echo "Start it: limactl start $VM_NAME" >&2
    exit 1
fi

echo "Prerequisites OK."

# ---------------------------------------------------------------------------
# Discover SSH port
# ---------------------------------------------------------------------------
SSH_PORT=$(limactl show-ssh --format=args "$VM_NAME" 2>/dev/null \
    | grep -oE '\-p [0-9]+' | awk '{print $2}')

if [[ -z "$SSH_PORT" ]]; then
    echo "ERROR: Could not determine SSH port for VM '$VM_NAME'." >&2
    exit 1
fi

echo "SSH_PORT=$SSH_PORT" > "$SCRIPT_DIR/.env"
echo "Discovered SSH port: $SSH_PORT (written to demo/.env)"

# ---------------------------------------------------------------------------
# Build and install
# ---------------------------------------------------------------------------
echo ""
echo "Building project in VM..."
limactl shell "$VM_NAME" -- bash -c "
    source ~/.cargo/env 2>/dev/null || true
    cd '$PROJECT_ROOT' && cargo build --release 2>&1
"
echo "Build complete."

echo "Installing .so files..."
limactl shell "$VM_NAME" -- sudo bash -c "
    cp '$PROJECT_ROOT/target/release/libpam_preauth_gate.so'  /usr/lib64/security/pam_preauth_gate.so
    cp '$PROJECT_ROOT/target/release/libpam_preauth_stamp.so' /usr/lib64/security/pam_preauth_stamp.so
    install -d -m 0700 -o root -g root /run/pam-preauth
"

# ---------------------------------------------------------------------------
# Configure PAM (timeout=30 for demo, no debug — cleaner output)
# ---------------------------------------------------------------------------
echo "Configuring PAM stack (timeout=30)..."
limactl shell "$VM_NAME" -- sudo bash -c "
cat > /etc/pam.d/sshd <<'PAM_EOF'
# Demo PAM stack — google-authenticator stands in for pam_duo
auth  [success=1 ignore=ignore default=ignore]  pam_preauth_gate.so timeout=30
auth  required                                   pam_google_authenticator.so
auth  required                                   pam_preauth_stamp.so
account required pam_permit.so
password required pam_permit.so
session required pam_permit.so
PAM_EOF
"

# ---------------------------------------------------------------------------
# Configure sshd
# ---------------------------------------------------------------------------
echo "Configuring sshd..."
limactl shell "$VM_NAME" -- sudo bash -c '
    # Override auth settings in drop-in configs
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] || continue
        sed -i "s/^PasswordAuthentication.*/PasswordAuthentication no/" "$f"
        sed -i "s/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/" "$f"
        sed -i "s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/" "$f"
    done

    cfg=/etc/ssh/sshd_config
    sed -i "s/^PasswordAuthentication.*/PasswordAuthentication no/" "$cfg"
    sed -i "s/^#PasswordAuthentication.*/PasswordAuthentication no/" "$cfg"
    grep -q "^PasswordAuthentication" "$cfg" || echo "PasswordAuthentication no" >> "$cfg"
    sed -i "s/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/" "$cfg"
    sed -i "s/^#KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/" "$cfg"
    grep -q "^KbdInteractiveAuthentication" "$cfg" || echo "KbdInteractiveAuthentication yes" >> "$cfg"
    sed -i "s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/" "$cfg"
    sed -i "s/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/" "$cfg"
    sed -i "s/^#UsePAM.*/UsePAM yes/" "$cfg"
    grep -q "^UsePAM" "$cfg" || echo "UsePAM yes" >> "$cfg"
'

# ---------------------------------------------------------------------------
# Restart sshd and clear tokens
# ---------------------------------------------------------------------------
echo "Restarting sshd..."
limactl shell "$VM_NAME" -- sudo bash -c '
    systemctl restart sshd
    rm -f /run/pam-preauth/*.token /run/pam-preauth/*.lock
'
sleep 1

# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
echo ""
echo "Smoke test: SSH with TOTP..."
TOTP_CODE=$(oathtool --totp -b "$TOTP_SECRET")

SMOKE_RESULT=$(expect -c "
    set timeout 15
    spawn ssh -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o PubkeyAuthentication=no \
              -o PreferredAuthentications=keyboard-interactive \
              -p $SSH_PORT testuser@127.0.0.1 echo smoke-ok
    expect {
        \"Verification code:\" {
            send \"${TOTP_CODE}\r\"
            expect eof
        }
        eof {}
        timeout { exit 1 }
    }
    catch wait result
    exit [lindex \$result 3]
" 2>&1)

if echo "$SMOKE_RESULT" | grep -q "smoke-ok"; then
    echo "Smoke test PASSED."
else
    echo "ERROR: Smoke test FAILED. Output:" >&2
    echo "$SMOKE_RESULT" >&2
    exit 1
fi

echo ""
echo "=== Setup complete. Run: vhs demo/demo.tape ==="
