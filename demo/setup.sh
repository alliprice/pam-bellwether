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
echo "=== pam-bellwether demo setup ==="
echo ""

for cmd in vhs tmux oathtool expect limactl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Install it first." >&2
        exit 1
    fi
done

VM_STATUS=$(limactl list --json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
# Handle both single VM object and array of VMs
if isinstance(data, dict) and 'name' in data:
    # Single VM object
    if data.get('name') == '$VM_NAME':
        print(data.get('status', 'unknown'))
else:
    # Array of VMs
    items = data if isinstance(data, list) else data.get('items', [])
    for i in items:
        if i.get('name') == '$VM_NAME':
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
    | grep -oE '(Port=|"-p ")[0-9]+' | grep -oE '[0-9]+' | head -1)

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
    cp '$PROJECT_ROOT/target/release/libpam_bellwether_gate.so'  /usr/lib64/security/pam_bellwether_gate.so
    cp '$PROJECT_ROOT/target/release/libpam_bellwether_stamp.so' /usr/lib64/security/pam_bellwether_stamp.so
    install -d -m 0700 -o root -g root /run/pam-bellwether
"

# ---------------------------------------------------------------------------
# Configure PAM (timeout=30 for demo, no debug — cleaner output)
# ---------------------------------------------------------------------------
echo "Configuring PAM stack (timeout=30)..."
limactl shell "$VM_NAME" -- sudo bash -c "
cat > /etc/pam.d/sshd <<'PAM_EOF'
# Demo PAM stack — google-authenticator stands in for pam_duo
auth  [success=1 ignore=ignore default=ignore]  pam_bellwether_gate.so timeout=30
auth  requisite                                  pam_google_authenticator.so echo_verification_code
auth  required                                   pam_bellwether_stamp.so
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
# SELinux policy: allow sshd to manage google_authenticator files in home dirs
# ---------------------------------------------------------------------------
# pam_google_authenticator writes an atomic tempfile in the user's home dir
# when recording a used TOTP code. Without this, sshd_t is denied create/write
# on user_home_dir_t, causing "Failed to create tempfile" and a double-round
# auth prompt on every login.
echo "Installing SELinux policy for google_authenticator..."
limactl shell "$VM_NAME" -- sudo bash -c '
    cd /tmp
    cat > sshd_google_auth.te << '"'"'TE_EOF'"'"'
module sshd_google_auth 1.0;

require {
    type sshd_t;
    type user_home_dir_t;
    type user_home_t;
    class file { create write read open getattr setattr rename unlink };
    class dir { write add_name remove_name };
}

#============= sshd_t ==============
# Allow sshd (running pam_google_authenticator) to create and update the
# .google_authenticator file and its atomic tempfile in user home directories.
allow sshd_t user_home_dir_t:file { create write read open getattr setattr rename unlink };
allow sshd_t user_home_dir_t:dir { write add_name remove_name };
allow sshd_t user_home_t:file { create write read open getattr setattr rename unlink };
allow sshd_t user_home_t:dir { write add_name remove_name };
TE_EOF
    checkmodule -M -m -o sshd_google_auth.mod sshd_google_auth.te
    semodule_package -o sshd_google_auth.pp -m sshd_google_auth.mod
    # Remove any previous version of the module before installing
    semodule -r sshd_google_auth 2>/dev/null || true
    semodule -r sshd_google_auth2 2>/dev/null || true
    semodule -i sshd_google_auth.pp
    echo "SELinux module installed: $(semodule -l | grep sshd_google)"
'

# ---------------------------------------------------------------------------
# Restart sshd and clear tokens
# ---------------------------------------------------------------------------
echo "Restarting sshd..."
limactl shell "$VM_NAME" -- sudo bash -c '
    systemctl restart sshd
    rm -f /run/pam-bellwether/*.token /run/pam-bellwether/*.lock
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
