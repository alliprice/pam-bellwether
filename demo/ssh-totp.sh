#!/usr/bin/env bash
set -euo pipefail

# SSH to VM with TOTP — used by VHS demo for the "cache miss" act.
# Computes a live TOTP code and answers the prompt via expect.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

TOTP_SECRET="JBSWY3DPEHPK3PXP"
TOTP_CODE=$(oathtool --totp -b "$TOTP_SECRET")

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH_OPTS+=" -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive"

expect -c "
    set timeout 15
    spawn ssh $SSH_OPTS -p $SSH_PORT testuser@127.0.0.1 \
        {echo \"Connected! MFA succeeded.\"}
    expect {
        \"Verification code:\" {
            send \"${TOTP_CODE}\r\"
            expect eof
        }
        eof {}
        timeout {
            puts stderr \"Timed out waiting for prompt\"
            exit 1
        }
    }
    catch wait result
    exit [lindex \$result 3]
"
