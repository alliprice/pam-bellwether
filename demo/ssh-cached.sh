#!/usr/bin/env bash
set -euo pipefail

# SSH to VM expecting a cache hit — used by VHS demo for the "cache hit" act.
# Expects immediate connection without a TOTP prompt.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH_OPTS+=" -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive"

expect -c "
    set timeout 15
    spawn ssh $SSH_OPTS -p $SSH_PORT testuser@127.0.0.1 \
        {echo \"Connected! No MFA — cache hit.\"}
    expect {
        \"Verification code:\" {
            puts stderr \"ERROR: Got TOTP prompt — cache miss when hit was expected\"
            exit 1
        }
        eof {}
        timeout {
            puts stderr \"Timed out waiting for connection\"
            exit 1
        }
    }
    catch wait result
    exit [lindex \$result 3]
"
