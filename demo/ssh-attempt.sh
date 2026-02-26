#!/usr/bin/env bash
set -euo pipefail

# Universal SSH attempt — handles both TOTP (cache miss) and cached (cache hit).
# Used by VHS demo.  Args: --label N (optional pane label prefix)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

TOTP_SECRET="JBSWY3DPEHPK3PXP"
TOTP_CODE=$(oathtool --totp -b "$TOTP_SECRET")

LABEL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --label) LABEL="[$2] "; shift 2 ;;
        *) shift ;;
    esac
done

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH_OPTS+=" -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive"

expect -c "
    log_user 0
    set timeout 30
    spawn ssh $SSH_OPTS -p $SSH_PORT testuser@127.0.0.1 {echo CONNECTED}
    send_user \"${LABEL}Connecting...\n\"
    expect -re \"Warning:.*\n\" {}
    log_user 1
    expect {
        \"Verification code:\" {
            sleep 2
            foreach char [split \"${TOTP_CODE}\" \"\"] {
                send \"\$char\"
                sleep 0.4
            }
            send \"\r\"
            expect {
                \"CONNECTED\" {}
                timeout { exit 1 }
            }
        }
        \"Waiting for MFA\" {
            expect {
                \"CONNECTED\" {}
                timeout { exit 1 }
            }
        }
        \"CONNECTED\" {}
        timeout { exit 1 }
    }
    expect eof
    catch wait result
    exit [lindex \$result 3]
"
