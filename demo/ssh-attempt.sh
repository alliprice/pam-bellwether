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
SSH_OPTS+=" -o LogLevel=ERROR"

expect -c "
    log_user 0
    set timeout 30
    spawn ssh $SSH_OPTS -p $SSH_PORT testuser@127.0.0.1 {echo CONNECTED}
    send_user \"${LABEL}Connecting...\n\"
    expect {
        \"Verification code:\" {
            send_user \"${LABEL}Verification code: _\n\"
            sleep 2
            send \"${TOTP_CODE}\r\"
            expect {
                \"CONNECTED\" {
                    send_user \"\033\[32m${LABEL}MFA verified\033\[0m\n\"
                }
                timeout {
                    send_user \"\033\[31m${LABEL}Timed out after MFA\033\[0m\n\"
                    exit 1
                }
            }
        }
        \"Waiting for MFA\" {
            send_user \"\033\[33m${LABEL}Waiting for MFA to complete...\033\[0m\n\"
            expect {
                \"CONNECTED\" {
                    send_user \"\033\[36m${LABEL}Connected (cached — no MFA)\033\[0m\n\"
                }
                timeout {
                    send_user \"\033\[31m${LABEL}Timed out while waiting\033\[0m\n\"
                    exit 1
                }
            }
        }
        \"CONNECTED\" {
            send_user \"\033\[36m${LABEL}Connected (cached — no MFA)\033\[0m\n\"
        }
        timeout {
            send_user \"\033\[31m${LABEL}Timed out\033\[0m\n\"
            exit 1
        }
    }
    expect eof
    catch wait result
    exit [lindex \$result 3]
"
