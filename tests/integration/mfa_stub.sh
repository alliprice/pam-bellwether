#!/usr/bin/env bash
# MFA stub for pam_exec.so - simulates server-side MFA (like Duo autopush).
# Exits 0 (success) unless /tmp/bellwether-mfa-fail exists (failure).
# Logs to syslog so tests can verify whether the stub ran or was skipped.

logger -t mfa_stub "mfa_stub: invoked for ${PAM_USER:-unknown}"

if [[ -f /tmp/bellwether-mfa-fail ]]; then
    logger -t mfa_stub "mfa_stub: failing for ${PAM_USER:-unknown}"
    exit 1
fi

exit 0
