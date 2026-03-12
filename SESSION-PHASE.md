# Bellwether Session-Phase Support

## Problem

Bellwether's gate and stamp modules only implement `pam_sm_authenticate` (PAM auth phase). On OpenSSH, the auth phase runs exclusively through the `keyboard-interactive` SSH authentication method. This creates a hard dependency:

```
sshd config:  AuthenticationMethods publickey,keyboard-interactive
PAM stack:    auth → gate → pam_duo → stamp
SSH protocol: pubkey (first factor) → keyboard-interactive (drives PAM auth)
```

Non-interactive SSH clients - specifically Ansible - cannot negotiate keyboard-interactive. OpenSSH's client skips it entirely when there is no TTY and no `SSH_ASKPASS` program. Ansible additionally hardcodes `-o KbdInteractiveAuthentication=no -o PreferredAuthentications=gssapi-with-mic,gssapi-keyex,hostbased,publickey`, explicitly excluding keyboard-interactive.

**Result**: Ansible cannot connect to a bastion that requires `publickey,keyboard-interactive`, even when the MFA provider (Duo with autopush) requires zero user input.

### Workarounds considered and rejected

- **Exempt automation accounts from MFA**: The community consensus. Creates a passwordless sudo backdoor that bypasses the entire security model MFA exists to enforce.
- **SSH_ASKPASS wrapper + ssh_args override**: Works (proven in testing), but requires three coordinated config changes (wrapper script, `KbdInteractiveAuthentication=yes`, `PreferredAuthentications` override) and increased timeouts. Fragile, non-obvious, and fights against Ansible's explicit design choice to disable keyboard-interactive.
- **ControlMaster priming**: Manually SSH once to create a persistent socket, then run Ansible within the persist window. Works but requires manual intervention before every automation run.
- **ForceCommand with login_duo**: Moves Duo outside PAM entirely. Breaks SCP/SFTP (ForceCommand intercepts all commands). Loses bellwether integration - no flock serialization, no cache.

All workarounds either weaken security, add operational burden, or lose bellwether's serialization guarantees.

## Root cause

OpenSSH only invokes PAM auth (`pam_sm_authenticate`) when the SSH authentication method is `password` or `keyboard-interactive`. With `AuthenticationMethods publickey`, sshd handles key verification internally and never calls PAM auth. PAM `account` and `session` phases still run regardless of auth method.

Bellwether and the MFA module (pam_duo) live in the auth phase, so they require keyboard-interactive as a transport - even though neither module actually needs interactive user input:

- **Bellwether gate**: Checks token mtime, acquires flock. No user interaction.
- **Bellwether stamp**: Touches token, releases flock. No user interaction.
- **pam_duo with autopush**: Sends push notification server-side. The "keyboard-interactive conversation" is vestigial - the client's response is ignored.

The only use of the PAM conversation function in gate/stamp is `PAM_TEXT_INFO` status messages ("MFA cached", "Waiting for MFA..."). These are informational, not interactive.

## Proposed change

Add `pam_sm_open_session` entry points to gate and stamp, so the modules can run in the PAM session phase. The internal logic (flock, token check, fail marker) is identical - only the PAM entry point changes.

### New PAM stack

```
# /etc/pam.d/sshd

# Auth - empty (pubkey handled by sshd)
auth      required    pam_permit.so

# Session - bellwether + MFA
session   [success=1 ignore=ignore auth_err=die default=ignore]  pam_bellwether_gate.so timeout=60
session   requisite   pam_duo.so
session   required    pam_bellwether_stamp.so

# (existing account, password, session lines unchanged)
```

### New sshd config

```
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
```

No keyboard-interactive. Ansible connects with just pubkey. The Duo push fires in the session phase after auth succeeds.

## Requirements

### R1: Session entry points

Gate and stamp must implement `pam_sm_open_session` (and stub `pam_sm_close_session`). The session entry points call the same internal logic as the current auth entry points. The auth entry points (`pam_sm_authenticate`) must remain functional for backward compatibility.

### R2: Conversation function is optional

Gate and stamp currently call `send_info()` which uses the PAM conversation function. In the session phase, a conversation function may or may not be available depending on the PAM consumer.

- If conversation is available: send info messages as before.
- If conversation is unavailable: log to syslog instead. Do not fail.

`send_info` must handle a missing or failed conversation gracefully (currently it ignores errors, which may already be sufficient - verify).

### R3: pam_duo compatibility in session phase

Verify that pam_duo works in the session phase. pam_duo uses the PAM conversation function to drive the Duo push (even with autopush, it sends a prompt). Two scenarios:

- **pam_duo works in session**: The conversation function is available via sshd's session PAM handle. Confirm and document.
- **pam_duo does not work in session**: It requires auth-phase conversation, or crashes/fails without it. In this case, we need an alternative Duo integration (direct API call via pam_exec or a custom module).

This is the critical unknown. Test before implementing anything else.

### R4: Flock semantics unchanged

The flock serialization, fail-marker protocol, penalty delay, and token mtime check must behave identically in the session phase. No changes to `flock.rs` or `common/` logic.

### R5: pam_set_data / pam_get_data across session modules

Gate passes the lock fd to stamp via `pam_set_data`. Verify this works across session modules in the same PAM handle. PAM data is per-handle, not per-phase, so this should work - but confirm.

### R6: Requisite behavior in session phase

The MFA module must be `requisite` in the session stack (same requirement as auth). Verify that `requisite` in the session phase stops the stack immediately on failure, preventing stamp from running and poisoning the cache.

### R7: Match block for service accounts

The itadmin MFA-exempt account currently uses an sshd Match block with `AuthenticationMethods publickey`. With the new approach, auth is always just pubkey. MFA exemption moves to PAM:

```
# Option A: pam_succeed_if to skip MFA for specific users
session  [success=2 default=ignore]  pam_succeed_if.so user = itadmin
session  [success=1 ...]             pam_bellwether_gate.so timeout=60
session  requisite                   pam_duo.so
session  required                    pam_bellwether_stamp.so
```

Or keep the sshd Match block and use a separate PAM config for the service account. Define the approach.

### R8: Test coverage

Extend the integration test suite:

- Automated SSH without keyboard-interactive (simulating Ansible's connection mode)
- Session-phase cache miss, hit, and expiry (mirror existing auth-phase tests)
- Concurrent session-phase connections (flock serialization)
- Failure propagation in session phase
- pam_duo autopush in session phase (if R3 confirms compatibility)
- Service account exemption (R7)

### R9: Backward compatibility

The modules must support both deployment modes:

- **Auth phase** (current): `AuthenticationMethods publickey,keyboard-interactive` with gate/stamp in PAM auth. For deployments that want or need keyboard-interactive.
- **Session phase** (new): `AuthenticationMethods publickey` with gate/stamp in PAM session. For deployments with non-interactive clients.

Both modes from the same compiled `.so` files. The PAM stack configuration determines which phase is used.

## Testing strategy

### What we learned from production deployment

The session-phase change exists because of a specific, reproducible failure mode discovered during production deployment of the bastion.ssh Ansible role to two Tierpoint bastions (DFW and ORD). The following is a knowledge dump of the exact failure chain, so the testing agent can reproduce it without the production infrastructure.

### The exact failure chain

1. sshd is configured with `AuthenticationMethods publickey,keyboard-interactive` and `UsePAM yes`.
2. PAM auth stack: bellwether gate -> pam_duo (requisite, autopush=yes) -> bellwether stamp.
3. Ansible runs `ssh` with these hardcoded options (visible in `-vvv` output):
   ```
   -o KbdInteractiveAuthentication=no
   -o PreferredAuthentications=gssapi-with-mic,gssapi-keyex,hostbased,publickey
   -o PasswordAuthentication=no
   ```
4. SSH client completes pubkey auth (partial success). Server says "continue with keyboard-interactive."
5. SSH client says "No more authentication methods to try" because keyboard-interactive is explicitly excluded from PreferredAuthentications and disabled via KbdInteractiveAuthentication=no.
6. Connection fails: `Permission denied (keyboard-interactive)`.
7. The PAM auth stack never executes. Bellwether gate never runs. pam_duo never runs. The failure is at the SSH protocol layer, before PAM is involved.

### The workaround that proved the concept

We proved that the underlying MFA flow works by overriding Ansible's hardcoded options:

```
# In ansible.cfg [ssh_connection]:
ssh_args = -F ssh_config -o KbdInteractiveAuthentication=yes -o PreferredAuthentications=publickey,keyboard-interactive

# ssh_executable wrapper that sets:
SSH_ASKPASS=/bin/echo        # provides empty response to keyboard-interactive prompts
SSH_ASKPASS_REQUIRE=force    # use ASKPASS even without a TTY
DISPLAY=:0                   # some SSH implementations require DISPLAY for ASKPASS
```

With this workaround, Ansible connected, Duo autopush fired (server-side, no user input needed), bellwether stamped the token, and subsequent connections within the TTL skipped MFA. The full bellwether flow worked correctly - the only problem was getting SSH to negotiate keyboard-interactive in the first place.

### What the Lima VM test environment can reproduce

The existing Lima-based test VM (tests/bastion/ in hps-ansible) runs Rocky 9 x86_64 via QEMU. The integration tests use `expect` to script keyboard-interactive SSH from inside the VM (localhost to localhost). This tests the PAM stack correctly but does NOT test the non-interactive client scenario because expect provides a pseudo-TTY.

To test the session-phase change, the test suite needs to verify that SSH connections succeed WITHOUT keyboard-interactive:

```bash
# This is what Ansible does. With auth-phase bellwether, this fails.
# With session-phase bellwether, this must succeed.
ssh -o BatchMode=yes \
    -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=publickey \
    -o StrictHostKeyChecking=no \
    -i /home/testuser/.ssh/id_ed25519 \
    testuser@127.0.0.1 whoami
```

With the current auth-phase config (`AuthenticationMethods publickey,keyboard-interactive`), this command fails immediately with `Permission denied (keyboard-interactive)`. With the session-phase config (`AuthenticationMethods publickey`), pubkey auth succeeds, then the PAM session stack fires bellwether + MFA.

### Test plan for session-phase modules

**Phase 0: pam_duo viability (gates everything else)**

Before writing any Rust code, test whether pam_duo works in the PAM session phase at all. On the Lima VM:

1. Configure sshd: `AuthenticationMethods publickey`, `KbdInteractiveAuthentication no`, `UsePAM yes`
2. Configure PAM: move `session requisite pam_duo.so` into the session stack (without bellwether for now)
3. Attempt SSH with `BatchMode=yes` and pubkey only
4. Observe: does pam_duo fire the Duo push? Does it crash? Does it fail because it can't find a conversation function?

If pam_duo fails in session, the entire approach needs rethinking. If it works, proceed.

**Do not substitute pam_google_authenticator for this testing.** Google Authenticator prompts for a verification code, which requires the conversation function to deliver the prompt AND receive the response. pam_duo with autopush is fundamentally different - it sends a push notification server-side and the "prompt" is vestigial. The Phase 0 test specifically needs to determine whether pam_duo's autopush mode works without a functional conversation (or with a degraded one). Only real pam_duo with autopush answers this question.

We have a Duo test application set up for exactly this purpose. Credentials are stored in `tests/integration/.env` (gitignored):

```
# /etc/duo/pam_duo.conf
[duo]
ikey = <from .env>
skey = <from .env>
host = <from .env>
failmode = safe
pushinfo = yes
autopush = yes
```

The test user `l-aprice` is enrolled in this Duo application. The `autopush = yes` setting is critical - it makes Duo send a push notification automatically without waiting for the user to select a method. This is the setting that makes the keyboard-interactive conversation vestigial.

To install duo_unix on Rocky 9:
```bash
# Duo repo
yum-config-manager --add-repo https://pkg.duosecurity.com/RedHat/9/x86_64
rpm --import https://duo.com/DUO-GPG-PUBLIC-KEY.asc
dnf install duo_unix
```

Note: the repo URL must be `RedHat/` not `CentOS/` for Rocky 9.

**Phase 1: Session-phase bellwether without MFA**

Test gate and stamp in the session phase with a dummy MFA module (pam_permit.so or pam_exec.so returning success):

1. **Session entry points exist**: gate.so has pam_sm_open_session symbol, stamp.so has pam_sm_open_session symbol.
2. **Cache miss**: first connection with no token file - gate returns PAM_IGNORE, falls through to MFA, stamp creates token.
3. **Cache hit**: second connection within TTL - gate returns PAM_SUCCESS, skips MFA.
4. **Cache expiry**: connection after TTL - gate returns PAM_IGNORE, MFA runs again.
5. **pam_set_data/pam_get_data**: gate passes lock fd to stamp across session modules in the same PAM handle.

**Phase 2: Non-interactive client (the Ansible scenario)**

This is the test that the current suite does NOT have:

```bash
# Must succeed with session-phase config, must fail with auth-phase config
ssh -o BatchMode=yes \
    -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -i /home/testuser/.ssh/id_ed25519 \
    testuser@127.0.0.1 whoami
```

Test matrix:
- Non-interactive client + cache miss (MFA must fire and succeed without conversation)
- Non-interactive client + cache hit (MFA skipped, gate returns SUCCESS)
- Non-interactive client + cache expiry (MFA fires again)
- Non-interactive client + 10 concurrent connections (flock serialization)
- Non-interactive client + failure propagation (leader fails, followers denied)

**Phase 3: Backward compatibility**

The same .so files must still work in the auth phase. Run the existing test suite (expect-based, keyboard-interactive) against the auth-phase PAM config with the updated modules. All existing tests must pass unchanged.

**Phase 4: Service account exemption**

Test that a service account (e.g., itadmin) with a PAM-level MFA exemption (pam_succeed_if or equivalent) can connect without triggering bellwether or MFA, while normal users still get the full session-phase MFA flow.

### Failure modes to watch for

- **pam_duo segfault in session phase**: If pam_duo assumes a conversation function exists and dereferences a null pointer. Check with `journalctl -u sshd` for SIGSEGV.
- **Session denial after auth success**: If MFA fails in the session phase, sshd has already told the client "auth succeeded." The session just... doesn't start. The client sees "Connection closed" with no explanation. This is different from the auth phase where the client sees "Permission denied." Verify that failure feedback is adequate (syslog at minimum).
- **SCP/SFTP**: Verify these work through the session-phase MFA. This was an argument against ForceCommand but should work fine with PAM session. Confirm.
- **Timeout interaction**: pam_duo waits for push approval. In the auth phase, sshd's `LoginGraceTime` limits this. In the session phase, auth is already complete - what limits the session setup time? If pam_duo blocks indefinitely waiting for a push response, the SSH session hangs. Investigate whether sshd has a session-setup timeout or if pam_duo's own timeout config handles this.

## Open questions

1. **Does pam_duo work in the session phase?** This gates the entire approach. If pam_duo requires auth-phase conversation, we need an alternative. Test this first.

2. **PAM_TEXT_INFO in session phase**: Do info messages reach the SSH client during session setup, or are they silently discarded? If discarded, syslog is the only feedback channel. Acceptable but worth documenting.

3. **Control action syntax in session**: Verify that `[success=1 ignore=ignore auth_err=die default=ignore]` works identically for session modules as it does for auth modules. PAM control actions are phase-independent in theory, but confirm.

4. **Interaction with existing session modules**: The PAM sshd config already has session lines (pam_loginuid, pam_limits, pam_selinux, etc.). Bellwether session modules must be ordered before these to ensure MFA runs before the session is fully established. A failed MFA in session phase should prevent the session from completing - verify the failure path tears down cleanly.
