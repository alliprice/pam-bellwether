# pam-bellwether

MFA is good security. But when Ansible opens 50 connections to a bastion and each one triggers a separate Duo push, people disable MFA. That's a net loss.

**Bellwether fixes this.** One connection does MFA. The rest of the flock follows.

Two small Rust PAM modules bracket `pam_duo` in the auth stack. The first SSH connection for a given user+IP acquires a `flock(2)`, does Duo normally, and stamps a token. Every connection queued behind it sees the stamp and skips Duo. One push, one approve, done. Ansible runs clean.

The name: a **bellwether** is the lead sheep in a flock — it wears the bell, the others follow. This code literally uses `flock(2)` to serialize the herd.

## How it works

```
auth  [success=1 default=ignore]  pam_bellwether_gate.so timeout=60
auth  required                    pam_duo.so
auth  required                    pam_bellwether_stamp.so
```

**Gate** runs before Duo. It acquires an exclusive flock on `/run/pam-bellwether/<user>_<ip>.lock`, serializing concurrent connections. If a fresh token exists (mtime within TTL), it returns `PAM_SUCCESS` and skips Duo. Otherwise it falls through.

**Stamp** runs after Duo succeeds. It touches the token file and releases the flock, unblocking the next connection in line.

Tokens live on tmpfs (`/run/pam-bellwether/`), cleared on reboot. TTL is configurable via the `timeout=N` PAM argument (default: 60 seconds).

## Build

```bash
cargo build --release
sudo cp target/release/libpam_bellwether_*.so /usr/lib64/security/
```

## Why this matters

MFA adoption fails when it punishes automation. A team running Ansible against a Duo-protected bastion will either:

1. Get flooded with 50 push notifications per playbook run
2. Disable MFA on the bastion
3. Route around the bastion entirely

All three are bad. Bellwether makes MFA invisible for automation — the security policy stays enforced, and nobody has to suffer through it.
