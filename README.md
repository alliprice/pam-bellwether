# pam-bellwether

MFA is good security. But when automation opens 50 connections to a bastion and each one triggers a separate MFA prompt, people disable MFA. That's a net loss.

**Bellwether fixes this.** One connection does MFA. The rest of the flock follows.

Two small Rust PAM modules bracket your MFA module (e.g., `pam_duo.so`) in the auth stack. The first SSH connection for a given user+IP acquires a `flock(2)`, does MFA normally, and stamps a token. Every connection queued behind it sees the stamp and skips MFA. One prompt, one approve, done. Automation runs clean.

The name: a **bellwether** is the lead sheep in a flock — it wears the bell, the others follow. This code literally uses `flock(2)` to serialize the herd.

## Demo

**Act 1** — First connection does MFA. Second connection hits the cache and skips it.

![Act 1: cold cache then warm cache](demo/pam-bellwether-demo.gif)

**Act 2** — Six connections at once. One MFA prompt. Five queue behind the flock, served from cache.

![Act 2: 6 concurrent connections](demo/act2.gif)

## How it works

```
auth  [success=1 ignore=ignore auth_err=die default=ignore]  pam_bellwether_gate.so timeout=60
auth  requisite                   pam_duo.so    # or any MFA module
auth  required                    pam_bellwether_stamp.so
```

**Gate** runs before your MFA module. It acquires an exclusive flock on `/run/pam-bellwether/<user>_<ip>.lock`, serializing concurrent connections. If a fresh token exists (mtime within TTL), it returns `PAM_SUCCESS` and skips MFA. Otherwise it falls through.

**Stamp** runs after MFA succeeds. It touches the token file and releases the flock, unblocking the next connection in line.

Tokens live on tmpfs (`/run/pam-bellwether/`), cleared on reboot. TTL is configurable via the `timeout=N` PAM argument (default: 60 seconds).

## Build

```bash
cargo build --release
sudo cp target/release/libpam_bellwether_*.so /usr/lib64/security/
```

## Why this matters

MFA adoption fails when it punishes automation. A team running parallel SSH against an MFA-protected bastion will either:

1. Get flooded with 50 MFA prompts per run
2. Disable MFA on the bastion
3. Route around the bastion entirely

All three are bad. Bellwether makes MFA invisible for automation — the security policy stays enforced, and nobody has to suffer through it.
