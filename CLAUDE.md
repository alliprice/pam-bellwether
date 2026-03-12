# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Two Rust PAM modules (`pam_bellwether_gate.so` and `pam_bellwether_stamp.so`) that serialize concurrent SSH auth attempts per user+IP and cache successful MFA for a configurable TTL. Solves the problem of automation tools opening 50+ parallel connections, each triggering a separate MFA prompt on a Rocky 9 bastion host.

## Build

```bash
cargo build --release
# target/release/libpam_bellwether_gate.so
# target/release/libpam_bellwether_stamp.so
sudo cp target/release/libpam_bellwether_*.so /usr/lib64/security/
```

Cargo workspace with three crates: `gate/`, `stamp/`, `common/`.

## Architecture

The two modules bracket your MFA module (e.g., `pam_duo.so`) in the PAM stack:

```
auth  [success=1 ignore=ignore auth_err=die default=ignore]  pam_bellwether_gate.so timeout=60
auth  requisite                                     pam_duo.so    # or any MFA module
auth  required                                      pam_bellwether_stamp.so
```

**Gate** (before MFA): acquires a blocking flock on `/run/pam-bellwether/<user>_<ip>.lock`, checks token mtime against TTL. Fresh → `PAM_SUCCESS` (skips MFA). Stale/missing → `PAM_IGNORE` (falls through to MFA). Passes lock fd to stamp via `pam_set_data`.

**Stamp** (after MFA success): retrieves lock fd via `pam_get_data`, touches the `.token` file, releases flock.

**Common**: token path derivation (`/run/pam-bellwether/<user>_<ip>.{lock,token}`) and flock helpers shared between both modules.

Key invariants:
- Flock serializes all concurrent connections for the same user+IP — prevents TOCTOU races
- Token files live on tmpfs (`/run/pam-bellwether/`, root:root 0700) — cleared on reboot
- TTL is configurable via PAM arg `timeout=N` (default 60s)
- Failed MFA triggers a 2-second penalty delay before releasing the lock

## Git

This is a public repository. Do not push to origin or create pull requests without explicit permission. Commit locally on branches as usual, but treat pushing as a manual step the user controls.

## Canonical Spec

`SPEC.md` is the single source of truth for design decisions, security model, and PAM stack integration. Read it before making architectural changes.
