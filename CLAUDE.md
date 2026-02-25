# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Two Rust PAM modules (`pam_preauth_gate.so` and `pam_preauth_stamp.so`) that serialize concurrent SSH auth attempts per user+IP and cache successful Duo MFA for a configurable TTL. Solves the problem of Ansible's 50+ parallel connections each triggering a separate Duo push on a Rocky 9 bastion host.

## Build

```bash
cargo build --release
# target/release/libpam_preauth_gate.so
# target/release/libpam_preauth_stamp.so
sudo cp target/release/libpam_preauth_*.so /usr/lib64/security/
```

Cargo workspace with three crates: `gate/`, `stamp/`, `common/`.

## Architecture

The two modules bracket `pam_duo` in the PAM stack:

```
auth  [success=done ignore=ignore default=ignore]  pam_preauth_gate.so timeout=60
auth  required                                      pam_duo.so
auth  required                                      pam_preauth_stamp.so
```

**Gate** (before Duo): acquires a blocking flock on `/run/pam-preauth/<user>_<ip>.lock`, checks token mtime against TTL. Fresh → `PAM_SUCCESS` (skips Duo). Stale/missing → `PAM_IGNORE` (falls through to Duo). Passes lock fd to stamp via `pam_set_data`.

**Stamp** (after Duo success): retrieves lock fd via `pam_get_data`, touches the `.token` file, releases flock.

**Common**: token path derivation (`/run/pam-preauth/<user>_<ip>.{lock,token}`) and flock helpers shared between both modules.

Key invariants:
- Flock serializes all concurrent connections for the same user+IP — prevents TOCTOU races
- Token files live on tmpfs (`/run/pam-preauth/`, root:root 0700) — cleared on reboot
- TTL is configurable via PAM arg `timeout=N` (default 60s)
- Failed Duo triggers a 2-second penalty delay before releasing the lock

## Canonical Spec

`SPEC.md` is the single source of truth for design decisions, security model, and PAM stack integration. Read it before making architectural changes.
