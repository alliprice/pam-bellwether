# pam-bellwether

PAM modules for Ansible-safe Duo MFA on a Rocky 9 bastion host.

## Problem

When Ansible opens 50+ parallel SSH connections to a bastion with Duo MFA, every connection simultaneously triggers a Duo push before the user can approve any of them. The user gets flooded, can't respond in time, and gets locked out.

## Solution

Serialize concurrent auth attempts per user+IP using a flock, then cache a successful Duo auth for a configurable window. The first connection through triggers exactly one Duo push. All queued connections behind it see the cache and skip Duo entirely.

```
Connection arrives
  → acquire /run/pam-bellwether/<user>_<ip>.lock  (blocking flock — queues concurrent connections)
  → check /run/pam-bellwether/<user>_<ip>.token   (mtime-based, configurable TTL)
    → fresh?  return PAM_SUCCESS, release lock
    → stale?  return PAM_IGNORE, release lock   (falls through to pam_duo)
After pam_duo succeeds:
  → touch /run/pam-bellwether/<user>_<ip>.token, release lock
```

## Modules

Two small Rust PAM modules compiled to `.so`:

### `pam_bellwether_gate.so`

Runs before `pam_duo` in the PAM stack.

- Gets `PAM_USER` and `PAM_RHOST` from the PAM handle
- Derives lock path: `/run/pam-bellwether/<user>_<ip>.lock`
- Acquires an exclusive flock (blocking) — concurrent connections queue here
- Checks token file mtime against TTL
- Fresh → return `PAM_SUCCESS` (skip duo, but stamp module still runs to refresh token)
- Stale → return `PAM_IGNORE` (fall through to pam_duo)
- Passes lock fd to stamp module via `pam_set_data`

### `pam_bellwether_stamp.so`

Runs after `pam_duo` in the PAM stack (only reached on Duo success).

- Retrieves lock fd from `pam_get_data`
- Touches `/run/pam-bellwether/<user>_<ip>.token`
- Releases flock

## PAM Stack (`/etc/pam.d/sshd`)

```
auth  [success=1 ignore=ignore default=ignore]  pam_bellwether_gate.so timeout=60
auth  required                                      pam_duo.so
auth  required                                      pam_bellwether_stamp.so
```

If the gate returns `PAM_SUCCESS`, the `success=1` action skips exactly one module (`pam_duo`) and lands on `pam_bellwether_stamp`, which refreshes the token. If the gate returns `PAM_IGNORE`, we fall through to `pam_duo` normally. Using `success=1` instead of `success=done` ensures stamp always runs on cache hits to refresh the token mtime.

## Token Files

- Location: `/run/pam-bellwether/` (tmpfs, cleared on reboot)
- Filename: `<username>_<ip>.token` and `<username>_<ip>.lock`
- Auth check: compare file mtime to current time, allow if within TTL
- TTL default: 60 seconds (configurable via PAM arg `timeout=N`)

## Security Notes

- Per-user-per-IP prevents one user/IP from poisoning cache for another source
- `/run/pam-bellwether/` owned root:root, mode 0700
- Token files owned root:root — user can't forge them
- Flock prevents TOCTOU race between check and write
- Reboot clears all tokens (tmpfs)
- Does not bypass Duo for new source IPs even if user recently authed elsewhere

## Error Handling — Fail Secure

**Invariant: the only path to `PAM_SUCCESS` is a verified-fresh token with a valid flock held.** Every error condition must resolve to "do Duo." The module is an optimization — if it breaks, the worst case is Duo prompts every time, never Duo prompts never.

### Gate errors → `PAM_IGNORE` (fall through to Duo)

| Condition | Outcome |
|-----------|---------|
| Can't read `PAM_USER` or `PAM_RHOST` | `PAM_IGNORE` |
| Can't create/open lock file | `PAM_IGNORE` |
| Can't acquire flock | `PAM_IGNORE` |
| Can't stat token file | `PAM_IGNORE` (treat as stale) |
| Token mtime in the future | `PAM_IGNORE` (treat as stale) |
| `pam_set_data` fails | `PAM_IGNORE` |

### Stamp errors → silent failure (next connection does Duo again)

| Condition | Outcome |
|-----------|---------|
| `pam_get_data` fails (no lock fd) | Return `PAM_SUCCESS`, don't touch token |
| Can't open/touch token file | Return `PAM_SUCCESS`, don't touch token |
| Can't release flock | Return `PAM_SUCCESS` (fd cleanup on process exit) |

Stamp always returns `PAM_SUCCESS` because it runs after Duo has already succeeded — the user is authenticated. Stamp failures just mean the cache doesn't get refreshed, so the next connection does a full Duo prompt.

## Build

```bash
cargo build --release
# produces:
#   target/release/libpam_bellwether_gate.so
#   target/release/libpam_bellwether_stamp.so
sudo cp target/release/libpam_bellwether_*.so /usr/lib64/security/
```

Workspace with two crates: `gate/` and `stamp/`, plus a shared `common/` crate for token path logic and flock helpers.

## Decisions

- **TTL**: PAM stack arg only (`timeout=60`). No per-user config file.
- **Boot setup**: Include a `tmpfiles.d` entry to create `/run/pam-bellwether/` with correct permissions.
- **Failed Duo**: Brief penalty delay (2 seconds) before releasing the lock. Slows brute force and gives Duo time to settle before the next queued connection tries.
