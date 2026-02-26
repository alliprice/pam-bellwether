# pam-bellwether

PAM modules for Ansible-safe MFA on a Rocky 9 bastion host.

## Problem

When Ansible opens 50+ parallel SSH connections to a bastion with MFA, every connection simultaneously triggers an MFA prompt before the user can approve any of them. The user gets flooded, can't respond in time, and gets locked out.

The practical result: teams disable MFA on the bastion. The theoretical security of per-connection MFA prompts is irrelevant if people turn it off. The real comparison isn't "bellwether vs. perfect MFA" — it's "bellwether vs. no MFA because someone got fed up."

## Solution

Serialize concurrent auth attempts per user+IP using a flock, then cache a successful MFA auth for a configurable window. The first connection through triggers exactly one MFA prompt. All queued connections behind it see the cache and skip MFA entirely.

```
Connection arrives
  → acquire /run/pam-bellwether/<user>_<ip>.lock  (blocking flock — queues concurrent connections)
  → check /run/pam-bellwether/<user>_<ip>.token   (mtime-based, configurable TTL)
    → fresh?  return PAM_SUCCESS, release lock
    → stale?  return PAM_IGNORE, release lock   (falls through to MFA module)
After MFA module succeeds:
  → touch /run/pam-bellwether/<user>_<ip>.token, release lock
```

## Modules

Two small Rust PAM modules compiled to `.so`:

### `pam_bellwether_gate.so`

Runs before your MFA module (e.g., `pam_duo.so`) in the PAM stack.

- Gets `PAM_USER` and `PAM_RHOST` from the PAM handle
- Derives lock path: `/run/pam-bellwether/<user>_<ip>.lock`
- Acquires an exclusive flock (blocking) — concurrent connections queue here
- Checks token file mtime against TTL
- Fresh → return `PAM_SUCCESS` (skip MFA, but stamp module still runs to refresh token)
- Stale → return `PAM_IGNORE` (fall through to MFA module)
- Passes lock fd to stamp module via `pam_set_data`

### `pam_bellwether_stamp.so`

Runs after your MFA module in the PAM stack (only reached on MFA success).

- Retrieves lock fd from `pam_get_data`
- Touches `/run/pam-bellwether/<user>_<ip>.token`
- Releases flock

## PAM Stack (`/etc/pam.d/sshd`)

```
auth  [success=1 ignore=ignore default=ignore]  pam_bellwether_gate.so timeout=60
auth  required                                      pam_duo.so    # or any MFA module
auth  required                                      pam_bellwether_stamp.so
```

If the gate returns `PAM_SUCCESS`, the `success=1` action skips exactly one module (your MFA module) and lands on `pam_bellwether_stamp`, which refreshes the token. If the gate returns `PAM_IGNORE`, we fall through to the MFA module normally. Using `success=1` instead of `success=done` ensures stamp always runs on cache hits to refresh the token mtime.

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
- Does not bypass MFA for new source IPs even if user recently authed elsewhere

### Trust Assumptions

The cache trusts the same things SSH already trusts:

- **`PAM_RHOST` (source IP)**: Set by OpenSSH from the TCP peer address. Spoofing this requires hijacking a full TCP + SSH handshake, not just a SYN — the same bar SSH itself relies on for `AllowUsers user@host`, `Match Address`, and TCP wrappers. Bellwether does not lower this bar.

- **`PAM_USER` (username)**: Set by OpenSSH from the client's auth request. An attacker exploiting the cache would need the user's private key (or password), access from the same source IP, and would need to connect within the TTL window. At that point the cache is irrelevant — the attacker already authenticated and has a live SSH session from the first connection.

- **Token file integrity**: Only root can write to `/run/pam-bellwether/`. An authenticated unprivileged user cannot forge tokens. A user with root access can already do anything.

### What the TTL Window Actually Risks

During the TTL window (default 60s), the second factor is not rechecked for the same user+IP. This is functionally equivalent to provider-side session caching, but at the PAM layer. The attack scenario — stolen private key, same source IP, within the TTL — implies the attacker already has everything needed to open their own fully-authenticated session. The cache grants no access beyond what the attacker already obtained.

### Net Security Effect

Bellwether is a net increase in security because it drives MFA adoption. MFA that punishes automation gets disabled — a team that gets 50 MFA prompts per Ansible run will find a way to turn MFA off on that bastion, and then they have zero second factor. A 60-second cache window with MFA enforced is strictly better than no MFA at all. Making MFA invisible for automation keeps the security policy in place.

### Scope Limitation

These modules assume `PAM_RHOST` is a network-verified source address, which is true when the consumer is OpenSSH. Do not use these modules in PAM stacks where `PAM_RHOST` is set from client-controlled data (e.g., HTTP `X-Forwarded-For`), as the cache would be spoofable.

## Error Handling — Fail Secure

**Invariant: the only path to `PAM_SUCCESS` is a verified-fresh token with a valid flock held.** Every error condition must resolve to "do MFA." The module is an optimization — if it breaks, the worst case is MFA prompts every time, never MFA prompts never.

### Gate errors → `PAM_IGNORE` (fall through to MFA module)

| Condition | Outcome |
|-----------|---------|
| Can't read `PAM_USER` or `PAM_RHOST` | `PAM_IGNORE` |
| Can't create/open lock file | `PAM_IGNORE` |
| Can't acquire flock | `PAM_IGNORE` |
| Can't stat token file | `PAM_IGNORE` (treat as stale) |
| Token mtime in the future | `PAM_IGNORE` (treat as stale) |
| `pam_set_data` fails | `PAM_IGNORE` |

### Stamp errors → silent failure (next connection does MFA again)

| Condition | Outcome |
|-----------|---------|
| `pam_get_data` fails (no lock fd) | Return `PAM_SUCCESS`, don't touch token |
| Can't open/touch token file | Return `PAM_SUCCESS`, don't touch token |
| Can't release flock | Return `PAM_SUCCESS` (fd cleanup on process exit) |

Stamp always returns `PAM_SUCCESS` because it runs after MFA has already succeeded — the user is authenticated. Stamp failures just mean the cache doesn't get refreshed, so the next connection does a full MFA prompt.

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
- **Failed MFA**: Brief penalty delay (2 seconds) before releasing the lock. Slows brute force and gives the MFA provider time to settle before the next queued connection tries.
