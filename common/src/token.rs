use libc::{self, c_int, c_uint, O_CREAT, O_WRONLY};
use std::ffi::CString;
use std::path::Path;
use std::time::Duration;

fn get_mtime(st: &libc::stat) -> i64 {
    st.st_mtime
}

#[cfg(target_os = "linux")]
unsafe fn do_touch(fd: c_int) -> bool {
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
    ];
    libc::futimens(fd, times.as_ptr()) == 0
}

#[cfg(target_os = "macos")]
unsafe fn do_touch(fd: c_int) -> bool {
    // futimes with NULL sets both times to the current time
    libc::futimes(fd, std::ptr::null()) == 0
}

/// Check if token file exists and its mtime is within `ttl` of current time.
/// Returns false on any error (fail-secure: treat as stale → do Duo).
/// Also rejects future mtime.
pub fn token_is_fresh(path: &Path, ttl: Duration) -> bool {
    let c_path = match CString::new(path.to_str().unwrap_or("")) {
        Ok(p) => p,
        Err(_) => return false,
    };
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::stat(c_path.as_ptr(), &mut st) != 0 {
            return false;
        }
        let mut now: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) != 0 {
            return false;
        }
        let mtime = get_mtime(&st);
        let current = now.tv_sec;

        // Reject future mtime
        if mtime > current {
            return false;
        }

        let age = (current - mtime) as u64;
        age < ttl.as_secs()
    }
}

/// Touch the token file (create if needed, update mtime to now).
/// Returns true on success.
pub fn touch_token(path: &Path) -> bool {
    let c_path = match CString::new(path.to_str().unwrap_or("")) {
        Ok(p) => p,
        Err(_) => return false,
    };
    unsafe {
        let fd = libc::open(c_path.as_ptr(), O_CREAT | O_WRONLY, 0o600 as c_uint);
        if fd < 0 {
            return false;
        }
        let result = do_touch(fd);
        libc::close(fd);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // --- touch_token tests ---

    #[test]
    fn test_touch_creates_file() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let token_path = dir.path().join("token.file");
        assert!(!token_path.exists(), "file should not exist yet");
        let result = touch_token(&token_path);
        assert!(result, "touch_token should return true");
        assert!(token_path.exists(), "file should exist after touch_token");
    }

    #[test]
    fn test_touch_updates_mtime() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let token_path = dir.path().join("token.file");

        assert!(touch_token(&token_path), "first touch failed");
        let mtime_before = std::fs::metadata(&token_path)
            .expect("metadata failed")
            .modified()
            .expect("modified() failed");

        thread::sleep(Duration::from_secs(1));

        assert!(touch_token(&token_path), "second touch failed");
        let mtime_after = std::fs::metadata(&token_path)
            .expect("metadata failed")
            .modified()
            .expect("modified() failed");

        assert!(
            mtime_after > mtime_before,
            "mtime should have increased after second touch"
        );
    }

    #[test]
    fn test_touch_nonexistent_parent() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let token_path = dir.path().join("nonexistent_subdir").join("token.file");
        let result = touch_token(&token_path);
        assert!(!result, "touch_token should return false for missing parent dir");
    }

    // --- token_is_fresh tests ---

    #[test]
    fn test_fresh_missing_file() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let token_path = dir.path().join("does_not_exist.token");
        let result = token_is_fresh(&token_path, Duration::from_secs(60));
        assert!(!result, "missing file should not be fresh");
    }

    #[test]
    fn test_fresh_just_touched() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let token_path = dir.path().join("token.file");
        assert!(touch_token(&token_path), "touch failed");
        let result = token_is_fresh(&token_path, Duration::from_secs(60));
        assert!(result, "just-touched file should be fresh with 60s TTL");
    }

    #[test]
    fn test_fresh_expired() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let token_path = dir.path().join("token.file");
        assert!(touch_token(&token_path), "touch failed");
        thread::sleep(Duration::from_secs(2));
        let result = token_is_fresh(&token_path, Duration::from_secs(1));
        assert!(!result, "file touched 2s ago should not be fresh with 1s TTL");
    }

    #[test]
    fn test_fresh_future_mtime() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let token_path = dir.path().join("token.file");
        assert!(touch_token(&token_path), "initial touch failed");

        // Set mtime to 1 hour in the future using platform-specific libc calls.
        let c_path = std::ffi::CString::new(token_path.to_str().unwrap()).unwrap();
        let future_sec = unsafe {
            let mut now: libc::timespec = std::mem::zeroed();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut now);
            now.tv_sec + 3600
        };

        #[cfg(target_os = "macos")]
        unsafe {
            let times = [
                libc::timeval { tv_sec: future_sec, tv_usec: 0 },
                libc::timeval { tv_sec: future_sec, tv_usec: 0 },
            ];
            let ret = libc::utimes(c_path.as_ptr(), times.as_ptr());
            assert_eq!(ret, 0, "utimes failed to set future mtime");
        }

        #[cfg(target_os = "linux")]
        unsafe {
            let times = [
                libc::timespec { tv_sec: future_sec, tv_nsec: 0 },
                libc::timespec { tv_sec: future_sec, tv_nsec: 0 },
            ];
            let ret = libc::utimensat(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                times.as_ptr(),
                0,
            );
            assert_eq!(ret, 0, "utimensat failed to set future mtime");
        }

        let result = token_is_fresh(&token_path, Duration::from_secs(60));
        assert!(!result, "file with future mtime should not be fresh");
    }
}
