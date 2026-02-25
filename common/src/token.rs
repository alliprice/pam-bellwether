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
