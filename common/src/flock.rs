use libc::{self, c_uint, LOCK_EX, LOCK_UN, O_CREAT, O_RDWR};
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;

/// Open the lock file and acquire an exclusive blocking flock.
/// Returns the fd on success, None on any error.
pub fn acquire_lock(path: &Path) -> Option<RawFd> {
    let c_path = CString::new(path.to_str()?).ok()?;
    let fd = unsafe { libc::open(c_path.as_ptr(), O_CREAT | O_RDWR, 0o600 as c_uint) };
    if fd < 0 {
        return None;
    }
    let rc = unsafe { libc::flock(fd, LOCK_EX) };
    if rc != 0 {
        unsafe { libc::close(fd) };
        return None;
    }
    Some(fd)
}

/// Release flock and close the fd. Used by gate cleanup.
pub fn release_lock(fd: RawFd) {
    unsafe {
        libc::flock(fd, LOCK_UN);
        libc::close(fd);
    }
}

/// Release flock only (no close). Used by stamp — gate cleanup handles close.
pub fn unlock(fd: RawFd) {
    unsafe {
        libc::flock(fd, LOCK_UN);
    }
}
