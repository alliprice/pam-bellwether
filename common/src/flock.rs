use libc::{self, c_uint, LOCK_EX, LOCK_NB, LOCK_UN, O_CREAT, O_NOFOLLOW, O_RDWR};
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::Path;

/// Open the lock file and acquire an exclusive blocking flock.
/// Returns the fd on success, None on any error.
pub fn acquire_lock(path: &Path) -> Option<RawFd> {
    let c_path = CString::new(path.to_str()?).ok()?;
    let fd = unsafe { libc::open(c_path.as_ptr(), O_CREAT | O_RDWR | O_NOFOLLOW, 0o600 as c_uint) };
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

/// Open the lock file without acquiring the flock.
/// Returns the fd on success, None on any error.
pub fn open_lock(path: &Path) -> Option<RawFd> {
    let c_path = CString::new(path.to_str()?).ok()?;
    let fd = unsafe { libc::open(c_path.as_ptr(), O_CREAT | O_RDWR | O_NOFOLLOW, 0o600 as c_uint) };
    if fd < 0 {
        return None;
    }
    Some(fd)
}

/// Try to acquire exclusive lock without blocking.
/// Returns Some(true) if acquired, Some(false) if contended, None on error.
pub fn try_lock(fd: RawFd) -> Option<bool> {
    let rc = unsafe { libc::flock(fd, LOCK_EX | LOCK_NB) };
    if rc == 0 {
        Some(true)
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EWOULDBLOCK || errno == libc::EAGAIN {
            Some(false)
        } else {
            None
        }
    }
}

/// Block until exclusive lock is acquired. For use after try_lock returns false.
pub fn block_lock(fd: RawFd) -> bool {
    unsafe { libc::flock(fd, LOCK_EX) == 0 }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::sync::mpsc;

    #[test]
    fn test_acquire_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join("test.lock");

        let fd = acquire_lock(&lock_path).expect("acquire_lock should succeed");
        assert!(fd >= 0, "fd should be non-negative");
        assert!(lock_path.exists(), "lock file should exist after acquire");

        release_lock(fd);
    }

    #[test]
    fn test_acquire_nonexistent_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join("nonexistent_subdir").join("test.lock");

        let result = acquire_lock(&lock_path);
        assert!(result.is_none(), "acquire_lock should return None for non-existent parent dir");
    }

    #[test]
    fn test_release_closes_fd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join("test.lock");

        let fd = acquire_lock(&lock_path).expect("acquire_lock should succeed");
        release_lock(fd);

        // After release_lock, the fd should be closed (EBADF)
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, -1, "flock on closed fd should return -1 (EBADF)");
    }

    #[test]
    fn test_unlock_keeps_fd_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path = dir.path().join("test.lock");

        let fd = acquire_lock(&lock_path).expect("acquire_lock should succeed");
        unlock(fd);

        // After unlock (no close), the fd should still be valid
        // Re-acquiring the lock on the same fd should succeed since the lock was released
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "flock on still-open fd should succeed after unlock");

        // Clean up manually
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_concurrent_lock_contention() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock_path: PathBuf = dir.path().join("contention.lock");

        let barrier = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel::<&'static str>();

        let path1 = lock_path.clone();
        let barrier1 = Arc::clone(&barrier);
        let tx1 = tx.clone();

        let thread1 = std::thread::spawn(move || {
            let fd = acquire_lock(&path1).expect("thread1: acquire_lock should succeed");
            tx1.send("acquired").expect("thread1: send acquired");
            // Wait for thread2 to be ready to contend
            barrier1.wait();
            // Hold the lock briefly so thread2 actually blocks
            std::thread::sleep(std::time::Duration::from_millis(100));
            release_lock(fd);
        });

        let path2 = lock_path.clone();
        let barrier2 = Arc::clone(&barrier);
        let tx2 = tx;

        let thread2 = std::thread::spawn(move || {
            // Wait until thread1 has acquired the lock
            // The "acquired" message signals thread1 holds the lock
            // We don't receive here — main thread does — so just sync via barrier
            barrier2.wait();
            // thread1 holds the lock; this will block until thread1 releases
            let fd = acquire_lock(&path2).expect("thread2: acquire_lock should succeed");
            tx2.send("acquired").expect("thread2: send acquired");
            release_lock(fd);
        });

        // Wait for thread1 to signal it holds the lock
        let msg1 = rx.recv().expect("recv thread1 acquired");
        assert_eq!(msg1, "acquired");

        thread1.join().expect("thread1 join");
        thread2.join().expect("thread2 join");

        // thread2 should also have successfully acquired and sent its message
        let msg2 = rx.recv().expect("recv thread2 acquired");
        assert_eq!(msg2, "acquired");
    }
}
