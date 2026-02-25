use libc::{c_char, c_int};
use std::ffi::CStr;
use std::time::Duration;

pub const DEFAULT_TTL: Duration = Duration::from_secs(60);
pub const PENALTY_DELAY: Duration = Duration::from_secs(2);
pub const PAM_DATA_KEY: &[u8] = b"pam_preauth_lock_fd\0";

/// Parse PAM module args from argc/argv into a Vec of &str.
///
/// # Safety
/// argv must point to argc valid C string pointers.
pub unsafe fn parse_args(argc: c_int, argv: *const *const c_char) -> Vec<&'static str> {
    let mut args = Vec::new();
    for i in 0..argc as isize {
        let ptr = *argv.offset(i);
        if ptr.is_null() {
            continue;
        }
        if let Ok(s) = CStr::from_ptr(ptr).to_str() {
            args.push(s);
        }
    }
    args
}

/// Extract timeout=N from args, returning the TTL as a Duration.
pub fn parse_ttl(args: &[&str]) -> Duration {
    for arg in args {
        if let Some(val) = arg.strip_prefix("timeout=") {
            if let Ok(secs) = val.parse::<u64>() {
                if secs > 0 {
                    return Duration::from_secs(secs);
                }
            }
        }
    }
    DEFAULT_TTL
}

/// Check if "debug" is present in the PAM args.
pub fn has_debug(args: &[&str]) -> bool {
    args.iter().any(|&a| a == "debug")
}
