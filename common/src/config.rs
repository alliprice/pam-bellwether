use libc::{c_char, c_int};
use std::ffi::CStr;
use std::time::Duration;

pub const DEFAULT_TTL: Duration = Duration::from_secs(60);
pub const PENALTY_DELAY: Duration = Duration::from_secs(2);
pub const PAM_DATA_KEY: &[u8] = b"pam_bellwether_lock_fd\0";
pub const PAM_DATA_CACHED_KEY: &[u8] = b"pam_bellwether_cached\0";

/// Parse PAM module args from argc/argv into a Vec of &str.
///
/// # Safety
/// argv must point to argc valid C string pointers.
pub unsafe fn parse_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    let mut args = Vec::new();
    for i in 0..argc as isize {
        let ptr = *argv.offset(i);
        if ptr.is_null() {
            continue;
        }
        if let Ok(s) = CStr::from_ptr(ptr).to_str() {
            args.push(s.to_owned());
        }
    }
    args
}

/// Extract timeout=N from args, returning the TTL as a Duration.
pub fn parse_ttl<S: AsRef<str>>(args: &[S]) -> Duration {
    for arg in args {
        if let Some(val) = arg.as_ref().strip_prefix("timeout=") {
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
pub fn has_debug<S: AsRef<str>>(args: &[S]) -> bool {
    args.iter().any(|a| a.as_ref() == "debug")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ttl_default_on_empty_args() {
        assert_eq!(parse_ttl::<&str>(&[]), DEFAULT_TTL);
    }

    #[test]
    fn test_parse_ttl_explicit_value() {
        assert_eq!(parse_ttl(&["timeout=120"]), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_ttl_zero_returns_default() {
        assert_eq!(parse_ttl(&["timeout=0"]), DEFAULT_TTL);
    }

    #[test]
    fn test_parse_ttl_non_numeric_returns_default() {
        assert_eq!(parse_ttl(&["timeout=abc"]), DEFAULT_TTL);
    }

    #[test]
    fn test_parse_ttl_empty_value_returns_default() {
        assert_eq!(parse_ttl(&["timeout="]), DEFAULT_TTL);
    }

    #[test]
    fn test_parse_ttl_multiple_timeout_args() {
        assert_eq!(parse_ttl(&["timeout=30", "timeout=90"]), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_ttl_mixed_args() {
        assert_eq!(parse_ttl(&["debug", "timeout=45", "other"]), Duration::from_secs(45));
    }

    #[test]
    fn test_has_debug_empty() {
        assert_eq!(has_debug::<&str>(&[]), false);
    }

    #[test]
    fn test_has_debug_present() {
        assert_eq!(has_debug(&["debug"]), true);
    }

    #[test]
    fn test_has_debug_prefix_not_matched() {
        assert_eq!(has_debug(&["debug=foo"]), false);
    }

    #[test]
    fn test_has_debug_case_sensitive() {
        assert_eq!(has_debug(&["Debug"]), false);
    }
}
