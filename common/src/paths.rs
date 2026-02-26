use std::path::PathBuf;

const RUN_DIR: &str = "/run/pam-bellwether";

/// Sanitize input to allow only safe characters [a-zA-Z0-9._:-]
/// Returns None if empty, contains slashes, or contains null bytes.
pub fn sanitize(input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    for c in input.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | ':' | '-' => {}
            _ => return None,
        }
    }
    Some(input.to_string())
}

pub fn lock_path(user: &str, ip: &str) -> Option<PathBuf> {
    let user = sanitize(user)?;
    let ip = sanitize(ip)?;
    Some(PathBuf::from(format!("{}/{}_{}.lock", RUN_DIR, user, ip)))
}

pub fn token_path(user: &str, ip: &str) -> Option<PathBuf> {
    let user = sanitize(user)?;
    let ip = sanitize(ip)?;
    Some(PathBuf::from(format!("{}/{}_{}.token", RUN_DIR, user, ip)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // sanitize tests

    #[test]
    fn test_sanitize_empty() {
        assert_eq!(sanitize(""), None);
    }

    #[test]
    fn test_sanitize_valid_alphanum() {
        assert_eq!(sanitize("user123"), Some("user123".to_string()));
    }

    #[test]
    fn test_sanitize_slash() {
        assert_eq!(sanitize("a/b"), None);
    }

    #[test]
    fn test_sanitize_space() {
        assert_eq!(sanitize("a b"), None);
    }

    #[test]
    fn test_sanitize_null_byte() {
        assert_eq!(sanitize("a\0b"), None);
    }

    #[test]
    fn test_sanitize_unicode() {
        assert_eq!(sanitize("über"), None);
    }

    #[test]
    fn test_sanitize_ipv6_colons() {
        assert_eq!(sanitize("::1"), Some("::1".to_string()));
    }

    #[test]
    fn test_sanitize_dots_hyphens_underscores() {
        assert_eq!(
            sanitize("my-host_name.local"),
            Some("my-host_name.local".to_string())
        );
    }

    #[test]
    fn test_sanitize_ipv4() {
        assert_eq!(sanitize("192.168.1.1"), Some("192.168.1.1".to_string()));
    }

    // lock_path tests

    #[test]
    fn test_lock_path_valid() {
        assert_eq!(
            lock_path("root", "10.0.0.1"),
            Some(PathBuf::from("/run/pam-bellwether/root_10.0.0.1.lock"))
        );
    }

    #[test]
    fn test_lock_path_invalid_user() {
        assert_eq!(lock_path("ro/ot", "10.0.0.1"), None);
    }

    #[test]
    fn test_lock_path_invalid_ip() {
        assert_eq!(lock_path("root", "10.0.0 .1"), None);
    }

    // token_path tests

    #[test]
    fn test_token_path_valid() {
        assert_eq!(
            token_path("deploy", "192.168.1.5"),
            Some(PathBuf::from("/run/pam-bellwether/deploy_192.168.1.5.token"))
        );
    }

    #[test]
    fn test_token_path_invalid_user() {
        assert_eq!(token_path("", "10.0.0.1"), None);
    }
}
