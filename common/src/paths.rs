use std::path::PathBuf;

const RUN_DIR: &str = "/run/pam-preauth";

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
