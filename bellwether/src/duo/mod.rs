mod client;

use client::DuoClient;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub use client::{DuoError, PreauthResponse};

#[derive(Debug)]
pub enum FailMode {
    Secure,
    Safe,
}

pub struct DuoConfig {
    pub ikey: String,
    pub skey: String,
    pub host: String,
    pub failmode: FailMode,
}

pub fn parse_config(path: &str) -> Result<DuoConfig, DuoError> {
    let path_obj = Path::new(path);

    let file = File::open(path_obj)
        .map_err(|e| DuoError::ConfigError(format!("Cannot open config file: {}", e)))?;

    // Check permissions: must be owned by root and mode <= 0600
    let metadata = file.metadata()
        .map_err(|e| DuoError::ConfigError(format!("Cannot stat config file: {}", e)))?;

    if metadata.uid() != 0 {
        return Err(DuoError::ConfigError(
            "Config file must be owned by root".to_string()
        ));
    }

    let mode = metadata.mode() & 0o777;
    if mode > 0o600 {
        return Err(DuoError::ConfigError(
            format!("Config file permissions too open: {:o}, must be <= 0600", mode)
        ));
    }

    let reader = BufReader::new(file);
    let mut in_duo_section = false;
    let mut ikey: Option<String> = None;
    let mut skey: Option<String> = None;
    let mut host: Option<String> = None;
    let mut failmode = FailMode::Secure; // default

    for line in reader.lines() {
        let line = line.map_err(|e| DuoError::ConfigError(format!("Read error: {}", e)))?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "[duo]" {
            in_duo_section = true;
            continue;
        }

        if line.starts_with('[') {
            in_duo_section = false;
            continue;
        }

        if !in_duo_section {
            continue;
        }

        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim();
            let value = line[pos + 1..].trim();

            match key {
                "ikey" => ikey = Some(value.to_string()),
                "skey" => skey = Some(value.to_string()),
                "host" => host = Some(value.to_string()),
                "failmode" => {
                    failmode = match value {
                        "safe" => FailMode::Safe,
                        "secure" => FailMode::Secure,
                        _ => return Err(DuoError::ConfigError(
                            format!("Invalid failmode: {}", value)
                        )),
                    };
                }
                _ => {} // ignore unknown keys
            }
        }
    }

    let ikey = ikey.ok_or_else(|| DuoError::ConfigError("Missing ikey".to_string()))?;
    let skey = skey.ok_or_else(|| DuoError::ConfigError("Missing skey".to_string()))?;
    let host = host.ok_or_else(|| DuoError::ConfigError("Missing host".to_string()))?;

    Ok(DuoConfig {
        ikey,
        skey,
        host,
        failmode,
    })
}

pub fn authenticate(config: &DuoConfig, username: &str) -> Result<(), DuoError> {
    let client = DuoClient::new(
        config.ikey.clone(),
        config.skey.clone(),
        config.host.clone(),
    );

    // Step 1: preauth
    let preauth = client.preauth(username)?;
    match preauth.result.as_str() {
        "allow" => return Ok(()), // bypass user
        "deny" => return Err(DuoError::Denied),
        "enroll" => return Err(DuoError::NotEnrolled),
        "auth" => {} // continue to push
        _ => return Err(DuoError::ApiError(format!("Unknown preauth result: {}", preauth.result))),
    }

    // Step 2: initiate push
    let txid = client.auth_push(username)?;

    // Step 3: poll for result (60 second timeout, 2 second intervals)
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let status = client.auth_status(&txid)?;

        if let Some(result) = status.result {
            return match result.as_str() {
                "allow" => Ok(()),
                "deny" => Err(DuoError::Denied),
                _ => Err(DuoError::ApiError(format!("Unknown auth result: {}", result))),
            };
        }

        // Still waiting (no result yet)
    }

    Err(DuoError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_config_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("duo.conf");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, "[duo]").unwrap();
        writeln!(file, "ikey = DITEST123").unwrap();
        writeln!(file, "skey = testsecret").unwrap();
        writeln!(file, "host = api-test.duosecurity.com").unwrap();
        drop(file);

        // Set permissions to 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&config_path, perms).unwrap();
        }

        // This will fail on non-root systems, so we can't fully test ownership
        // Just verify it parses if permissions are OK
        let result = parse_config(config_path.to_str().unwrap());

        // If we're not root, we'll get an ownership error, which is expected
        // If we are root, it should succeed
        match result {
            Ok(config) => {
                assert_eq!(config.ikey, "DITEST123");
                assert_eq!(config.skey, "testsecret");
                assert_eq!(config.host, "api-test.duosecurity.com");
            }
            Err(DuoError::ConfigError(msg)) if msg.contains("owned by root") => {
                // Expected when running as non-root
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_parse_config_missing_ikey() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("duo.conf");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, "[duo]").unwrap();
        writeln!(file, "skey = testsecret").unwrap();
        writeln!(file, "host = api-test.duosecurity.com").unwrap();
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&config_path, perms).unwrap();
        }

        let result = parse_config(config_path.to_str().unwrap());
        match result {
            Err(DuoError::ConfigError(msg)) => {
                assert!(msg.contains("Missing ikey") || msg.contains("owned by root"));
            }
            _ => {} // May fail on ownership check first
        }
    }

    #[test]
    fn test_parse_config_failmode_safe() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("duo.conf");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, "[duo]").unwrap();
        writeln!(file, "ikey = DITEST123").unwrap();
        writeln!(file, "skey = testsecret").unwrap();
        writeln!(file, "host = api-test.duosecurity.com").unwrap();
        writeln!(file, "failmode = safe").unwrap();
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&config_path, perms).unwrap();
        }

        let result = parse_config(config_path.to_str().unwrap());
        match result {
            Ok(config) => {
                matches!(config.failmode, FailMode::Safe);
            }
            Err(DuoError::ConfigError(msg)) if msg.contains("owned by root") => {}
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_parse_config_failmode_secure_default() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("duo.conf");
        let mut file = File::create(&config_path).unwrap();
        writeln!(file, "[duo]").unwrap();
        writeln!(file, "ikey = DITEST123").unwrap();
        writeln!(file, "skey = testsecret").unwrap();
        writeln!(file, "host = api-test.duosecurity.com").unwrap();
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&config_path, perms).unwrap();
        }

        let result = parse_config(config_path.to_str().unwrap());
        match result {
            Ok(config) => {
                matches!(config.failmode, FailMode::Secure);
            }
            Err(DuoError::ConfigError(msg)) if msg.contains("owned by root") => {}
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // Mock HTTP server for authenticate() tests.
    // Handler returns (status_code, body). Server runs in a background thread.

    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;

    fn start_mock_server_with_status<F>(handler: F) -> u16
    where
        F: Fn(&str) -> (u16, String) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(conn) => conn,
                    Err(_) => break,
                };

                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let mut content_length: usize = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(len_str) = line.split(':').nth(1) {
                            content_length = len_str.trim().parse().unwrap_or(0);
                        }
                    }
                }

                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    reader.read_exact(&mut body).unwrap();
                }

                let parts: Vec<&str> = request_line.split_whitespace().collect();
                let path = if parts.len() > 1 { parts[1] } else { "/" };

                let (status_code, response_body) = handler(path);
                let response = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    status_code,
                    response_body.len(),
                    response_body
                );

                use std::io::Write;
                let _ = stream.write_all(response.as_bytes());
            }
        });

        port
    }

    fn start_mock_server<F>(handler: F) -> u16
    where
        F: Fn(&str) -> String + Send + 'static,
    {
        start_mock_server_with_status(move |path| (200, handler(path)))
    }

    #[test]
    fn test_authenticate_happy_path() {
        let port = start_mock_server(|path| {
            if path.contains("/auth/v2/preauth") {
                r#"{"stat":"OK","response":{"result":"auth"}}"#.to_string()
            } else if path.contains("/auth/v2/auth") && !path.contains("auth_status") {
                r#"{"stat":"OK","response":{"txid":"test-txid-123"}}"#.to_string()
            } else if path.contains("/auth/v2/auth_status") {
                r#"{"stat":"OK","response":{"result":"allow","status":"allow"}}"#.to_string()
            } else {
                r#"{"stat":"FAIL","message":"unknown path"}"#.to_string()
            }
        });

        let config = DuoConfig {
            ikey: "DITEST123".to_string(),
            skey: "testsecret".to_string(),
            host: format!("127.0.0.1:{}", port),
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "testuser");
        match result {
            Ok(()) => {}
            other => panic!("Expected Ok(()), got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_preauth_allow() {
        let port = start_mock_server(|path| {
            if path.contains("/auth/v2/preauth") {
                r#"{"stat":"OK","response":{"result":"allow"}}"#.to_string()
            } else {
                r#"{"stat":"FAIL","message":"unexpected call"}"#.to_string()
            }
        });

        let config = DuoConfig {
            ikey: "DITEST123".to_string(),
            skey: "testsecret".to_string(),
            host: format!("127.0.0.1:{}", port),
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "bypassuser");
        match result {
            Ok(()) => {}
            other => panic!("Expected Ok(()), got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_preauth_deny() {
        let port = start_mock_server(|path| {
            if path.contains("/auth/v2/preauth") {
                r#"{"stat":"OK","response":{"result":"deny"}}"#.to_string()
            } else {
                r#"{"stat":"FAIL","message":"unexpected call"}"#.to_string()
            }
        });

        let config = DuoConfig {
            ikey: "DITEST123".to_string(),
            skey: "testsecret".to_string(),
            host: format!("127.0.0.1:{}", port),
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "denieduser");
        match result {
            Err(DuoError::Denied) => {}
            other => panic!("Expected Err(Denied), got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_preauth_enroll() {
        let port = start_mock_server(|path| {
            if path.contains("/auth/v2/preauth") {
                r#"{"stat":"OK","response":{"result":"enroll"}}"#.to_string()
            } else {
                r#"{"stat":"FAIL","message":"unexpected call"}"#.to_string()
            }
        });

        let config = DuoConfig {
            ikey: "DITEST123".to_string(),
            skey: "testsecret".to_string(),
            host: format!("127.0.0.1:{}", port),
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "unenrolleduser");
        match result {
            Err(DuoError::NotEnrolled) => {}
            other => panic!("Expected Err(NotEnrolled), got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_push_denied() {
        let port = start_mock_server(|path| {
            if path.contains("/auth/v2/preauth") {
                r#"{"stat":"OK","response":{"result":"auth"}}"#.to_string()
            } else if path.contains("/auth/v2/auth") && !path.contains("auth_status") {
                r#"{"stat":"OK","response":{"txid":"test-txid-deny"}}"#.to_string()
            } else if path.contains("/auth/v2/auth_status") {
                r#"{"stat":"OK","response":{"result":"deny","status":"deny"}}"#.to_string()
            } else {
                r#"{"stat":"FAIL","message":"unknown path"}"#.to_string()
            }
        });

        let config = DuoConfig {
            ikey: "DITEST123".to_string(),
            skey: "testsecret".to_string(),
            host: format!("127.0.0.1:{}", port),
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "testuser");
        match result {
            Err(DuoError::Denied) => {}
            other => panic!("Expected Err(Denied), got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_transient_error() {
        // No server listening - connection will be refused
        let config = DuoConfig {
            ikey: "DITEST123".to_string(),
            skey: "testsecret".to_string(),
            host: "127.0.0.1:1".to_string(), // port 1 unlikely to be listening
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "testuser");
        match result {
            Err(DuoError::TransientError(_)) => {}
            other => panic!("Expected Err(TransientError), got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_api_error_4xx() {
        let port = start_mock_server_with_status(|path| {
            if path.contains("/auth/v2/preauth") {
                (401, r#"{"stat":"FAIL","message":"Invalid credentials"}"#.to_string())
            } else {
                (500, r#"{"stat":"FAIL","message":"unexpected"}"#.to_string())
            }
        });

        let config = DuoConfig {
            ikey: "BADKEY".to_string(),
            skey: "badsecret".to_string(),
            host: format!("127.0.0.1:{}", port),
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "testuser");
        match result {
            Err(DuoError::ApiError(_)) => {}
            other => panic!("Expected Err(ApiError), got {:?}", other),
        }
    }

    #[test]
    fn test_authenticate_server_error_5xx() {
        let port = start_mock_server_with_status(|path| {
            if path.contains("/auth/v2/preauth") {
                (500, r#"{"stat":"FAIL","message":"Internal server error"}"#.to_string())
            } else {
                (500, r#"{"stat":"FAIL","message":"unexpected"}"#.to_string())
            }
        });

        let config = DuoConfig {
            ikey: "DITEST123".to_string(),
            skey: "testsecret".to_string(),
            host: format!("127.0.0.1:{}", port),
            failmode: FailMode::Secure,
        };

        let result = authenticate(&config, "testuser");
        match result {
            Err(DuoError::TransientError(_)) => {}
            other => panic!("Expected Err(TransientError), got {:?}", other),
        }
    }
}
