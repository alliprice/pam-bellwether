use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha1::Sha1;
use std::collections::BTreeMap;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug)]
pub enum DuoError {
    Denied,
    Timeout,
    NotEnrolled,
    ConfigError(String),
    ApiError(String),       // HTTP 4xx (bad creds, etc.) - never failsafe
    TransientError(String), // HTTP 5xx, network errors - failsafe eligible
}

#[derive(Deserialize)]
struct DuoApiResponse<T> {
    stat: String,
    response: Option<T>,
    message: Option<String>,
    message_detail: Option<String>,
}

#[derive(Deserialize)]
pub struct PreauthResponse {
    pub result: String, // "auth", "allow", "deny", "enroll"
}

#[derive(Deserialize)]
pub struct AuthResponse {
    pub txid: String,
}

#[derive(Deserialize)]
pub struct AuthStatusResponse {
    pub result: Option<String>, // "allow", "deny", or absent while waiting
    pub status: Option<String>, // "pushed", "answered", etc.
    #[allow(dead_code)]
    pub waiting: Option<bool>,  // Some(true) means still polling
}

pub struct DuoClient {
    ikey: String,
    skey: String,
    host: String,
}

impl DuoClient {
    pub fn new(ikey: String, skey: String, host: String) -> Self {
        Self { ikey, skey, host }
    }

    pub fn preauth(&self, username: &str) -> Result<PreauthResponse, DuoError> {
        let params = format!("username={}", url_encode(username));
        let response: DuoApiResponse<PreauthResponse> =
            self.request("POST", "/auth/v2/preauth", &params)?;

        if response.stat != "OK" {
            return Err(DuoError::ApiError(
                response.message.unwrap_or_else(|| "API error".to_string())
            ));
        }

        response.response.ok_or_else(||
            DuoError::ApiError("Missing response field".to_string())
        )
    }

    pub fn auth_push(&self, username: &str) -> Result<String, DuoError> {
        let params = format!(
            "async=1&device=auto&factor=push&username={}",
            url_encode(username)
        );
        let response: DuoApiResponse<AuthResponse> =
            self.request("POST", "/auth/v2/auth", &params)?;

        if response.stat != "OK" {
            return Err(DuoError::ApiError(
                response.message.unwrap_or_else(|| "API error".to_string())
            ));
        }

        response.response
            .map(|r| r.txid)
            .ok_or_else(|| DuoError::ApiError("Missing txid".to_string()))
    }

    pub fn auth_status(&self, txid: &str) -> Result<AuthStatusResponse, DuoError> {
        let params = format!("txid={}", url_encode(txid));
        let response: DuoApiResponse<AuthStatusResponse> =
            self.request("GET", "/auth/v2/auth_status", &params)?;

        if response.stat != "OK" {
            return Err(DuoError::ApiError(
                response.message.unwrap_or_else(|| "API error".to_string())
            ));
        }

        response.response.ok_or_else(||
            DuoError::ApiError("Missing response field".to_string())
        )
    }

    fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        params: &str,
    ) -> Result<T, DuoError> {
        let date = rfc2822_date();
        let auth_header = self.sign_request(method, path, params, &date);

        // Use http:// for hosts with ports (test mode), https:// otherwise
        let scheme = if self.host.contains(':') { "http" } else { "https" };
        let url = if method == "GET" && !params.is_empty() {
            format!("{}://{}{}?{}", scheme, self.host, path, params)
        } else {
            format!("{}://{}{}", scheme, self.host, path)
        };

        let mut request = ureq::request(method, &url)
            .set("Authorization", &auth_header)
            .set("Date", &date);

        let response = if method == "POST" {
            request = request.set("Content-Type", "application/x-www-form-urlencoded");
            request.send_string(params)
        } else {
            request.call()
        };

        match response {
            Ok(resp) => {
                resp.into_json::<T>()
                    .map_err(|e| DuoError::TransientError(format!("JSON parse error: {}", e)))
            }
            Err(ureq::Error::Status(code, resp)) => {
                if code >= 500 {
                    Err(DuoError::TransientError(format!("HTTP {}", code)))
                } else {
                    // 4xx - API error (bad creds, etc.)
                    let body = resp.into_string().unwrap_or_else(|_| String::new());
                    Err(DuoError::ApiError(format!("HTTP {}: {}", code, body)))
                }
            }
            Err(ureq::Error::Transport(e)) => {
                Err(DuoError::TransientError(format!("Network error: {}", e)))
            }
        }
    }

    fn sign_request(&self, method: &str, path: &str, params: &str, date: &str) -> String {
        let sorted = sort_params(params);
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}",
            date, method, self.host, path, sorted
        );

        let mut mac = HmacSha1::new_from_slice(self.skey.as_bytes())
            .expect("HMAC can accept any key length");
        mac.update(canonical.as_bytes());
        let result = mac.finalize();
        let hmac_hex = hex::encode(result.into_bytes());

        let auth_string = format!("{}:{}", self.ikey, hmac_hex);
        format!("Basic {}", base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            auth_string.as_bytes()
        ))
    }
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

fn rfc2822_date() -> String {
    unsafe {
        let mut now: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) != 0 {
            return String::new();
        }

        let mut tm: libc::tm = std::mem::zeroed();
        if libc::gmtime_r(&now.tv_sec, &mut tm).is_null() {
            return String::new();
        }

        let mut buf = [0u8; 64];
        let fmt = b"%a, %d %b %Y %H:%M:%S +0000\0";
        let len = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            fmt.as_ptr() as *const libc::c_char,
            &tm,
        );

        if len == 0 {
            return String::new();
        }

        String::from_utf8_lossy(&buf[..len]).to_string()
    }
}

// Sort params for canonical request (used in signing)
fn sort_params(params: &str) -> String {
    if params.is_empty() {
        return String::new();
    }

    let mut map = BTreeMap::new();
    for pair in params.split('&') {
        if let Some(pos) = pair.find('=') {
            let key = &pair[..pos];
            let val = &pair[pos + 1..];
            map.insert(key, val);
        }
    }

    map.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode_simple() {
        assert_eq!(url_encode("hello"), "hello");
    }

    #[test]
    fn test_url_encode_space() {
        assert_eq!(url_encode("hello world"), "hello%20world");
    }

    #[test]
    fn test_url_encode_special() {
        assert_eq!(url_encode("user@example.com"), "user%40example.com");
    }

    #[test]
    fn test_url_encode_alphanumeric() {
        assert_eq!(url_encode("abc123"), "abc123");
    }

    #[test]
    fn test_sort_params_empty() {
        assert_eq!(sort_params(""), "");
    }

    #[test]
    fn test_sort_params_single() {
        assert_eq!(sort_params("foo=bar"), "foo=bar");
    }

    #[test]
    fn test_sort_params_multiple_sorted() {
        assert_eq!(sort_params("a=1&b=2&c=3"), "a=1&b=2&c=3");
    }

    #[test]
    fn test_sort_params_multiple_unsorted() {
        assert_eq!(sort_params("c=3&a=1&b=2"), "a=1&b=2&c=3");
    }

    #[test]
    fn test_sign_request_deterministic() {
        let client = DuoClient::new(
            "DITEST1234567890ABCD".to_string(),
            "testsecretkey1234567890abcdefghijklmnop".to_string(),
            "api-test.duosecurity.com".to_string(),
        );

        let date = "Tue, 21 Aug 2012 17:29:18 +0000";
        let auth = client.sign_request("POST", "/auth/v2/preauth", "username=testuser", date);

        // Just verify it produces a Basic auth header
        assert!(auth.starts_with("Basic "));
    }

    #[test]
    fn test_deserialize_preauth_response() {
        let json = r#"{"stat":"OK","response":{"result":"auth"}}"#;
        let resp: DuoApiResponse<PreauthResponse> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.stat, "OK");
        assert_eq!(resp.response.unwrap().result, "auth");
    }

    #[test]
    fn test_deserialize_auth_response() {
        let json = r#"{"stat":"OK","response":{"txid":"mock-txid-001"}}"#;
        let resp: DuoApiResponse<AuthResponse> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.stat, "OK");
        assert_eq!(resp.response.unwrap().txid, "mock-txid-001");
    }

    #[test]
    fn test_deserialize_auth_status_allow() {
        let json = r#"{"stat":"OK","response":{"result":"allow","status":"allow"}}"#;
        let resp: DuoApiResponse<AuthStatusResponse> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.stat, "OK");
        let status = resp.response.unwrap();
        assert_eq!(status.result.unwrap(), "allow");
    }

    #[test]
    fn test_deserialize_auth_status_waiting() {
        let json = r#"{"stat":"OK","response":{"status":"pushed","waiting":true}}"#;
        let resp: DuoApiResponse<AuthStatusResponse> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.stat, "OK");
        let status = resp.response.unwrap();
        assert!(status.result.is_none());
        assert_eq!(status.waiting.unwrap(), true);
    }
}
