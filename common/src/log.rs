use libc::{self, c_int, LOG_AUTH, LOG_DEBUG, LOG_INFO};
use std::ffi::CString;

// Ident must live for the lifetime of the log session
const IDENT: &[u8] = b"pam_preauth\0";

fn syslog(priority: c_int, msg: &str) {
    // Use "%s" format to prevent format string injection
    let fmt = match CString::new("%s") {
        Ok(f) => f,
        Err(_) => return,
    };
    let c_msg = match CString::new(msg) {
        Ok(m) => m,
        Err(_) => return,
    };
    unsafe {
        libc::openlog(IDENT.as_ptr() as *const libc::c_char, 0, LOG_AUTH);
        libc::syslog(priority, fmt.as_ptr(), c_msg.as_ptr());
        libc::closelog();
    }
}

pub fn log_info(msg: &str) {
    syslog(LOG_INFO, msg);
}

pub fn log_debug(msg: &str) {
    syslog(LOG_DEBUG, msg);
}
