use libc::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use std::time::Duration;

use pam_bellwether_common::{config, ffi, flock, log as pam_log, paths, token};
use ffi::{PamHandle, PAM_AUTH_ERR, PAM_IGNORE, PAM_SESSION_ERR, PAM_SUCCESS};

mod duo;

unsafe extern "C" fn lock_cleanup(
    _pamh: *mut PamHandle,
    data: *mut c_void,
    _error_status: c_int,
) {
    let fd = data as usize as RawFd;
    if flock::has_fail_marker(fd) {
        // MFA failed - penalty delay
        libc::sleep(2);
    }
    flock::release_lock(fd);
}

fn bellwether_inner(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> Option<c_int> {
    let args = unsafe { config::parse_args(argc, argv) };
    let ttl: Duration = config::parse_ttl(&args);
    let debug = config::has_debug(&args);

    // Extract duo_config= path from args
    let mut duo_config_path: Option<String> = None;
    for arg in &args {
        if let Some(path) = arg.strip_prefix("duo_config=") {
            duo_config_path = Some(path.to_string());
            break;
        }
    }

    let duo_config_path = match duo_config_path {
        Some(path) => path,
        None => {
            pam_log::log_info("pam_bellwether: duo_config parameter missing");
            return None;
        }
    };

    // Load Duo config
    let duo_config = match duo::parse_config(&duo_config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            pam_log::log_info(&format!("pam_bellwether: Failed to load Duo config: {:?}", e));
            return None;
        }
    };

    let user = unsafe { ffi::get_pam_item(pamh, ffi::PAM_USER) }?;
    let rhost = unsafe { ffi::get_pam_item(pamh, ffi::PAM_RHOST) }?;

    let lock_path = paths::lock_path(&user, &rhost)?;
    let token_path = paths::token_path(&user, &rhost)?;

    // Self-deadlock prevention - release any old lock from a previous auth attempt
    let mut old_data: *const c_void = std::ptr::null();
    let old_rc = unsafe {
        ffi::pam_get_data(
            pamh as *const ffi::PamHandle,
            config::PAM_DATA_KEY.as_ptr() as *const c_char,
            &mut old_data,
        )
    };
    if old_rc == PAM_SUCCESS && !old_data.is_null() {
        let old_fd = old_data as usize as RawFd;
        flock::unlock(old_fd);
    }

    let fd = flock::open_lock(&lock_path)?;
    let immediate = flock::try_lock(fd)?;
    if !immediate {
        unsafe { ffi::send_info(pamh, "Waiting for MFA to complete in another session...") };
        pam_log::log_info(&format!(
            "pam_bellwether: waiting for flock ({}@{})",
            user, rhost
        ));
        if !flock::block_lock(fd) {
            unsafe { libc::close(fd) };
            return None;
        }
        // Leader failed - kill this queued connection
        if flock::has_fail_marker(fd) {
            pam_log::log_info(&format!(
                "pam_bellwether: MFA failed in another session, denying {}@{}",
                user, rhost
            ));
            unsafe { ffi::send_info(pamh, "MFA failed in another session") };
            flock::release_lock(fd);
            return Some(PAM_AUTH_ERR);
        }
    }

    // Assume failure - marker stays unless we succeed
    flock::write_fail_marker(fd);

    // Store fd in pam_data with cleanup callback
    let rc = unsafe {
        ffi::pam_set_data(
            pamh,
            config::PAM_DATA_KEY.as_ptr() as *const c_char,
            fd as usize as *mut c_void,
            lock_cleanup,
        )
    };
    if rc != PAM_SUCCESS {
        flock::release_lock(fd);
        return None;
    }

    // Check token freshness
    if token::token_is_fresh(&token_path, ttl) {
        pam_log::log_info(&format!(
            "pam_bellwether: cache hit for {}@{}, skipping MFA",
            user, rhost
        ));
        unsafe { ffi::send_info(pamh, "MFA cached") };

        // Refresh token, clear fail marker, unlock
        token::touch_token(&token_path);
        flock::clear_fail_marker(fd);
        flock::unlock(fd);

        return Some(PAM_SUCCESS);
    }

    // Cache miss - do Duo authentication
    if debug {
        pam_log::log_debug(&format!(
            "pam_bellwether: cache miss for {}@{}, calling Duo",
            user, rhost
        ));
    }

    match duo::authenticate(&duo_config, &user) {
        Ok(()) => {
            pam_log::log_info(&format!(
                "pam_bellwether: MFA verified for {}@{}",
                user, rhost
            ));
            unsafe { ffi::send_info(pamh, "MFA verified") };

            // Success - touch token, clear fail marker, unlock
            token::touch_token(&token_path);
            flock::clear_fail_marker(fd);
            flock::unlock(fd);

            Some(PAM_SUCCESS)
        }
        Err(duo::DuoError::TransientError(msg)) => {
            // Transient error + failmode=safe -> allow
            match duo_config.failmode {
                duo::FailMode::Safe => {
                    pam_log::log_info(&format!(
                        "pam_bellwether: Duo transient error (failsafe), allowing {}@{}: {}",
                        user, rhost, msg
                    ));

                    // Failsafe - touch token, clear fail marker, unlock
                    token::touch_token(&token_path);
                    flock::clear_fail_marker(fd);
                    flock::unlock(fd);

                    Some(PAM_SUCCESS)
                }
                duo::FailMode::Secure => {
                    pam_log::log_info(&format!(
                        "pam_bellwether: Duo transient error (failsecure), denying {}@{}: {}",
                        user, rhost, msg
                    ));
                    // Fail marker stays, lock_cleanup handles penalty + release
                    Some(PAM_AUTH_ERR)
                }
            }
        }
        Err(e) => {
            pam_log::log_info(&format!(
                "pam_bellwether: MFA denied for {}@{}: {:?}",
                user, rhost, e
            ));
            // Fail marker stays, lock_cleanup handles penalty + release
            Some(PAM_AUTH_ERR)
        }
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    bellwether_inner(pamh, flags, argc, argv).unwrap_or(PAM_IGNORE)
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let rc = bellwether_inner(pamh, flags, argc, argv).unwrap_or(PAM_IGNORE);
    if rc == PAM_AUTH_ERR { PAM_SESSION_ERR } else { rc }
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}
