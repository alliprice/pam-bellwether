use libc::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use std::time::Duration;

use pam_bellwether_common::{config, ffi, flock, log as pam_log, paths, token};
use ffi::{PamHandle, PAM_IGNORE, PAM_SUCCESS};

unsafe extern "C" fn lock_cleanup(
    _pamh: *mut PamHandle,
    data: *mut c_void,
    error_status: c_int,
) {
    let fd = data as usize as RawFd;
    if error_status != PAM_SUCCESS {
        // MFA failed or something else went wrong — apply penalty delay
        libc::sleep(2);
    }
    flock::release_lock(fd);
}

unsafe extern "C" fn noop_cleanup(
    _pamh: *mut PamHandle,
    _data: *mut c_void,
    _error_status: c_int,
) {
    // No-op — flag data is just a sentinel value, nothing to free.
}


fn gate_inner(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> Option<c_int> {
    let args = unsafe { config::parse_args(argc, argv) };
    let ttl: Duration = config::parse_ttl(&args);
    let debug = config::has_debug(&args);

    let user = unsafe { ffi::get_pam_item(pamh, ffi::PAM_USER) }?;
    let rhost = unsafe { ffi::get_pam_item(pamh, ffi::PAM_RHOST) }?;

    let lock_path = paths::lock_path(user, rhost)?;
    let token_path = paths::token_path(user, rhost)?;

    let fd = flock::open_lock(&lock_path)?;
    let immediate = flock::try_lock(fd)?;
    if !immediate {
        unsafe { ffi::send_info(pamh, "Waiting for MFA to complete in another session...") };
        pam_log::log_info(&format!(
            "pam_bellwether: gate waiting for flock ({}@{})",
            user, rhost
        ));
        if !flock::block_lock(fd) {
            unsafe { libc::close(fd) };
            return None;
        }
    }

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

    if token::token_is_fresh(&token_path, ttl) {
        pam_log::log_info(&format!(
            "pam_bellwether: cache hit for {}@{}, skipping MFA",
            user, rhost
        ));
        unsafe { ffi::send_info(pamh, "MFA cached") };
        // Signal to stamp that this was a cache hit
        unsafe {
            ffi::pam_set_data(
                pamh,
                config::PAM_DATA_CACHED_KEY.as_ptr() as *const c_char,
                1usize as *mut c_void,
                noop_cleanup,
            );
        }
        Some(PAM_SUCCESS)
    } else {
        if debug {
            pam_log::log_debug(&format!(
                "pam_bellwether: cache miss for {}@{}, falling through to MFA",
                user, rhost
            ));
        }
        Some(PAM_IGNORE)
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    gate_inner(pamh, flags, argc, argv).unwrap_or(PAM_IGNORE)
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
