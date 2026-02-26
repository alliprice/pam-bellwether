use libc::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use pam_bellwether_common::{ffi, flock, paths, token, config};
use pam_bellwether_common::log as pam_log;

fn stamp_inner(pamh: *mut ffi::PamHandle, argc: c_int, argv: *const *const c_char) {
    let args = unsafe { config::parse_args(argc, argv) };
    let debug = config::has_debug(&args);

    // Step 1: retrieve the lock fd from pam data. If not present, nothing to do.
    let mut data: *const c_void = std::ptr::null();
    let rc = unsafe {
        ffi::pam_get_data(
            pamh as *const ffi::PamHandle,
            config::PAM_DATA_KEY.as_ptr() as *const c_char,
            &mut data,
        )
    };

    if rc != ffi::PAM_SUCCESS || data.is_null() {
        if debug {
            pam_log::log_debug("pam_bellwether stamp: no lock fd found in pam data, skipping");
        }
        return;
    }

    let fd = data as usize as RawFd;

    // Step 2: get user and rhost so we can derive the token path.
    let user_opt = unsafe { ffi::get_pam_item(pamh, ffi::PAM_USER) };
    let rhost_opt = unsafe { ffi::get_pam_item(pamh, ffi::PAM_RHOST) };

    // Step 3: if we have both user and rhost, derive the token path and touch it.
    if let (Some(user), Some(rhost)) = (user_opt, rhost_opt) {
        if let Some(path) = paths::token_path(&user, &rhost) {
            if !token::touch_token(&path) {
                pam_log::log_info("pam_bellwether stamp: failed to touch token file");
            } else {
                // Only send "MFA verified" if this wasn't a cache hit
                // (gate sets PAM_DATA_CACHED_KEY when serving from cache)
                let mut cached_data: *const c_void = std::ptr::null();
                let cached_rc = unsafe {
                    ffi::pam_get_data(
                        pamh as *const ffi::PamHandle,
                        config::PAM_DATA_CACHED_KEY.as_ptr() as *const c_char,
                        &mut cached_data,
                    )
                };
                if cached_rc != ffi::PAM_SUCCESS || cached_data.is_null() {
                    unsafe { ffi::send_info(pamh, "MFA verified") };
                }
                if debug {
                    pam_log::log_debug(&format!(
                        "pam_bellwether: stamped token for {}@{}",
                        user, rhost
                    ));
                }
            }
        } else {
            pam_log::log_info("pam_bellwether stamp: could not derive token path");
        }
    } else {
        pam_log::log_info("pam_bellwether stamp: missing user or rhost, cannot touch token");
    }

    // Step 4: always unlock the fd (gate's cleanup closes it at pam_end time).
    flock::unlock(fd);
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut ffi::PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    stamp_inner(pamh, argc, argv);
    // Always return PAM_SUCCESS — MFA already succeeded; stamp failure just
    // means the cache won't be refreshed, but the user IS authenticated.
    ffi::PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut ffi::PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    ffi::PAM_SUCCESS
}
