use libc::{self, c_char, c_int, c_void};

/// Opaque PAM handle
pub enum PamHandle {}

// PAM constants
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_IGNORE: c_int = 25;
pub const PAM_USER: c_int = 2;  // PAM_ITEM for username
pub const PAM_RHOST: c_int = 4; // PAM_ITEM for remote host

// PAM cleanup function type
pub type PamCleanupFn = unsafe extern "C" fn(
    pamh: *mut PamHandle,
    data: *mut c_void,
    error_status: c_int,
);

#[link(name = "pam")]
extern "C" {
    pub fn pam_get_item(
        pamh: *mut PamHandle,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    pub fn pam_set_data(
        pamh: *mut PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: PamCleanupFn,
    ) -> c_int;

    pub fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;

}

// PAM conversation types
pub const PAM_CONV: c_int = 5; // PAM_ITEM type for conversation struct
pub const PAM_TEXT_INFO: c_int = 4;

#[repr(C)]
pub struct PamMessage {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

#[repr(C)]
pub struct PamResponse {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

pub type PamConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
pub struct PamConv {
    pub conv: Option<PamConvFn>,
    pub appdata_ptr: *mut c_void,
}

/// Safe wrapper to get a PAM item as a &str
///
/// # Safety
/// pamh must be a valid PAM handle from a PAM callback
pub unsafe fn get_pam_item(pamh: *mut PamHandle, item_type: c_int) -> Option<String> {
    let mut item: *const c_void = std::ptr::null();
    let rc = pam_get_item(pamh, item_type, &mut item);
    if rc != PAM_SUCCESS || item.is_null() {
        return None;
    }
    let cstr = std::ffi::CStr::from_ptr(item as *const c_char);
    cstr.to_str().ok().map(String::from)
}

/// Send a PAM_TEXT_INFO message to the user via the PAM conversation function.
///
/// # Safety
/// pamh must be a valid PAM handle from a PAM callback
pub unsafe fn send_info(pamh: *mut PamHandle, message: &str) {
    let msg_cstr = match std::ffi::CString::new(message) {
        Ok(s) => s,
        Err(_) => return,
    };

    let msg = PamMessage {
        msg_style: PAM_TEXT_INFO,
        msg: msg_cstr.as_ptr(),
    };
    let msg_ptr: *const PamMessage = &msg;

    let mut conv_ptr: *const c_void = std::ptr::null();
    let rc = pam_get_item(pamh, PAM_CONV, &mut conv_ptr);
    if rc != PAM_SUCCESS || conv_ptr.is_null() {
        return;
    }

    let conv = &*(conv_ptr as *const PamConv);
    let conv_fn = match conv.conv {
        Some(f) => f,
        None => return,
    };

    let mut resp: *mut PamResponse = std::ptr::null_mut();
    conv_fn(1, &msg_ptr, &mut resp, conv.appdata_ptr);
    if !resp.is_null() {
        if !(*resp).resp.is_null() {
            libc::free((*resp).resp as *mut c_void);
        }
        libc::free(resp as *mut c_void);
    }
}
