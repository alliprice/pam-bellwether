use libc::{c_char, c_int, c_void};

/// Opaque PAM handle
pub enum PamHandle {}

// PAM constants
pub const PAM_SUCCESS: c_int = 0;
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

/// Safe wrapper to get a PAM item as a &str
///
/// # Safety
/// pamh must be a valid PAM handle from a PAM callback
pub unsafe fn get_pam_item(pamh: *mut PamHandle, item_type: c_int) -> Option<&'static str> {
    let mut item: *const c_void = std::ptr::null();
    let rc = pam_get_item(pamh, item_type, &mut item);
    if rc != PAM_SUCCESS || item.is_null() {
        return None;
    }
    let cstr = std::ffi::CStr::from_ptr(item as *const c_char);
    cstr.to_str().ok()
}
