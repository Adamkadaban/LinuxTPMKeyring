//! Minimal hand-rolled PAM FFI over `libc`, plus the module entrypoints. This is the only place
//! `unsafe` is permitted in the workspace; the C ABI surface PAM exposes is small and frozen.
//!
//! Constant and signature references: `security/pam_modules.h` and `security/_pam_types.h`.

#![allow(non_camel_case_types, dead_code)]

use libc::{c_char, c_int, c_void};
use std::ffi::CStr;

use crate::gate::{GateEnv, GatePhase, HelperSpec};
use crate::helper::Watchdog;
use crate::ret;

/// Opaque PAM handle. We only ever pass the pointer back to libpam; we never dereference it.
pub enum pam_handle_t {}

// pam_get_item / pam_set_item item types.
pub const PAM_SERVICE: c_int = 1;
pub const PAM_USER: c_int = 2;
pub const PAM_TTY: c_int = 3;
pub const PAM_RHOST: c_int = 4;
pub const PAM_CONV: c_int = 5;
pub const PAM_AUTHTOK: c_int = 6;
pub const PAM_RUSER: c_int = 8;

// pam_message styles for a conversation.
pub const PAM_PROMPT_ECHO_OFF: c_int = 1;
pub const PAM_PROMPT_ECHO_ON: c_int = 2;
pub const PAM_ERROR_MSG: c_int = 3;
pub const PAM_TEXT_INFO: c_int = 4;

/// One message in a PAM conversation (module -> application).
#[repr(C)]
pub struct pam_message {
    pub msg_style: c_int,
    pub msg: *const c_char,
}

/// One response in a PAM conversation (application -> module). `resp` is heap-allocated by the
/// application and must be freed by the module.
#[repr(C)]
pub struct pam_response {
    pub resp: *mut c_char,
    pub resp_retcode: c_int,
}

/// The conversation function the application registers, used to prompt for a PIN.
#[repr(C)]
pub struct pam_conv {
    pub conv: Option<
        unsafe extern "C" fn(
            num_msg: c_int,
            msg: *const *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut c_void,
        ) -> c_int,
    >,
    pub appdata_ptr: *mut c_void,
}

/// Cleanup callback signature for [`pam_set_data`].
pub type pam_cleanup_fn =
    unsafe extern "C" fn(pamh: *mut pam_handle_t, data: *mut c_void, error_status: c_int);

unsafe extern "C" {
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    pub fn pam_set_data(
        pamh: *mut pam_handle_t,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<pam_cleanup_fn>,
    ) -> c_int;

    pub fn pam_get_data(
        pamh: *const pam_handle_t,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;

    pub fn pam_get_authtok(
        pamh: *mut pam_handle_t,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

/// Safe wrapper: read a NUL-terminated string PAM item, returning `None` if absent or not UTF-8.
fn get_string_item(pamh: *const pam_handle_t, item_type: c_int) -> Option<String> {
    if pamh.is_null() {
        return None;
    }
    let mut ptr: *const c_void = std::ptr::null();
    let rc = unsafe { pam_get_item(pamh, item_type, &mut ptr) };
    if rc != ret::PAM_SUCCESS || ptr.is_null() {
        return None;
    }
    let raw = unsafe { CStr::from_ptr(ptr as *const c_char) };
    raw.to_str().ok().map(str::to_owned)
}

/// Safe wrapper for the remote host (`PAM_RHOST`), used to detect remote sessions.
pub fn get_rhost(pamh: *const pam_handle_t) -> Option<String> {
    get_string_item(pamh, PAM_RHOST)
}

fn run_default_gate(pamh: *const pam_handle_t, phase: GatePhase) -> i32 {
    let env = GateEnv::detect(get_rhost(pamh).as_deref());
    crate::run_gate(
        phase,
        &env,
        &HelperSpec::from_env_or_default(),
        &Watchdog::default(),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    run_default_gate(pamh, GatePhase::Auth)
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // tess manages no credentials; succeed so the stack is not disturbed.
    ret::PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    run_default_gate(pamh, GatePhase::Session)
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    ret::PAM_SUCCESS
}
