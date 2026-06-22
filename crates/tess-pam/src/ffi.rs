//! Minimal hand-rolled PAM FFI over `libc`, plus the module entrypoints. This is the only place
//! `unsafe` is permitted in the workspace; the C ABI surface PAM exposes is small and frozen.
//!
//! Constant and signature references: `security/pam_modules.h` and `security/_pam_types.h`.

#![allow(non_camel_case_types, dead_code)]

use libc::{c_char, c_int, c_void};
use std::ffi::CStr;

use zeroize::Zeroizing;

use crate::gate::{GateEnv, GatePhase, GateResult, HelperSpec};
use crate::helper::Watchdog;
use crate::ret;

/// Defensive cap on the PIN copied out of the PAM conversation. A real PIN is far smaller; the cap
/// only bounds the bytes handed to the helper.
const MAX_PIN_BYTES: usize = 1024;

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

/// Safe wrapper: read a NUL-terminated string PAM item, returning `None` only if absent. A non-UTF-8
/// value is lossily decoded rather than dropped, so a present-but-odd item (e.g. an exotic
/// `PAM_RHOST`) is never mistaken for absent — callers that only test emptiness then fail safe.
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
    Some(raw.to_string_lossy().into_owned())
}

/// Safe wrapper for the remote host (`PAM_RHOST`), used to detect remote sessions.
pub fn get_rhost(pamh: *const pam_handle_t) -> Option<String> {
    get_string_item(pamh, PAM_RHOST)
}

/// Obtain the PIN from the PAM conversation (`pam_get_authtok`, which returns the cached
/// `PAM_AUTHTOK` if a prior phase gathered it, else prompts via the conversation). The bytes are
/// copied into a zeroizing buffer and never logged; the returned pointer is owned by libpam and must
/// not be freed. `None` when no token is available (no conversation, or an empty entry).
fn get_pin(pamh: *mut pam_handle_t) -> Option<Zeroizing<Vec<u8>>> {
    if pamh.is_null() {
        return None;
    }
    let mut authtok: *const c_char = std::ptr::null();
    let prompt = c"tess PIN: ";
    let rc = unsafe { pam_get_authtok(pamh, PAM_AUTHTOK, &mut authtok, prompt.as_ptr()) };
    if rc != ret::PAM_SUCCESS || authtok.is_null() {
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(authtok) }.to_bytes();
    if bytes.is_empty() {
        return None;
    }
    let take = bytes.len().min(MAX_PIN_BYTES);
    Some(Zeroizing::new(bytes[..take].to_vec()))
}

/// Emit a best-effort, secret-free line to the auth-private syslog facility. A logging failure must
/// never affect login, so the result is ignored. The fixed `"%s"` format prevents any
/// format-string interpretation of `message`.
fn syslog_info(message: &CStr) {
    unsafe {
        libc::syslog(
            libc::LOG_AUTHPRIV | libc::LOG_INFO,
            c"%s".as_ptr(),
            message.as_ptr(),
        );
    }
}

/// Log the session-phase outcome without leaking the PIN, the key, or any other secret.
fn log_session_outcome(outcome: Option<GateResult>) {
    let message: &CStr = match outcome {
        None => {
            c"tess: session — no unlock gesture available (remote session or no TPM); keyring left locked"
        }
        Some(GateResult::Authorized) => c"tess: session — login keyring unlocked",
        Some(GateResult::Declined) => {
            c"tess: session — wrong PIN or unseal/unlock failed; keyring left locked"
        }
        Some(GateResult::Unavailable) => {
            c"tess: session — unlock unavailable (timeout or no PIN); keyring left locked"
        }
    };
    syslog_info(message);
}

/// Resolve the helper spec from the module arguments PAM passed into an entrypoint.
///
/// # Safety
///
/// `argc`/`argv` must be the count/array PAM passed straight into the entrypoint (see
/// [`module_args`]).
unsafe fn helper_spec(argc: c_int, argv: *const *const c_char) -> HelperSpec {
    let args = unsafe { module_args(argc, argv) };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    HelperSpec::resolve(&arg_refs)
}

/// Auth phase: tess never authenticates the user or unlocks the keyring here (that is the session
/// phase's job) — it only declines so a `[success=done default=ignore]` stack falls through to the
/// password factor, or aborts cleanly on a remote / no-TPM host. A panic must never unwind across
/// the `extern "C"` boundary, so it is caught and mapped to the fall-through code.
fn run_auth_gate(pamh: *const pam_handle_t, argc: c_int, argv: *const *const c_char) -> i32 {
    let gate = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let env = GateEnv::detect(get_rhost(pamh).as_deref());
        // SAFETY: argc/argv are the arguments PAM passed straight into the entrypoint.
        let spec = unsafe { helper_spec(argc, argv) };
        crate::run_gate(GatePhase::Auth, &env, &spec, &Watchdog::default(), None)
    }));
    gate.unwrap_or(ret::PAM_AUTHINFO_UNAVAIL)
}

/// Session phase: obtain the PIN and run the watchdog'd helper to unseal the key and unlock the
/// login keyring under the hard deadline. The session must always open, so any outcome maps to
/// `PAM_SUCCESS` — on timeout or failure the keyring just stays locked. A panic is caught and also
/// mapped to `PAM_SUCCESS` so login is never broken.
fn run_session_gate(pamh: *mut pam_handle_t, argc: c_int, argv: *const *const c_char) -> i32 {
    let gate = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let env = GateEnv::detect(get_rhost(pamh).as_deref());
        // SAFETY: argc/argv are the arguments PAM passed straight into the entrypoint.
        let spec = unsafe { helper_spec(argc, argv) };
        // Only prompt for a PIN once a gesture is known to be possible, so SSH/remote and no-TPM
        // hosts are never prompted.
        let pin = if env.aborts() { None } else { get_pin(pamh) };
        let outcome = crate::evaluate(
            &env,
            &spec,
            &Watchdog::default(),
            pin.as_ref().map(|p| p.as_slice()),
        );
        log_session_outcome(outcome);
        match outcome {
            None => ret::PAM_SUCCESS,
            Some(result) => crate::decide(GatePhase::Session, result),
        }
    }));
    gate.unwrap_or(ret::PAM_SUCCESS)
}

/// Collect the PAM module arguments (the tokens after the module path in the PAM config line) into
/// owned UTF-8 strings. This is the root-controlled configuration channel for the module.
///
/// # Safety
///
/// `argv` must be null, or point to `argc` entries each of which is null or a valid pointer to a
/// NUL-terminated C string that stays valid for the duration of the call — the contract PAM
/// guarantees for the arguments passed to `pam_sm_*`.
unsafe fn module_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    if argv.is_null() || argc <= 0 {
        return Vec::new();
    }
    let raw = std::slice::from_raw_parts(argv, argc as usize);
    raw.iter()
        .filter(|entry| !entry.is_null())
        .filter_map(|&entry| CStr::from_ptr(entry).to_str().ok())
        .map(str::to_owned)
        .collect()
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    run_auth_gate(pamh, argc, argv)
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
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    run_session_gate(pamh, argc, argv)
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
