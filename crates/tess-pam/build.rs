fn main() {
    // The module resolves the `pam_*` C symbols from the host's libpam at load time. Linking it
    // here also lets the rlib's unit and integration test binaries resolve those symbols at link
    // time, so the safe FFI wrappers are exercised by `cargo test` without a live PAM stack.
    println!("cargo:rustc-link-lib=dylib=pam");
}
