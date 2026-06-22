//! Library surface of the `tess` CLI: the enrollment transaction, the post-enrollment lifecycle
//! flows, and the readiness probes, exposed so the binary and the integration tests share one
//! implementation.

pub mod doctor;
pub mod enroll;
pub mod install;
pub mod lifecycle;
pub mod session;

mod tcti;
