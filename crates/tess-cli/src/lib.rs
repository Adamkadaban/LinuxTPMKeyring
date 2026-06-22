//! Library surface of the `tess` CLI: the enrollment transaction and the readiness probes, exposed
//! so the binary and the integration tests share one implementation.

pub mod doctor;
pub mod enroll;
pub mod install;
