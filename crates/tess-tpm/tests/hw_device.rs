//! `hw`-gated integration test: run the full seal/unseal core against a **real** TPM via the kernel
//! resource manager (`/dev/tpmrm0`, device TCTI). It exercises the exact same `seal`/`unseal`/
//! `persist`/lockout code the `sim` tests do — no crypto is duplicated here — and is the body of the
//! Phase 1 exit test run on the Azure vTPM.
//!
//! Off by default; built only with `--features hw` and run only where `/dev/tpmrm0` exists. When the
//! device node is absent the test skips cleanly so the feature still *compiles* on a hardware-free
//! host without ever touching a TPM. Never run this against the developer host's TPM.
//!
//! A single test drives the whole sequence on one shared device on purpose: `cargo test` runs tests
//! in parallel, but a real TPM has one global DA-lockout counter, so concurrent seal/unseal/lockout
//! tests would interfere. One serial test keeps the device state deterministic.
#![cfg(feature = "hw")]

use std::path::Path;

use tess_core::SecretBytes;
use tess_tpm::persist::{from_metadata, load, save, to_metadata};
use tess_tpm::{
    create_primary, generate_sealing_key, read_lockout_state, read_tpm_version, seal, unseal,
    Error, TctiConfig,
};

const TPM_RM_PATH: &str = "/dev/tpmrm0";

/// One temp directory for this test's persisted metadata, removed when the guard drops.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("tess-hw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn hw_seal_unseal_roundtrip_wrong_pin_and_lockout() {
    if !Path::new(TPM_RM_PATH).exists() {
        eprintln!("skipping hw test: {TPM_RM_PATH} not present (no real TPM on this host)");
        return;
    }

    let cfg = TctiConfig::DeviceManager {
        path: TPM_RM_PATH.to_string(),
    };
    let mut context = cfg
        .open_context()
        .expect("open ESAPI context against /dev/tpmrm0");

    // Sanity: the device really is a TPM 2.0.
    let version = read_tpm_version(&mut context).expect("read TPM version");
    assert_eq!(
        version.family.trim_end_matches('\0'),
        "2.0",
        "expected a TPM 2.0 family indicator, got {version:?}"
    );

    let primary = create_primary(&mut context).expect("create ECC storage primary");

    let key = generate_sealing_key(&mut context).expect("generate sealing key");
    assert_eq!(key.len(), 32);
    let pin = SecretBytes::new(b"1234".to_vec());

    // 1) Round-trip: the correct PIN unseals the exact bytes that were sealed.
    let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");
    let recovered = unseal(&mut context, primary.key_handle, &sealed, &pin).expect("unseal");
    assert_eq!(
        recovered.as_slice(),
        key.as_slice(),
        "unseal must return the exact sealed key on real hardware"
    );

    // 2) Persistence survives a simulated reboot on real hardware: persist, re-derive the
    //    deterministic primary, reload, and unseal again.
    let tmp = TempDir::new();
    let path = tmp.path("metadata.json");
    save(&to_metadata(&sealed).expect("to_metadata"), &path).expect("save");
    let reloaded = from_metadata(&load(&path).expect("load")).expect("from_metadata");
    context
        .flush_context(primary.key_handle.into())
        .expect("flush original primary");
    let primary = create_primary(&mut context).expect("re-derive primary");
    let recovered =
        unseal(&mut context, primary.key_handle, &reloaded, &pin).expect("unseal reloaded object");
    assert_eq!(recovered.as_slice(), key.as_slice());

    // 3) Wrong PIN fails cleanly as Error::WrongPin and ticks the DA counter up (anti-hammering).
    let wrong = SecretBytes::new(b"0000".to_vec());
    let before = read_lockout_state(&mut context).expect("read lockout state");
    let err = unseal(&mut context, primary.key_handle, &sealed, &wrong)
        .expect_err("wrong PIN must not unseal");
    assert!(
        matches!(err, Error::WrongPin),
        "wrong PIN must map to Error::WrongPin, got {err:?}"
    );
    if before.max_auth_fail == 0 {
        eprintln!(
            "DA lockout disabled on this TPM (max_auth_fail=0); skipping counter/lockout asserts"
        );
        context
            .flush_context(primary.key_handle.into())
            .expect("flush primary");
        return;
    }
    let after = read_lockout_state(&mut context).expect("read lockout state");
    assert_eq!(
        after.counter,
        before.counter.saturating_add(1),
        "a wrong PIN must increment the DA lockout counter on real hardware"
    );

    // 4) Hammer wrong PINs until the TPM stops reporting WrongPin and reports a distinct Lockout.
    //    Skip if the configured threshold is too high for a bounded loop on this device.
    if after.max_auth_fail > 64 {
        eprintln!(
            "max_auth_fail={} too high for a bounded hardware lockout loop; skipping",
            after.max_auth_fail
        );
        context
            .flush_context(primary.key_handle.into())
            .expect("flush primary");
        return;
    }
    let cap = after.max_auth_fail.saturating_add(5);
    let mut saw_lockout = false;
    for _ in 0..cap {
        match unseal(&mut context, primary.key_handle, &sealed, &wrong) {
            Err(Error::WrongPin) => {}
            Err(Error::Lockout) => {
                saw_lockout = true;
                break;
            }
            other => panic!("unexpected result while hammering wrong PINs: {other:?}"),
        }
    }
    assert!(
        saw_lockout,
        "after max_auth_fail wrong PINs a real TPM must surface a distinct Error::Lockout"
    );
    assert!(
        read_lockout_state(&mut context)
            .expect("read lockout state")
            .is_locked_out(),
        "lockout state must report locked out after hammering"
    );

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}
