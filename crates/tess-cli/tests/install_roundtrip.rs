//! Install → uninstall round-trip and idempotency against a throwaway `pam.d`-style fixture.
//!
//! These exercise the public `tess_cli::install` API end-to-end (service-file edit, backup, module
//! copy) entirely inside a `tempfile::TempDir`. They never read or write the host's real
//! `/etc/pam.d` or PAM module directory — the only mention of `/etc/pam.d` in the install code is the
//! `DEFAULT_SERVICE_FILE` constant, which these tests deliberately do not use.

use std::fs;
use std::path::Path;

use tess_cli::install::{config, install, uninstall, InstallPlan};

const FIXTURE: &str = "\
session [default=1] pam_permit.so
session requisite    pam_deny.so
session required     pam_permit.so
session optional     pam_umask.so
session required     pam_unix.so
session optional     pam_gnome_keyring.so auto_start
";

fn plan_in(root: &Path) -> InstallPlan {
    let service_file = root.join("common-session");
    fs::write(&service_file, FIXTURE).unwrap();
    let module_src = root.join("libpam_tess.so");
    fs::write(&module_src, b"dummy-module").unwrap();
    let module_dir = root.join("security");
    fs::create_dir_all(&module_dir).unwrap();
    InstallPlan {
        service_file,
        module_src,
        module_dir,
    }
}

#[test]
fn round_trip_restores_original_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = plan_in(tmp.path());

    install(&plan).unwrap();
    let wired = fs::read_to_string(&plan.service_file).unwrap();
    assert!(
        wired.contains(config::SNIPPET_LINE),
        "tess line present after install"
    );
    assert!(
        config::has_block(&wired),
        "managed block present after install"
    );
    config::validate_stack(&wired).expect("wired stack is well-formed and fail-open");
    assert!(
        plan.installed_module().is_file(),
        "module copied into module dir"
    );

    uninstall(&plan).unwrap();
    let restored = fs::read_to_string(&plan.service_file).unwrap();
    assert_eq!(
        restored, FIXTURE,
        "uninstall restores the original byte-for-byte"
    );
    assert!(
        !plan.installed_module().exists(),
        "module removed on uninstall"
    );
    assert!(!plan.backup_file().exists(), "backup removed on uninstall");
}

#[test]
fn install_twice_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = plan_in(tmp.path());

    install(&plan).unwrap();
    let once = fs::read_to_string(&plan.service_file).unwrap();
    install(&plan).unwrap();
    let twice = fs::read_to_string(&plan.service_file).unwrap();

    assert_eq!(once, twice, "re-running install yields an identical file");
    assert_eq!(
        twice.matches(config::BEGIN_MARKER).count(),
        1,
        "no duplicate block"
    );
    assert_eq!(
        twice.matches(config::SNIPPET_LINE).count(),
        1,
        "no duplicate tess line"
    );
}

#[test]
fn uninstall_when_not_installed_is_a_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = plan_in(tmp.path());

    let report = uninstall(&plan).unwrap();
    assert!(!report.removed_block);
    assert_eq!(
        fs::read_to_string(&plan.service_file).unwrap(),
        FIXTURE,
        "uninstall leaves an un-wired stack untouched"
    );
}
