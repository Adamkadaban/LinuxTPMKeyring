#![no_main]

//! Fuzzes our interpretation of an untrusted, attacker-influenced serialized artifact.
//!
//! Target choice: the genuine D-Bus reply surfaces in `tess-keyring`/`tess-fprint` are too thin to
//! fuzz meaningfully — `tess_fprint`'s fprintd `VerifyStatus` interpretation is a fixed four-arm
//! string match over a token and `tess_keyring`'s only reply decode is a single `Locked` boolean —
//! neither parses variable-length attacker bytes nor can panic. Per the deliverable's fallback, this
//! harness instead exercises the strongest available untrusted-input parser: the recovery blob
//! reload path. `recovery.json` is an on-disk, attacker-tamperable artifact, and `unwrap_key` runs
//! the most parsing logic on those bytes — `serde_json` deserialization, base64 decoding with
//! allocation-bounding length checks, and an XChaCha20-Poly1305 AEAD open. The grouped-hex
//! `recovery::decode` (the user-typed recovery secret parser) is fuzzed alongside it. All paths must
//! reject malformed input with an error, never a panic.

use libfuzzer_sys::fuzz_target;
use tess_cli::enroll::recovery::{decode, unwrap_key, RecoveryBlob};
use tess_core::SecretBytes;

fuzz_target!(|data: &[u8]| {
    if let Ok(blob) = serde_json::from_slice::<RecoveryBlob>(data) {
        // A fixed, non-secret key: the harness fuzzes the parse/AEAD reject path, not key
        // confidentiality. Allocated only on a successful parse — the common reject path stays cheap.
        let recovery = SecretBytes::new(vec![0x42u8; 32]);
        let _ = unwrap_key(&blob, &recovery);
    }

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = decode(text);
    }
});
