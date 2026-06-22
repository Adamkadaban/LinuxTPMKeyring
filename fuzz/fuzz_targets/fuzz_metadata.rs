#![no_main]

//! Fuzzes the on-disk enrollment metadata parse path with arbitrary bytes: the `serde_json`
//! deserialization of `tess_core::Metadata` plus the post-deserialize validation and blob
//! reconstruction in `tess_tpm::persist::from_metadata`. A tampered or truncated `metadata.json`
//! must always surface as a `Result::Err`, never a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(metadata) = serde_json::from_slice::<tess_core::Metadata>(data) {
        // Reaching here means arbitrary bytes parsed as well-formed metadata; the post-deserialize
        // path (version check, base64 decode, TPM2B unmarshalling) must reject them gracefully.
        let _ = tess_tpm::persist::from_metadata(&metadata);
    }
});
