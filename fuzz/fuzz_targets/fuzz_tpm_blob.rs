#![no_main]

//! Fuzzes the sealed pub/priv TPM2B blob parse boundary that runs *before* any tss-esapi FFI call:
//! the `Public::unmarshall` and `Private::try_from` invocations `tess_tpm::persist::from_metadata`
//! performs on base64-decoded blob bytes. These replicate those exact calls so arbitrary attacker
//! bytes hit the same parsers directly, skipping the JSON/base64 outer layer.
//!
//! A leading little-endian `u16` length splits the input into the two independently-sized slices fed
//! to the two parsers, so the fuzzer can grow the public and private regions separately. Both calls
//! must reject malformed bytes with an error, never panic.

use libfuzzer_sys::fuzz_target;
use tss_esapi::structures::{Private, Public};
use tss_esapi::traits::UnMarshall;

fuzz_target!(|data: &[u8]| {
    let (public_bytes, private_bytes) = split(data);

    let _ = Public::unmarshall(public_bytes);
    let _ = Private::try_from(private_bytes.to_vec());
});

fn split(data: &[u8]) -> (&[u8], &[u8]) {
    // Inputs too short to carry the u16 length prefix have no public blob — both regions are empty
    // rather than misattributing the partial prefix bytes to the public area.
    if data.len() < 2 {
        return (&[], &[]);
    }
    let want = u16::from_le_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    let cut = want.min(rest.len());
    rest.split_at(cut)
}
