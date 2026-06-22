//! Read-only TPM identity properties for diagnostics (`tess doctor`). No authorization, no session,
//! no secret material — just `TPM2_GetCapability` on fixed-property tags.

use tss_esapi::constants::PropertyTag;
use tss_esapi::Context;

use crate::esapi::Result;
use crate::lockout::read_property;

/// The TPM's reported spec family and revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmVersion {
    /// `TPM2_PT_FAMILY_INDICATOR` decoded to its ASCII family string, e.g. `"2.0"`.
    pub family: String,
    /// `TPM2_PT_REVISION`: the spec revision times 100 (e.g. `138` for revision 1.38).
    pub spec_revision: u32,
}

/// Read the TPM spec family and revision via `TPM2_GetCapability`. Read-only, needs no session.
pub fn read_tpm_version(context: &mut Context) -> Result<TpmVersion> {
    let family_raw = read_property(context, PropertyTag::FamilyIndicator)?;
    let spec_revision = read_property(context, PropertyTag::Revision)?;
    Ok(TpmVersion {
        family: decode_family_indicator(family_raw),
        spec_revision,
    })
}

/// The family indicator packs up to four ASCII bytes (big-endian), NUL-padded — `"2.0\0"` on a
/// TPM 2.0. Decode it to the printable, non-NUL bytes; if *any* non-NUL byte is non-printable, fall
/// back to the raw hex so a malformed value never yields a misleading partial string.
fn decode_family_indicator(value: u32) -> String {
    let non_nul: Vec<u8> = value
        .to_be_bytes()
        .into_iter()
        .filter(|&b| b != 0)
        .collect();
    let all_printable =
        !non_nul.is_empty() && non_nul.iter().all(|&b| b.is_ascii_graphic() || b == b' ');
    if all_printable {
        non_nul.into_iter().map(char::from).collect()
    } else {
        format!("{value:#010x}")
    }
}

impl std::fmt::Display for TpmVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TPM {} (spec rev {})", self.family, self.spec_revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_tpm_two_dot_zero_family() {
        // ASCII "2.0\0" big-endian.
        let raw = u32::from_be_bytes([b'2', b'.', b'0', 0]);
        assert_eq!(decode_family_indicator(raw), "2.0");
    }

    #[test]
    fn falls_back_to_hex_for_nonprintable_family() {
        assert_eq!(decode_family_indicator(0x0000_0001), "0x00000001");
    }

    #[test]
    fn falls_back_to_hex_for_mixed_printable_and_nonprintable() {
        // A printable prefix followed by a control byte must NOT render as the truncated prefix.
        let raw = u32::from_be_bytes([b'2', 0x01, b'.', 0]);
        assert_eq!(decode_family_indicator(raw), "0x32012e00");
    }

    #[test]
    fn version_display_is_human_readable() {
        let v = TpmVersion {
            family: "2.0".to_string(),
            spec_revision: 138,
        };
        assert_eq!(v.to_string(), "TPM 2.0 (spec rev 138)");
    }
}
