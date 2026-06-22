//! Pure, side-effect-free editing and validation of a `pam.d` service file.
//!
//! Everything here operates on strings: it never reads or writes a file, so it is exhaustively unit-
//! testable without touching the host. The filesystem orchestration that backs up, writes, and
//! installs the module lives in the parent module.
//!
//! The tess line is wrapped in a re-runnable marked block so [`add_block`] is idempotent (running it
//! twice yields identical output) and [`remove_block`] restores the surrounding stack byte-for-byte.
//! A hard safety invariant runs before any edit is committed: [`validate_stack`] rejects a malformed
//! stack or any `pam_tess.so` line whose control flag is not fail-open, so a tess edit can never be
//! the reason a login fails.

/// Opening marker of the tess-managed block. Matched as a full line (after trimming trailing
/// whitespace) so the block is located unambiguously.
pub const BEGIN_MARKER: &str = "# >>> tess >>>";

/// Closing marker of the tess-managed block.
pub const END_MARKER: &str = "# <<< tess <<<";

/// The PAM module file name tess installs and wires.
pub const MODULE_FILE: &str = "pam_tess.so";

/// The single session line tess adds. `optional` makes a tess failure (no TPM, slow or declined
/// unseal) ignored, so login proceeds with the keyring left locked — it can never lock a user out.
pub const SNIPPET_LINE: &str = "session optional pam_tess.so";

/// Comment lines carried inside the managed block, explaining the fail-open guarantee in place. Kept
/// as separate column-0 lines (not a `\`-continued literal) so the on-disk block provably matches the
/// snippet shown in the README and `deploy/pam/` docs.
const BLOCK_COMMENT_LINES: [&str; 2] = [
    "# Managed by `tess install` — remove with `tess install --uninstall`. `optional` means a tess",
    "# failure is ignored and login proceeds with the keyring left locked; it can never lock you out.",
];

/// PAM line types tess understands. A leading `-` (silently skip a missing module) is tolerated by
/// the parser but not emitted by tess.
const PAM_TYPES: [&str; 4] = ["auth", "account", "password", "session"];

/// The exact text of the tess-managed block, terminated by a trailing newline so it appends cleanly
/// after a newline-terminated stack.
pub fn block_text() -> String {
    format!(
        "{BEGIN_MARKER}\n{}\n{SNIPPET_LINE}\n{END_MARKER}\n",
        BLOCK_COMMENT_LINES.join("\n")
    )
}

/// Whether `content` already contains a tess-managed block.
pub fn has_block(content: &str) -> bool {
    marker_line_indices(content).is_some()
}

/// Insert (or refresh) the tess-managed block at the end of `content`, idempotently.
///
/// Any existing block is stripped first, then a fresh block is appended, so running this twice
/// produces identical output and never duplicates the block. The result always ends in a newline.
pub fn add_block(content: &str) -> String {
    let base = remove_block(content);
    if base.is_empty() {
        return block_text();
    }
    let mut out = base;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block_text());
    out
}

/// Remove every tess-managed block from `content`, restoring the surrounding stack.
///
/// For the realistic case — a newline-terminated stack with a single block appended by
/// [`add_block`] — this is the exact inverse of [`add_block`], so an install→uninstall round-trip
/// restores the original bytes. All blocks are stripped (not just the first), so a file that somehow
/// accumulated duplicates is fully cleaned, which is what keeps [`add_block`]'s strip-then-append
/// guarantee of exactly one block. If no block is present the input is returned unchanged.
pub fn remove_block(content: &str) -> String {
    let mut out = content.to_string();
    while let Some((begin_byte, end_byte)) = marker_byte_span(&out) {
        let mut next = String::with_capacity(out.len());
        next.push_str(&out[..begin_byte]);
        next.push_str(&out[end_byte..]);
        out = next;
    }
    out
}

/// Byte span `[start_of_begin_line, end_of_end_line_including_newline)` of the managed block, or
/// `None` if the block is absent.
fn marker_byte_span(content: &str) -> Option<(usize, usize)> {
    let mut begin: Option<usize> = None;
    let mut offset = 0usize;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']).trim_end();
        if trimmed == BEGIN_MARKER {
            // Reset to the most recent BEGIN so a later END pairs with it, never with a stray
            // earlier unmatched BEGIN — that would delete a large unintended span of the stack.
            begin = Some(offset);
        } else if trimmed == END_MARKER {
            if let Some(start) = begin {
                return Some((start, offset + line.len()));
            }
        }
        offset += line.len();
    }
    None
}

/// `(begin_line, end_line)` 0-based line indices of the managed block, or `None` if absent. Used
/// only by [`has_block`]; the editing path uses byte offsets for exact slicing.
fn marker_line_indices(content: &str) -> Option<(usize, usize)> {
    let mut begin: Option<usize> = None;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_end().trim_end_matches('\r').trim_end();
        if trimmed == BEGIN_MARKER {
            begin = Some(idx);
        } else if trimmed == END_MARKER {
            if let Some(start) = begin {
                return Some((start, idx));
            }
        }
    }
    None
}

/// An error explaining why a candidate stack was rejected before being written. Surfaced so the
/// caller aborts the edit and restores the backup rather than committing an unsafe stack.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("malformed PAM line {line}: {reason} ({content:?})")]
    Malformed {
        line: usize,
        reason: String,
        content: String,
    },
    #[error(
        "pam_tess.so on line {line} uses a control flag that is not fail-open ({control:?}); a tess \
         failure could block login"
    )]
    NotFailOpen { line: usize, control: String },
}

/// Hard safety check run before any edit is committed.
///
/// Rejects a syntactically malformed stack and — the load-bearing invariant — any `pam_tess.so`
/// line whose control flag is not fail-open. Only effective lines (non-blank, non-comment) are
/// parsed; comments and blank lines pass through untouched.
pub fn validate_stack(content: &str) -> Result<(), ValidationError> {
    for (idx, raw) in content.lines().enumerate() {
        let line = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Line-level directives (`@include common-session`, `@substack ...`) are not module lines —
        // they are common on Debian and can never be a `pam_tess.so` line, so pass them through
        // rather than rejecting them as malformed.
        if trimmed.starts_with('@') {
            continue;
        }
        let parsed = parse_line(trimmed).map_err(|reason| ValidationError::Malformed {
            line,
            reason,
            content: raw.to_string(),
        })?;
        if parsed.module_is(MODULE_FILE) && !control_is_fail_open(&parsed.control) {
            return Err(ValidationError::NotFailOpen {
                line,
                control: parsed.control,
            });
        }
    }
    Ok(())
}

/// A parsed effective PAM line: its type, control flag (a simple keyword or a `[...]` group), and
/// module path. Arguments after the module are not retained — the safety check only needs control +
/// module.
struct PamLine {
    control: String,
    module: String,
}

impl PamLine {
    /// Whether the module path is, or ends in, `name` (so both `pam_tess.so` and an absolute
    /// `/lib/.../pam_tess.so` match). A leading `-` (PAM's "don't log if the module is missing"
    /// prefix) is stripped first, so `-pam_tess.so` still matches and can't dodge the safety check.
    fn module_is(&self, name: &str) -> bool {
        let module = self.module.strip_prefix('-').unwrap_or(&self.module);
        module == name || module.rsplit('/').next() == Some(name)
    }
}

/// Parse one effective line into type / control / module. Returns the reason it is malformed on
/// failure. Handles a bracketed control group (`[success=done default=ignore]`) that contains
/// spaces.
fn parse_line(line: &str) -> Result<PamLine, String> {
    let mut rest = line.trim();
    let (ty, after_ty) = next_token(rest).ok_or_else(|| "empty line".to_string())?;
    let ty_norm = ty.strip_prefix('-').unwrap_or(ty);
    if !PAM_TYPES.contains(&ty_norm) {
        return Err(format!("unknown type {ty:?}"));
    }
    rest = after_ty.trim_start();
    let (control, after_control) = if rest.starts_with('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| "unterminated '[' control group".to_string())?;
        (&rest[..=close], &rest[close + 1..])
    } else {
        next_token(rest).ok_or_else(|| "missing control flag".to_string())?
    };
    rest = after_control.trim_start();
    let (module, _after_module) =
        next_token(rest).ok_or_else(|| "missing module path".to_string())?;
    Ok(PamLine {
        control: control.to_string(),
        module: module.to_string(),
    })
}

/// Split off the first whitespace-delimited token, returning `(token, remainder)`.
fn next_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(idx) => Some((&s[..idx], &s[idx..])),
        None => Some((s, "")),
    }
}

/// Whether a control flag is fail-open for a tess line — i.e. a tess failure can never fail the
/// login, and can never silently *grant* a login it shouldn't.
///
/// `optional` is fail-open by definition. A bracketed group is fail-open only when every return code
/// other than `success` falls through (`=ignore`) — including `default`, which must be `ignore`. The
/// `success` action may complete or count the stack (`ok`/`done`) or be ignored, but no failing or
/// declining return code may map to `ok`/`done` (that would turn a tess decline into an
/// authentication success, bypassing the password) or to `die`/`bad` (that would block login).
/// `required`, `requisite`, and `sufficient` are never fail-open for tess.
pub fn control_is_fail_open(control: &str) -> bool {
    let control = control.trim();
    if control == "optional" {
        return true;
    }
    let Some(inner) = control.strip_prefix('[').and_then(|c| c.strip_suffix(']')) else {
        return false;
    };
    let mut default_is_ignore = false;
    for pair in inner.split_whitespace() {
        let Some((key, value)) = pair.split_once('=') else {
            return false;
        };
        let key = key.trim();
        let value = value.trim();
        if key == "default" {
            if value != "ignore" {
                return false;
            }
            default_is_ignore = true;
        } else if key == "success" {
            // The happy path may complete the stack, count toward success, or be ignored.
            if !matches!(value, "ok" | "done" | "ignore") {
                return false;
            }
        } else if value != "ignore" {
            // Every other return code (errors, declines, unknown user) must fall through.
            return false;
        }
    }
    default_is_ignore
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMON_SESSION: &str = "\
session [default=1] pam_permit.so
session requisite    pam_deny.so
session required     pam_permit.so
session optional     pam_umask.so
session required     pam_unix.so
session optional     pam_gnome_keyring.so auto_start
";

    #[test]
    fn snippet_line_is_fail_open() {
        let parsed = parse_line(SNIPPET_LINE).unwrap();
        assert!(parsed.module_is(MODULE_FILE));
        assert!(control_is_fail_open(&parsed.control));
    }

    #[test]
    fn block_contains_markers_and_snippet() {
        let block = block_text();
        assert!(block.starts_with(BEGIN_MARKER));
        assert!(block.contains(SNIPPET_LINE));
        assert!(block.trim_end().ends_with(END_MARKER));
        assert!(block.ends_with('\n'));
    }

    #[test]
    fn block_lines_have_no_leading_whitespace() {
        // The on-disk block must match the column-0 snippet shown in README/deploy docs.
        for line in block_text().lines() {
            assert_eq!(
                line.trim_start(),
                line,
                "block line must start at column 0: {line:?}"
            );
        }
    }

    #[test]
    fn add_then_remove_restores_byte_for_byte() {
        let added = add_block(COMMON_SESSION);
        assert!(has_block(&added));
        assert!(added.contains(SNIPPET_LINE));
        assert_eq!(remove_block(&added), COMMON_SESSION);
    }

    #[test]
    fn add_is_idempotent() {
        let once = add_block(COMMON_SESSION);
        let twice = add_block(&once);
        assert_eq!(
            once, twice,
            "re-running install must not duplicate the block"
        );
        assert_eq!(once.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(once.matches(SNIPPET_LINE).count(), 1);
    }

    #[test]
    fn add_to_empty_then_remove_is_empty() {
        let added = add_block("");
        assert_eq!(added, block_text());
        assert_eq!(remove_block(&added), "");
    }

    #[test]
    fn add_collapses_duplicate_blocks_to_one() {
        // A file that somehow accumulated two blocks must end up with exactly one after add_block.
        let doubled = format!("{COMMON_SESSION}{}{}", block_text(), block_text());
        assert_eq!(doubled.matches(BEGIN_MARKER).count(), 2);
        let fixed = add_block(&doubled);
        assert_eq!(fixed.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(fixed.matches(SNIPPET_LINE).count(), 1);
        // Stripping all blocks restores the original stack.
        assert_eq!(remove_block(&doubled), COMMON_SESSION);
    }

    #[test]
    fn remove_without_block_is_unchanged() {
        assert_eq!(remove_block(COMMON_SESSION), COMMON_SESSION);
    }

    #[test]
    fn add_to_non_newline_terminated_still_round_trips_to_terminated() {
        let no_nl = "session required pam_unix.so";
        let added = add_block(no_nl);
        assert!(added.contains(SNIPPET_LINE));
        // add normalizes to a trailing newline; remove restores the (now newline-terminated) base.
        assert_eq!(remove_block(&added), format!("{no_nl}\n"));
    }

    #[test]
    fn generated_stack_validates() {
        let added = add_block(COMMON_SESSION);
        validate_stack(&added).unwrap();
    }

    #[test]
    fn validate_rejects_required_tess_line() {
        let bad = "session required pam_tess.so\n";
        let err = validate_stack(bad).unwrap_err();
        assert!(matches!(err, ValidationError::NotFailOpen { line: 1, .. }));
    }

    #[test]
    fn validate_rejects_sufficient_and_requisite_tess() {
        for ctrl in ["sufficient", "requisite"] {
            let line = format!("auth {ctrl} pam_tess.so\n");
            assert!(matches!(
                validate_stack(&line).unwrap_err(),
                ValidationError::NotFailOpen { .. }
            ));
        }
    }

    #[test]
    fn validate_rejects_malformed_line() {
        let err = validate_stack("session\n").unwrap_err();
        assert!(matches!(err, ValidationError::Malformed { line: 1, .. }));
        let err = validate_stack("notatype required pam_x.so\n").unwrap_err();
        assert!(matches!(err, ValidationError::Malformed { line: 1, .. }));
    }

    #[test]
    fn validate_skips_comments_and_blanks() {
        validate_stack("# a comment\n\n   \nsession optional pam_tess.so\n").unwrap();
    }

    #[test]
    fn auth_gate_bracket_form_is_fail_open() {
        assert!(control_is_fail_open("[success=done default=ignore]"));
        assert!(control_is_fail_open("[success=ok default=ignore]"));
        // Extra non-success codes are fine as long as they fall through.
        assert!(control_is_fail_open(
            "[success=done default=ignore user_unknown=ignore auth_err=ignore]"
        ));
        let line = "auth [success=done default=ignore] pam_tess.so\n";
        validate_stack(line).unwrap();
    }

    #[test]
    fn bracket_with_die_default_is_not_fail_open() {
        assert!(!control_is_fail_open("[success=done default=die]"));
        assert!(!control_is_fail_open("[success=done default=bad]"));
        // A non-default key mapping to die also fails the check.
        assert!(!control_is_fail_open("[auth_err=die default=ignore]"));
    }

    #[test]
    fn bracket_granting_failure_codes_is_not_fail_open() {
        // `default=ok`/`done` would turn a tess decline into an authentication success — rejected.
        assert!(!control_is_fail_open("[success=done default=ok]"));
        assert!(!control_is_fail_open("[success=done default=done]"));
        // A specific failure code mapped to a granting action is likewise rejected.
        assert!(!control_is_fail_open(
            "[success=done default=ignore auth_err=ok]"
        ));
        assert!(!control_is_fail_open(
            "[success=done default=ignore user_unknown=done]"
        ));
    }

    #[test]
    fn bracket_without_default_is_not_fail_open() {
        assert!(!control_is_fail_open("[success=done]"));
        // `default` must be explicitly `ignore`, even if every other code falls through.
        assert!(!control_is_fail_open("[success=done auth_err=ignore]"));
    }

    #[test]
    fn validate_passes_through_include_directives() {
        // Debian service files frequently use `@include`; these must not be rejected as malformed.
        let stack = "@include common-session\nsession optional pam_tess.so\n";
        validate_stack(stack).unwrap();
    }

    #[test]
    fn absolute_module_path_matches_tess() {
        let parsed =
            parse_line("session optional /lib/x86_64-linux-gnu/security/pam_tess.so").unwrap();
        assert!(parsed.module_is(MODULE_FILE));
    }

    #[test]
    fn non_tess_required_line_is_allowed() {
        // The fail-open rule is tess-specific: a stock `required pam_unix.so` must pass validation.
        validate_stack("session required pam_unix.so\n").unwrap();
    }

    #[test]
    fn stray_begin_marker_does_not_delete_unrelated_lines() {
        // A real block preceded by a stray, unmatched BEGIN: removing the block must pair the END
        // with the most recent BEGIN and leave the earlier lines intact, never deleting a big span.
        let stray = format!(
            "session required pam_unix.so\n{BEGIN_MARKER}\nsession required pam_deny.so\n{}",
            add_block("session optional pam_gnome_keyring.so\n")
        );
        let cleaned = remove_block(&stray);
        // The real tess block (the most recent BEGIN..END) is gone…
        assert!(!cleaned.contains(SNIPPET_LINE));
        // …but the unrelated lines between the stray BEGIN and the real block survive.
        assert!(cleaned.contains("session required pam_unix.so"));
        assert!(cleaned.contains("session required pam_deny.so"));
        assert!(cleaned.contains("session optional pam_gnome_keyring.so"));
    }

    #[test]
    fn dash_prefixed_tess_module_is_still_checked() {
        // PAM's `-module` prefix (don't log if missing) must not let an unsafe tess line bypass the
        // fail-open check.
        let parsed = parse_line("auth requisite -pam_tess.so").unwrap();
        assert!(parsed.module_is(MODULE_FILE));
        let err = validate_stack("auth requisite -pam_tess.so\n").unwrap_err();
        assert!(matches!(err, ValidationError::NotFailOpen { line: 1, .. }));
    }
}
