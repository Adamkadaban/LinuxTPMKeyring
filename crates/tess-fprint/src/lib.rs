//! `fprintd` client over the `net.reactivated.Fprint` D-Bus API, consumed unmodified — exactly as
//! `pam_fprintd` does (no patches to fprintd or libfprint). A successful fingerprint verify is
//! host-trusted *convenience*, never the sole gate: the PIN authValue sealed in the TPM remains the
//! real authorization. This client only reports whether the local fprintd matched a finger; it never
//! holds, derives, or releases key material itself.
//!
//! Tests drive a deterministic D-Bus mock of the `net.reactivated.Fprint` surface (see
//! `testing/fprint-mock/`), so the suite is fully headless with no real reader and no real fprintd.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use async_io::Timer;
use futures_util::future::{select, Either};
use futures_util::stream::StreamExt;
use tess_core::{AuthGate, Error, Result};
use zbus::zvariant::OwnedObjectPath;
use zbus::{proxy, Connection};

/// The fprintd D-Bus service name.
pub const FPRINT_BUS_NAME: &str = "net.reactivated.Fprint";

/// Environment variable libfprint reads to select the non-image virtual driver (test substrate).
pub const VIRTUAL_DEVICE_ENV: &str = "FP_VIRTUAL_DEVICE";

/// The finger token passed to `VerifyStart`; `"any"` asks fprintd to match against any enrolled
/// finger, matching `pam_fprintd`'s default.
const VERIFY_ANY_FINGER: &str = "any";

/// The exact [`Error::Auth`] message a bounded [`FprintClient::verify`] returns on a clean
/// `verify-no-match` (a finger was read but matched no enrolled template). Callers distinguish this
/// from other `Auth` failures (claim/start errors, disconnect, stream closed) by comparing against
/// this sentinel, so a real no-match is never confused with an unavailable reader.
pub const NO_MATCH_REASON: &str = "fingerprint did not match";

/// Extra time the hard wall-clock backstop allows beyond `deadline_ms` so the graceful inner-deadline
/// path can finish its `VerifyStop`/`Release` cleanup. The backstop only cancels mid-flight when the
/// bus is genuinely wedged — and fprintd releases a claim automatically when the client disconnects.
const CLEANUP_GRACE: Duration = Duration::from_millis(1000);

#[proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait Manager {
    /// Returns the object path of the system's default fingerprint device.
    fn get_default_device(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
trait Device {
    /// Claim the device for `username` (empty string means the calling user).
    fn claim(&self, username: &str) -> zbus::Result<()>;

    /// Release a previously claimed device.
    fn release(&self) -> zbus::Result<()>;

    /// Begin a verification against the enrolled finger named `finger_name`.
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;

    /// Stop an in-progress verification.
    fn verify_stop(&self) -> zbus::Result<()>;

    /// Progress/result signal. `result` is one of fprintd's `verify-*` tokens; `done` is true once
    /// the verification has reached a terminal state.
    #[zbus(signal)]
    fn verify_status(&self, result: String, done: bool) -> zbus::Result<()>;
}

/// The terminal meaning of a `VerifyStatus(result, done)` signal, decoupled from D-Bus so it is
/// unit-testable without a bus.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifyOutcome {
    /// A finger matched — fprintd authenticated the user locally.
    Match,
    /// A finger was read but did not match any enrolled template.
    NoMatch,
    /// A non-match terminal failure (device disconnected, internal error, …); carries the raw token.
    Failed(String),
    /// A transient, non-terminal status (retry, swipe too short, …) — keep waiting.
    Retry,
}

/// Classify an fprintd `VerifyStatus(result, done)` pair. Pure: the terminal `verify-match` /
/// `verify-no-match` tokens decide on their own; any other token is terminal only when `done` is set,
/// otherwise it is a retry the caller should wait through until the deadline.
fn classify_verify_result(result: &str, done: bool) -> VerifyOutcome {
    match result {
        "verify-match" => VerifyOutcome::Match,
        "verify-no-match" => VerifyOutcome::NoMatch,
        other if done => VerifyOutcome::Failed(other.to_owned()),
        _ => VerifyOutcome::Retry,
    }
}

/// An `fprintd` verification client bound to a D-Bus connection and the username to claim for.
///
/// Construct with [`FprintClient::system`] in production (fprintd on the system bus) or
/// [`FprintClient::connect_address`] for the test mock on a private bus. Every verify is bounded by a
/// caller-supplied deadline and never blocks indefinitely.
pub struct FprintClient {
    connection: Connection,
    username: String,
}

impl FprintClient {
    /// Connect to fprintd on the **system** bus and claim verifications for `username` (use `""` for
    /// the calling user, as `pam_fprintd` does when it has no explicit user).
    pub fn system(username: impl Into<String>) -> Result<Self> {
        let connection = async_io::block_on(Connection::system())
            .map_err(|e| Error::Io(format!("connect to system bus: {e}")))?;
        Ok(Self {
            connection,
            username: username.into(),
        })
    }

    /// Connect to an explicit D-Bus address (a private bus owned by the test mock) and claim for
    /// `username`. Passing the address directly keeps tests parallel-safe — no global
    /// `DBUS_SESSION_BUS_ADDRESS` mutation.
    pub fn connect_address(address: &str, username: impl Into<String>) -> Result<Self> {
        let connection = async_io::block_on(async {
            zbus::connection::Builder::address(address)?.build().await
        })
        .map_err(|e| Error::Io(format!("connect to bus {address}: {e}")))?;
        Ok(Self {
            connection,
            username: username.into(),
        })
    }

    /// Run one bounded fingerprint verification.
    ///
    /// Returns `Ok(())` on `verify-match`, [`Error::Auth`] on `verify-no-match` or any other terminal
    /// fprintd failure, and [`Error::Timeout`] if `deadline_ms` elapses first. The signal wait is
    /// bounded by `deadline_ms` and runs `VerifyStop`/`Release` cleanup on the way out; an outer
    /// `deadline_ms + CLEANUP_GRACE` wall-clock backstop additionally bounds the D-Bus setup calls
    /// (`GetDefaultDevice`, `Claim`, …) so the call can never block past that ceiling even on a wedged
    /// bus. The grace lets the graceful path finish cleanup; only a genuinely wedged bus hits the
    /// backstop, and fprintd releases the claim when this client's connection drops.
    pub fn verify(&self, deadline_ms: u64) -> Result<()> {
        async_io::block_on(async move {
            let op = std::pin::pin!(self.verify_async(deadline_ms));
            let hard_cap = Duration::from_millis(deadline_ms).saturating_add(CLEANUP_GRACE);
            let timer = Timer::after(hard_cap);
            match select(op, timer).await {
                Either::Left((result, _)) => result,
                Either::Right((_, _)) => Err(Error::Timeout(deadline_ms)),
            }
        })
    }

    async fn verify_async(&self, deadline_ms: u64) -> Result<()> {
        let start = Instant::now();
        let manager = ManagerProxy::new(&self.connection)
            .await
            .map_err(|e| Error::Auth(format!("fprintd Manager proxy: {e}")))?;
        let device_path = manager
            .get_default_device()
            .await
            .map_err(|e| Error::Auth(format!("fprintd GetDefaultDevice: {e}")))?;
        let device = DeviceProxy::builder(&self.connection)
            .path(device_path.clone())
            .map_err(|e| Error::Auth(format!("fprintd device path {device_path}: {e}")))?
            .build()
            .await
            .map_err(|e| Error::Auth(format!("fprintd Device proxy: {e}")))?;

        device
            .claim(&self.username)
            .await
            .map_err(|e| Error::Auth(format!("fprintd Claim: {e}")))?;

        let outcome = self.verify_claimed(&device, start, deadline_ms).await;

        let _ = device.release().await;
        outcome
    }

    async fn verify_claimed(
        &self,
        device: &DeviceProxy<'_>,
        start: Instant,
        deadline_ms: u64,
    ) -> Result<()> {
        // Subscribe before VerifyStart so a fast mock/reader can't emit VerifyStatus into a gap.
        let mut status = device
            .receive_verify_status()
            .await
            .map_err(|e| Error::Auth(format!("subscribe VerifyStatus: {e}")))?;

        if let Err(e) = device.verify_start(VERIFY_ANY_FINGER).await {
            return Err(Error::Auth(format!("fprintd VerifyStart: {e}")));
        }

        let result = wait_for_outcome(&mut status, start, deadline_ms).await;
        let _ = device.verify_stop().await;
        result
    }
}

/// Wait for a terminal [`VerifyOutcome`], racing each signal against the remaining time so the call is
/// always bounded by `deadline_ms` measured from `start`. Timing is elapsed-based (no absolute
/// `Instant + Duration`), so even a `u64::MAX` deadline can never overflow or panic.
async fn wait_for_outcome(
    status: &mut VerifyStatusStream,
    start: Instant,
    deadline_ms: u64,
) -> Result<()> {
    let total = Duration::from_millis(deadline_ms);
    loop {
        let elapsed = start.elapsed();
        if elapsed >= total {
            return Err(Error::Timeout(deadline_ms));
        }
        let timer = Timer::after(total - elapsed);
        match select(status.next(), timer).await {
            Either::Left((Some(signal), _)) => {
                let args = signal
                    .args()
                    .map_err(|e| Error::Auth(format!("parse VerifyStatus signal: {e}")))?;
                match classify_verify_result(&args.result, args.done) {
                    VerifyOutcome::Match => return Ok(()),
                    VerifyOutcome::NoMatch => return Err(Error::Auth(NO_MATCH_REASON.to_owned())),
                    VerifyOutcome::Failed(token) => {
                        return Err(Error::Auth(format!("fprintd verification failed: {token}")))
                    }
                    VerifyOutcome::Retry => continue,
                }
            }
            Either::Left((None, _)) => {
                return Err(Error::Auth("VerifyStatus stream closed".to_owned()))
            }
            Either::Right((_, _)) => return Err(Error::Timeout(deadline_ms)),
        }
    }
}

impl AuthGate for FprintClient {
    /// Fingerprint is host-trusted convenience layered on the PIN; satisfying it never on its own
    /// releases the sealed key.
    fn authorize(&self, deadline_ms: u64) -> Result<()> {
        self.verify(deadline_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_name_is_fprint() {
        assert_eq!(FPRINT_BUS_NAME, "net.reactivated.Fprint");
    }

    #[test]
    fn match_token_is_terminal_match() {
        assert_eq!(
            classify_verify_result("verify-match", true),
            VerifyOutcome::Match
        );
        // `verify-match` is terminal regardless of the (always-set) done flag.
        assert_eq!(
            classify_verify_result("verify-match", false),
            VerifyOutcome::Match
        );
    }

    #[test]
    fn no_match_token_is_terminal_no_match() {
        assert_eq!(
            classify_verify_result("verify-no-match", true),
            VerifyOutcome::NoMatch
        );
        assert_eq!(
            classify_verify_result("verify-no-match", false),
            VerifyOutcome::NoMatch
        );
    }

    #[test]
    fn retry_tokens_wait_until_done() {
        assert_eq!(
            classify_verify_result("verify-retry-scan-failed", false),
            VerifyOutcome::Retry
        );
        assert_eq!(
            classify_verify_result("verify-swipe-too-short", false),
            VerifyOutcome::Retry
        );
    }

    #[test]
    fn other_terminal_tokens_fail_with_token() {
        assert_eq!(
            classify_verify_result("verify-disconnected", true),
            VerifyOutcome::Failed("verify-disconnected".to_owned())
        );
        assert_eq!(
            classify_verify_result("verify-unknown-error", true),
            VerifyOutcome::Failed("verify-unknown-error".to_owned())
        );
    }
}
