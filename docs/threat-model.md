# Threat Model

This is the long-form, authoritative statement of what tess does and does not protect. The
[README](../README.md) carries the short version. Where a control is committed in an architectural
decision record, this document links it — information flows one way: this doc references the code and
ADRs, never the reverse.

## One-line summary

tess is **system authentication** that unlocks *your own* keyring **at rest**. It is **not** a
proof-of-presence or attestation mechanism, and it does **not** defend a live machine already owned
by a root/kernel attacker. It is a real, honest upgrade over today's password-derived keyring key —
and nothing more than that.

## What we protect

- **The GNOME login keyring at rest.** The keyring's wrapping key is a high-entropy **random** blob
  sealed in *your* TPM 2.0 under *your* PIN authValue. It is **never derived from the PIN** and
  **never derivable from anything on disk** — only the TPM-encrypted, primary-bound sealed blob and a
  policy descriptor are persisted (see [ADR-0001](adr/0001-tpm-seal-random-key-pin-authvalue-hmac-sessions.md)).
- **Against offline attack.** A stolen disk, a stolen sealed blob, or a powered-off laptop yields
  nothing: the blob is inert without both the original TPM (which holds the deterministic ECC primary
  under its owner seed) and the PIN that gates the sealed object.
- **Against PIN brute force.** The sealed object is **dictionary-attack protected** (no `noDA`), so
  every wrong PIN counts toward the TPM's hardware lockout counter. Anti-hammering is enforced in
  silicon, not by our code or by boot state.
- **Against TPM bus attacks.** Every seal and unseal runs under a **salted HMAC +
  parameter-encryption session**, so neither the PIN authValue nor the unsealed key ever crosses the
  TPM bus in the clear — an SPI interposer learns nothing.

## What this is, precisely: authentication, not attestation

tess unlocks *your own secrets* on a machine *you control* once you pass the gate. It **cannot prove
to a third party** — a remote policy server, an employer's MDM, a relying party — that a specific
human was physically present. The biometric leg is host-trusted (below), and the whole model assumes
the box is not already root-compromised. Use tess to log in and unlock your keyring; never as
evidence of presence to something that does not already trust the machine. This boundary is committed
in [ADR-0002](adr/0002-scope-root-out-no-vbs.md).

## Adversaries and boundaries

| Adversary | In scope? | Outcome |
|---|---|---|
| Thief with a powered-off / stolen laptop or disk | **Yes** | Keyring stays sealed; no offline brute force; needs the PIN on the original TPM. |
| Online PIN guesser on the running machine | **Yes** | Throttled to a hardware DA-lockout; a wrong PIN fails closed and accrues toward lockout. |
| Passive TPM-bus interposer (SPI sniffer) | **Yes** | HMAC + parameter-encrypted sessions; no plaintext authValue or key on the bus. |
| Root / kernel attacker on a **live, running** machine | **No** | Out of scope — can keylog the PIN or read the released key from memory. See below. |
| Remote attacker wanting proof a human was present | **No** | tess is auth, not attestation; it makes no such claim. |

## Explicitly out of scope: the root/runtime adversary

A **root/kernel adversary on a live, running machine is explicitly out of scope.** Root can keylog
the PIN, read the released key from process memory, or forge a fingerprint `verify-match`. This is an
acceptable boundary because such an attacker already has full system access — there is nothing left
to protect *from them* here — and because **no Linux system defends this without VBS-class isolation,
which does not exist on commodity hardware:**

- Building a Linux VBS equivalent (type-1 hypervisor + from-scratch secure kernel + IOMMU/firmware
  contracts) is a multi-year OS-team effort; the only attempt (Heki/LVBS) is an unmerged research PoC
  that protects kernel integrity, not user secrets.
- Commodity TEEs do not fit: Intel SGX was removed from client CPUs; Intel TDX / AMD SEV-SNP protect
  a VM *from its host* (the wrong trust direction) and are server-only; ARM TrustZone is ARM-only and
  vendor-gated.
- **ChromeOS cryptohome** — the closest shipped FOSS analogue — makes the *same* concession ("once an
  attacker has root, any user who logs in is exposed until reboot") and relies on verified boot + TPM
  at-rest. That is precisely our position.

The full rationale, alternatives, and consequences are in
[ADR-0002](adr/0002-scope-root-out-no-vbs.md). The consequence is that we **do not** build VBS, **do
not** use any TEE, and **do not** modify fprintd/libfprint. Attested match-on-sensor biometrics
(which would need libfprint + fprintd + sensor-vendor TEE changes) only defend the root adversary we
scoped out, so they are deliberately out of scope — not a deferred TODO.

## The fingerprint leg is host-trusted convenience, never the gate

The MVP ships an **optional** fingerprint front gate (the `fingerprint=yes` PAM module argument; the
default is PIN-only). When enabled, the PAM session runs **one bounded fprintd verify ahead of the
PIN unseal** and then — *regardless of the fingerprint result* — runs the PIN unseal/unlock. The
precedence is:

> **fingerprint (host-trusted convenience) → PIN (the real TPM gate) → password fallthrough.**

The honest limitation, by construction: **because the keyring key is sealed under the PIN authValue,
a fingerprint match alone cannot unseal it — the PIN is always required.** The fingerprint is layered
*on* the PIN, not in its place; a match does not skip the PIN prompt. Every fingerprint outcome —
`match`, `no-match`, `timeout`, or `unavailable` — falls through to the PIN, and only the PIN can
release the sealed key. A root adversary can forge a `verify-match`, which is exactly why the
fingerprint can never stand in for the TPM-sealed PIN authValue.

fprintd is consumed **unmodified** over its existing `net.reactivated.Fprint` D-Bus API — no patches
to fprintd or libfprint. A true "swipe instead of type" scheme (where a fingerprint *releases* a
stored PIN) would require that PIN to be itself TPM/recovery-protected and would need its own ADR; it
is deliberately out of scope for this MVP.

## The face leg (Mug) is a face-or-PIN unlock with real anti-spoofing

The post-MVP face factor (`mug`) gives **Windows-Hello-style face unlock**: a successful,
liveness-gated face match releases the keyring key with no PIN typed, and **the PIN remains an
always-available fallback** (and the recovery path). Unlike Howdy it ships a real anti-spoof:
**active IR reflectance liveness**. It captures a pair of IR frames with the camera's IR emitter OFF
then ON and keys on the per-pixel differential. A live 3-D skin face returns a strong,
spatially-structured response (reflectance gradient following facial geometry, high-frequency skin
texture, localized speculars); a printed photo returns a weak and/or uniform response; a
curved/glossy photo can fake the mean and variance but not the high-frequency relief; a
self-emitting screen shows a bright baseline even with the emitter off and barely changes when it
switches on. Hard gates on mean, spatial standard deviation, gradient energy, screen-emission
baseline, and saturation reject each class; the boundary is deterministic and unit-tested against
procedural live/photo/screen fixtures.

Honest security trade-off, by construction:

- **Face unlock softens the at-rest guarantee; PIN login does not.** With a typed PIN, nothing that
  unlocks the key is ever stored — a powered-off stolen laptop yields nothing to extract (the
  strongest posture). To unlock with *just a face*, the same keyring key `K` is sealed in the TPM a
  **second** time under a fresh, independent random authValue `A_face` (`metadata-face.json`), and
  `A_face` is stored on disk (`face-unlock.key`, mode 0600). `K` itself is still **never** on disk,
  so disk-only theft stays fully protected (unsealing always needs the TPM/laptop); but `A_face` on
  disk lets the TPM unseal `K` after a userspace, liveness-gated face match, so **whole-laptop
  powered-off theft is softened** versus PIN-only — protected by filesystem permissions plus the
  device's disk encryption when present. On commodity Linux there is no VBS/TEE to anchor that the
  way Windows Hello does, so face-unlock's powered-off-theft resistance is weaker than PIN-only's and
  depends on full-disk encryption. `A_face` is independent of both the PIN and the recovery secret
  (it is freshly drawn, never derived), so it grants no extra reach over the existing recovery path.
  Users who want the strongest at-rest posture use PIN login and leave face unenrolled.
- **Liveness raises the bar, it is not a guarantee.** It defeats the photo/screen replays that fool
  Howdy (which has no liveness at all), but it does not claim to stop a determined attacker with a
  fabricated 3-D mask matched to the enrolled face — that is out of scope, as is any root adversary
  on a live machine (who can forge a match or read the released key from memory).
- **No model ships.** The IR matcher is pluggable (an ArcFace/SFace ONNX network loaded from
  configuration); with no model the face factor is simply unavailable and unlock falls back to the
  PIN. No raw face image is ever persisted — only the embedding and liveness calibration, 0600 under
  the user's data dir.

## Recovery: a TPM-independent escape hatch

The TPM unseal path dies if the TPM is cleared, the motherboard is replaced, or the PIN is forgotten.
Enrollment therefore additionally backs the keyring key `K` up under a high-entropy **recovery
secret** `R`, committed in [ADR-0009](adr/0009-recovery-secret-wrapping-scheme.md):

- `R` is 256 bits from the OS CSPRNG, shown **once** as a transcription-friendly grouped-hex string
  and saved offline by the user.
- `K` is wrapped with `XChaCha20-Poly1305` under `KEK = HKDF-SHA256(salt, R, info)`. Only
  `{version, salt, nonce, ciphertext}` is persisted — never `K`, never `R`, never a hash of either.

**What recovery protects:** it survives a cleared TPM or a lost PIN. `tess recover` re-derives `KEK`
from the user-entered `R`, decrypts the blob back to `K` with **no TPM at all**, and re-unlocks the
keyring; `tess recover --reseal` then re-seals `K` under a new PIN against the current TPM, restoring
the normal PIN-unlock path. The recovery test proves `R` recovers the *same* `K` the TPM unseals.

**What recovery cannot do:** it is only as strong as `R`. The blob is inert without `R` — the
ciphertext is indistinguishable from random and the Poly1305 tag rejects a wrong secret or tampering
— but anyone who obtains the user's offline `R` can decrypt `K`. `R` is at least as strong as the
PIN, so it does not weaken the at-rest guarantee, but it shifts the burden to the user keeping `R`
safe. It is **not** TPM-protected and therefore has no hardware anti-hammering: treat `R` like a
root password / BIP-39 seed phrase.

## Hard-lockout reset is gated by the recovery secret, so anti-hammering holds

Every wrong PIN counts toward the TPM's global dictionary-attack counter; at `maxAuthFail` the TPM
enters a **hard lockout** and refuses even the correct PIN until the lockout interval self-heals.
Clearing it promptly needs the privileged `TPM2_DictionaryAttackLockReset`, authorized by the TPM's
**lockout hierarchy**. Per [ADR-0011](adr/0011-privileged-da-lockout-reset.md), enrollment binds the
lockout-hierarchy authValue to a key derived **only** from the recovery secret:
`HKDF-SHA256(ikm = R, salt = "", info = "tess-lockout-auth-v1")`, a distinct sub-key that is never
equal to the keyring-wrapping key `K`. `tess recover` detects a hard lockout, reproduces that
authValue from the user-entered `R`, and runs the reset (shelling out to `tpm2_dictionarylockout` with
the authValue fed on stdin, never argv, so it does not leak via `/proc`) before restoring keyring
access.

The security property: **only the recovery-secret holder can reset the counter.** A PIN-guessing
attacker who trips the lockout has, by construction, no way to derive the lockout authValue (it comes
from `R`, not the PIN and not `K`), so they cannot clear their own lockout — the hardware throttle
stays in force. The reset is a *recovery* convenience for the legitimate user, not a bypass of
anti-hammering. The reset is the same strength as `R` (a wrong authValue is refused by the TPM and
itself trips the lockout-hierarchy's own recovery delay). Given the recovery secret, `tess unenroll`
releases the lockout hierarchy back to empty, so uninstalling tess leaves the TPM as it was found
(skipping the secret leaves the authValue bound, with a warning); on a machine whose
lockout hierarchy is already owned by something else, tess refuses to clobber it and the privileged
reset is simply unavailable there.

## Enrollment is transactional and recoverable; uninstall restores stock behavior

Enrollment is the project's #1 safety-critical path and its #1 safety risk: it rekeys the login
keyring's wrapping key from password-derived to the random TPM-sealed key **in place**, preserving
**every** existing item. The **keyring-preservation invariant** is that no enroll, recover, or
unenroll ever drops, duplicates, or shadows an item — a test asserts N pre-existing secrets survive
the full cycle on throwaway keyrings.

The flow is strictly ordered and transactional: back up the recovery secret **first** → seal `K`
under the PIN and verify it unseals → verify the old keyring credential → `rekey(old → K)` in place →
verify the keyring unlocks and a known item still decrypts → commit. Any failure rolls back **in
reverse, credential-first**: the original keyring credential is restored before any blob is removed.
The one path that deliberately keeps the blobs is a failure to restore the credential — then the
sealed and recovery blobs are the only way back in, and the error directs the user to `tess recover`.

- `tess unenroll` transactionally rekeys the keyring back to a user-supplied password and removes the
  sealed + recovery blobs, restoring stock GNOME behavior with every item intact, and (given the
  recovery secret) releases the TPM lockout hierarchy back to empty.
- `tess install --uninstall` removes the tess PAM block and module, returning the login stack to its
  pre-tess state.

The PAM wiring itself is **fail-open by construction** (`session optional pam_tess.so`): a tess
failure — no TPM, a slow or declined unseal, a missing helper — is ignored and login proceeds with
the keyring simply left locked. The PAM module also runs all heavy work in a watchdog'd helper under
a hard wall-clock timeout, so it can **never freeze login**. tess can never be the reason a login
fails or hangs.

## Secret hygiene

- The keyring key and PIN live in `zeroize`-on-drop buffers (`SecretBytes`), and key lifetime is
  minimized to the unseal→handoff window. Those buffers are `mlock`ed into RAM (best-effort, via the
  safe `region` crate) so the cleartext is never written to swap or a hibernation image; if the OS
  refuses (a low `RLIMIT_MEMLOCK`) the secret stays `zeroize`-on-drop and a note is logged. Disabling
  core dumps (`PR_SET_DUMPABLE`/`RLIMIT_CORE`) remains planned hardening — until then an operator who
  wants that guarantee can disable core dumps at the system level.
- The PIN is never logged and never reaches argv, the environment, or disk. The PAM module hands it
  to the helper over an anonymous in-memory file (`memfd`), not a pipe — eliminating a `SIGPIPE` that
  could kill the login process (see [ADR-0010](adr/0010-pam-helper-pin-transport-memfd.md)).
- **No secret or secret-hash is ever written to disk** — only the TPM-sealed blob (inert without the
  TPM and PIN) and the recovery-wrapped blob (inert without `R`).

## Attack-class → control

Derived from the prior-vulnerability survey; each row cites the failure mode tess was designed to
avoid.

| Attack class (cited prior art) | Control in tess |
|---|---|
| Bus sniff / interposer (Dolos BitLocker, TPM Genie) | No PCR-only sealing; PIN authValue + **mandatory HMAC / parameter-encryption sessions** on every seal/unseal ([ADR-0001](adr/0001-tpm-seal-random-key-pin-authvalue-hmac-sessions.md)) |
| Weak keygen / RNG (ROCA) | Seal a **self-generated** random blob (not a TPM-born RSA key); ECC P-256; `getrandom` XOR-mixed with TPM `GetRandom` |
| Timing side channel (TPM-FAIL, Hertzbleed) | Constant-time PIN handling; rely on the TPM **DA-lockout**, not comparison-timing secrecy |
| Online PIN brute force / lockout abuse | Wrong PINs trip the hardware DA-lockout; the privileged reset is gated by the **recovery secret** (a sub-key never equal to `K`), so an attacker who trips the lockout cannot clear it ([ADR-0011](adr/0011-privileged-da-lockout-reset.md)) |
| Biometric spoof (Windows Hello IR replay, CVE-2021-34466) | The fingerprint leg is **host-trusted, never the sole gate** (the PIN authValue is the real gate). Face unlock (Mug) *can* release the key but is **liveness-gated** — active IR-reflectance rejects photo/screen spoofs (not 3-D masks) — and keeps the PIN as an always-available fallback |
| TOCTOU / confused deputy in PAM | Unseal is bound to the authenticated PAM session and gated by TPM policy; no replayable out-of-band "verify-match" |
| Memory disclosure (cold boot, swap, ptrace, core dump) | `zeroize`-on-drop + minimal key lifetime + best-effort `mlock` (secrets pinned in RAM, never swapped); core-dump disabling (`PR_SET_DUMPABLE`/`RLIMIT_CORE`) remains planned hardening / an operator-level recommendation |
| Dependency FFI UAF (RUSTSEC-2023-0044) | Pin `tss-esapi ≥ 7.1.0`; `cargo audit` + `cargo deny` gate every PR |

## Non-goals (so they are never mistaken for gaps)

- **Runtime-root resistance** — out of scope by design ([ADR-0002](adr/0002-scope-root-out-no-vbs.md)); no commodity Linux path exists.
- **Proof of presence / attestation to a third party** — tess is auth, not attestation.
- **Boot-state binding (PCR policy)** — the MVP binds the PIN authValue only; Azure vTPM PCRs differ
  from bare metal, so PCR binding would be brittle. It is a deferred, optional bar-raise, not shipped.
- **Defending KWallet's native `pam_kwallet` path** — out of scope; tess targets the freedesktop
  Secret Service API (GNOME reference impl).
