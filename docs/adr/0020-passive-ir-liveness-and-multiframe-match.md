# 0020 — Liveness is passive active-illumination IR, not motion/blink; match decides over multiple frames

## Status

Accepted

## Context

A reasonable question during bring-up: shouldn't liveness require a *moving* face (blink, smile, head
turn)? And the single-frame match flickers — is one matching frame enough to unlock? This ADR records
the researched answers so the design isn't second-guessed later.

We target a **local physical near-IR camera** (Logitech Brio), emulating Windows Hello. Face is
**host-trusted convenience; the PIN authValue is the real TPM gate** (see `threat-model.md`).

## Decision

**1. Liveness stays passive active-illumination IR (no motion/blink challenge).** We capture an
emitter-OFF/ON pair and analyze the IR reflectance differential (3-D skin structure, texture,
specular, screen-baseline) — exactly the class Windows Hello uses.

**2. The identity match decides over multiple quality-gated frames, by majority (median distance),
not a single frame.** Within the existing deadline, after the liveness pair, `verify` collects up to
`MATCH_FRAMES` ON frames, drops frames with no detectable face (quality gate), and requires the
**median** distance over **≥`MIN_MATCH_FRAMES`** valid frames to clear the threshold. Too few valid
frames → no-decision → PIN. (Implemented in `crates/mug/src/gate.rs`.)

## Rationale (researched)

- **Windows Hello** (Microsoft Learn, *Windows Hello face authentication*) uses near-IR and a pipeline
  of *find face → landmarks → head orientation → representation vector → threshold decision* — **no
  blink/motion**. It explicitly notes IR's anti-spoof value: *"IR doesn't display in photos because
  it's a different wavelength … the images do not display in photos or on an LCD display."* That is
  precisely the photo/screen invisibility we observed on the Brio (phone 9/9, glossy Polaroid 15/15
  not detected as a face — rejected at the detection stage).
- **Motion/blink liveness** (Wikipedia, *Liveness test*) is primarily a **remote-KYC video** technique
  ("look into a camera and move, smile or blink"), whose modern threat is **deepfake / video-injection
  attacks** — a remote-stream threat, not a local physical-camera one. It adds user friction and is
  itself defeatable by video replay. Hello/Face ID do **not** use it for local device unlock.
- **Match decision** (synthesis of three investigations + standard biometric fusion): a single-frame
  (or first-match-wins, as in howdy/fprintd) decision is vulnerable to a transient noise dip below
  threshold. Aggregating over quality-gated frames and requiring the **median** to clear the threshold
  means a single fluke frame cannot carry the decision (an impostor's occasional low-distance frame is
  outvoted), while a genuine user's occasional bad frame is tolerated. Bias is toward **false-reject**
  (the PIN catches rejects), per our convenience/PIN framing.

## Consequences

- No motion challenge → lower friction, no blink-replay weakness; matches Hello's UX (<2 s).
- Multi-frame match removes the transient false-match the live viewer exposed; the decision is stable.
- Still **not** a guarantee against a fabricated 3-D mask or an IR-faithful print (single passive IR
  sensor, no depth; we make no ISO/IEC 30107-3 PAD claim). The PIN remains authoritative.
- A future learned NIR PAD model (e.g. MiniFASNet) is an optional enhancement, tracked with #79; not
  required for the MVP.

## Alternatives considered

- **Add a blink/smile/head-turn challenge.** Rejected: friction, replay-defeatable, and not what
  local IR systems (Hello/Face ID) do. The off/on IR differential already separates flat/screen spoofs
  better, with no user action.
- **Keep single-frame match.** Rejected: a transient below-threshold frame authenticates; the viewer
  showed the per-frame distance crossing the threshold on noise.
- **First-match-wins loop (howdy/fprintd style).** Rejected: strictly worse — more frames = more
  chances for a fluke = higher false-accept.
- **Trimmed-mean of the distances (drop the worst, threshold once)** — the aggregation #89 originally
  proposed. Rejected in favor of the **median**: "drop the worst" discards the *highest* (most
  rejecting) distance, and a few transient *low* (false-match) frames then pull the mean toward accept;
  the median needs a *majority* of frames below threshold to accept, so a minority of transient
  low-distance frames cannot authenticate — which is exactly #89's own acceptance criterion ("a single
  transient below-threshold frame does **not** authenticate"). Median also tolerates a genuine user's
  occasional bad (high-distance) frame just as well. (#89's body predates this comparison; the median
  decision supersedes its trimmed-mean wording.)
- **Depth/structured-light liveness (Face ID style).** Not available: the Brio is IR + emitter, no
  depth sensor.
