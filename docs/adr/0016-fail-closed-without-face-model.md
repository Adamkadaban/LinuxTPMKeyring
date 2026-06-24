# 0016 — Fail closed without a real face model (the mock never gates a real unlock)

## Status

Accepted

## Context

tess ships no face-embedding model (licensing/size; ADR-0015). The matcher abstraction
(`EmbeddingExtractor`) has two backends: the real `tract` ONNX matcher behind the off-by-default
`face-model` feature, and a deterministic, model-free **mock** used so the headless test substrate can
exercise the capture → liveness → unseal pipeline with no model and no camera.

The mock performs **no identity discrimination** — it average-pools pixel statistics, so essentially
any live face produces a "match". Before this decision, `build_matcher` silently fell back to the mock
whenever no model was loaded (no feature, or feature but no `MUG_MODEL_PATH`). That meant a user who
ran `enroll --face` on a default build got face-unlock that accepts *any* live face — a security
footgun directly contradicting the point of a face factor.

The liveness gate (real on both backends) only proves a live 3D face is present; it does not prove
*whose* face. Identity is exactly what the model provides.

## Decision

`build_matcher` **fails closed**: if no real model is loaded, it returns an error rather than building
the mock, for both the enroll and unlock paths (`crates/tess-cli/src/face.rs`). The error tells the
user to build with `--features face-model` and set `MUG_MODEL_PATH` (the README documents where to
download a compatible fixed-shape NCHW model and the input contract).

The mock is allowed **only** behind an explicit, test-only opt-in: the `TESS_ALLOW_MOCK_FACE=1`
environment variable (`ENV_ALLOW_MOCK_FACE`). The hermetic virtual-IR test substrate sets it; when set,
the binary prints a loud warning that identity matching is disabled. It is never set on a real machine.

## Consequences

- A real `enroll --face` / `unlock --face` can never silently accept any live face: without a model it
  errors and the caller falls back to the PIN (which stays the real TPM gate regardless).
- CI and local tests keep working by opting into the mock in their env setup
  (`face_unlock.rs`, `pam_helper_face.rs`); the child PAM helper inherits the var.
- Enabling face identity matching is now a deliberate three-step act (build with the feature, download
  a model, point `MUG_MODEL_PATH` at it), documented in the README.

## Alternatives considered

- **Keep the silent mock fallback (prior behavior).** Rejected: ships a face factor that authenticates
  any face — the footgun this ADR removes.
- **Make the mock weakly discriminate** (tune the pooled extractor toward per-identity separation).
  Rejected: a mock is not a face recognizer; pretending otherwise invites trusting it. Fail-closed +
  a real model is the only honest posture.
- **Warn loudly but still build the mock by default.** Rejected: a warning on a login path is easily
  missed; security defaults must fail closed, not fail open with a log line.
