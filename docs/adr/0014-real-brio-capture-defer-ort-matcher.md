# 0014 — Real Brio IR capture wiring and deferral of the `ort` ONNX matcher backend

## Status

Accepted

## Context

Phase 5 landed `mug` with two halves of the face factor already built but not yet wired into the
`tess` CLI flow:

- the **real Logitech Brio** IR path (`mug::find_brio_ir_node`, `V4l2IrDevice::open_brio`,
  `BrioEmitter`), all safe Rust over the single `mug::sys` ioctl boundary; and
- a **pluggable matcher** (`EmbeddingExtractor` trait + cosine `Matcher` + the model-free
  `PooledExtractor` mock), with an `ort` (ArcFace/SFace ONNX) backend documented as the drop-in.

`tess-cli::face` only wired the headless virtual substrate (`MUG_VIRTUAL_IR_DIR`) and otherwise
errored "virtual substrate only". Two coupled issues asked to finish the job: #63 (wire real Brio
capture) and #56 (wire the `ort` matcher). CI must stay model-free and hardware-free; the real
hardware path is validated by a manual smoke on a dedicated test machine (throwaway keyring/TPM) with the Brio, never on the daily-driver host and never CI.

## Decision

**Hardware capture (#63) — wired.** `tess-cli::face::resolve_backend` (pure, unit-tested) chooses a
backend from `MUG_IR_BACKEND` with this precedence:

1. `hardware` → the Brio path, explicit opt-in, wins even if a substrate is configured;
2. `virtual` → the substrate, erroring if `MUG_VIRTUAL_IR_DIR` is unset;
3. `auto`/unset → the substrate when `MUG_VIRTUAL_IR_DIR` is set (the CI/default path), else the Brio
   when a GREY IR node is discoverable, else unavailable (degrade to PIN).

The virtual substrate stays the default/CI path; hardware reports cleanly unavailable (degrade to PIN)
with no camera. The Brio emitter `SET_CUR` payloads default to a starting value and are overridable
via `MUG_IR_EMITTER_ON_HEX`/`MUG_IR_EMITTER_OFF_HEX`; a wrong payload fails safe (emitter stays off,
liveness can't pass). Selection is symmetric across `template_source_from_env` (enroll) and
`verify_from_env` (unlock). No new `unsafe`: all hardware code remains behind `mug::sys` (ADR-0012);
`tess-cli` stays `deny(unsafe_code)`. See `crates/tess-cli/src/face.rs` (`resolve_backend`,
`build_hardware_backend`).

**Matcher backend (#56) — deferred/blocked, NOT wired.** No `ort` dependency or `face-model` feature
was added; the matcher stays the model-free mock. The blocker:

- **No stable, non-yanked `ort` exists on crates.io.** The entire `1.x` line is *yanked* (fails
  `cargo deny`'s `yanked = "deny"`); every `2.x` is a `2.0.0-rc.*` pre-release (the task forbids
  alpha/rc). `max_stable_version` is `null`.
- **`ort` 2.x is non-hermetic by default.** Its default features include `download-binaries`, which
  fetches a prebuilt native ONNX Runtime shared library at build time — an un-vettable non-Rust
  binary that breaks a hermetic build and cannot pass `cargo deny`/`cargo vet`.

Per the issue's own escape hatch ("if `ort`'s tree cannot pass deny/vet cleanly, or requires a
prebuilt native ONNX Runtime that breaks a hermetic build, STOP and report it"), #56 is left as the
trait + mock, unchanged, and reported as a blocker for a maintainer decision.

## Consequences

- Real face login on the Brio works as a **liveness-gated convenience**: capture + the active-IR
  liveness anti-spoof are real, but identity discrimination is weak (mock matcher) until #56 lands.
- CI and `cargo test` are unchanged: model-free, hardware-free; selection logic is unit-tested with
  closures and the substrate env, no camera touched.
- `Cargo.lock` gains no external crate; `cargo deny`/`cargo vet --locked` stay green untouched.
- #56 stays open. Reviving it needs either a published stable `ort` with a vettable, hermetic build
  (e.g. `load-dynamic` against a system ONNX Runtime, no download-binaries) or an alternative ONNX
  runtime crate that passes the supply-chain gates.

## Alternatives considered

- **Pin a yanked `ort` 1.16.x** — rejected: `cargo deny` denies yanked crates, and a yanked release is
  unmaintained.
- **Pin `ort` 2.0.0-rc.x** — rejected: the task forbids alpha/rc, and the default `download-binaries`
  is non-hermetic regardless of version.
- **Add the `face-model` feature + `OrtExtractor` now, off by default** — rejected: even an optional
  dep pulls `ort` into `Cargo.lock` when the feature is built, failing `cargo vet --locked`/`deny`,
  and the feature could not be built hermetically to prove it compiles. Leaving #56 untouched keeps
  the supply chain clean and the decision explicit.
