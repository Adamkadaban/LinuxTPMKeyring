# 0015 — Pure-Rust `tract` ONNX face matcher (supersedes the `ort` deferral in ADR-0014)

## Status

Accepted (supersedes the matcher-backend deferral in [ADR-0014](./0014-real-brio-capture-defer-ort-matcher.md))

## Context

ADR-0014 wired real Brio IR capture but **deferred** the ONNX face matcher (#56) because the planned
`ort` crate (ONNX Runtime bindings) failed the project's dependency gates:

- `ort` 1.x is entirely **yanked** (fails `cargo deny`'s `yanked = "deny"`);
- `ort` 2.x is all `2.0.0-rc.*` **pre-release**, and its default `download-binaries` feature fetches a
  prebuilt native ONNX Runtime at build time — **non-hermetic** and un-vettable.

The matcher is still needed for real identity matching (the liveness gate already rejects a flat
photo; the matcher answers "is this the enrolled user").

## Decision

Use **`tract-onnx`** (sonos/tract) as the face-embedding backend instead of `ort`. tract is a
**pure-Rust**, self-contained ONNX inference engine: no native ONNX Runtime download or C++ link, so
the build stays hermetic and the dependency tree is vettable. It runs a user-supplied fixed-shape
NCHW model (e.g. ArcFace/SFace) on the GREY IR crop.

- Gated behind the **off-by-default** `face-model` cargo feature on `mug` (and forwarded by
  `tess-cli`), so the CI/default build stays the deterministic model-free mock and never compiles
  tract.
- **No model ships with tess** — the path is user-supplied at runtime via `MUG_MODEL_PATH` /
  `MugConfig.model_path`; absent or unbuilt, the mock is used and face is a liveness-gated
  convenience that always degrades to the PIN.
- The matcher is held as `Matcher<Box<dyn EmbeddingExtractor>>` so the mock and tract backends share
  one type at the call sites. Implementation: `crates/mug/src/matcher.rs` (`TractExtractor`),
  selection in `crates/tess-cli/src/face.rs` (`build_matcher`).

`cargo deny` (advisories/bans/licenses/sources) passes on the tract tree; the new transitive crates
are added to the `cargo vet` exemptions store (still no external audit imports). `cargo check -p mug
--features face-model` runs in CI to keep the backend building.

## Consequences

- Real identity matching is available without any native blob, pre-release crate, or yanked
  dependency — consistent with the project's "100% safe Rust / reproducible / no native runtime"
  biases (the matcher code itself is safe Rust; `mug::sys` remains the only `unsafe` in the crate).
- A larger (but pure-Rust) dependency tree, exempted in `cargo vet`. `multiple-versions` stays a
  `warn` in `deny.toml`, so any duplicate transitive versions don't fail the gate.
- Preprocessing assumes the common ArcFace/SFace input scaling `(p - 127.5) / 127.5` and an NCHW
  fixed-shape model; a model with different expectations needs a matching preprocessing tweak.

## Alternatives considered

- **`ort` 2.x with `load-dynamic`** (link a system `libonnxruntime` instead of downloading one):
  still a pre-release crate and shifts the burden to an externally-managed native runtime on every
  deployment host. Rejected for the hermetic pure-Rust option.
- **Wait for a stable hermetic `ort`**: leaves #56 open indefinitely. Rejected.
