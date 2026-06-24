# 0018 — Live face-preview viewer as a separate non-workspace crate

## Status

Accepted

## Context

Bringing up the real Logitech Brio face pipeline needs a live viewer: a window showing the IR feed,
the detection box and landmarks, the aligned 112×112 crop the embedder sees, and the live match
verdict — so a human can eyeball that detection, alignment, embedding, and the cosine-distance
decision behave on a real face. The hard requirement is that the viewer drive the **exact shipped
`mug` pipeline** (`V4l2IrDevice` → `YuNetDetector` → `align_face` → `TractExtractor` →
`cosine_distance`), not a re-implementation, so what you see is what tess runs.

A live window needs a GUI/windowing crate. The lightest pure-Rust option, `minifb`, pulls a large
transitive stack (wayland + x11 on Linux, and — present in the lockfile across all platforms —
sdl2, winapi, web-sys/wasm, redox/orbclient): ~36 crates. tess is an **auth-critical** project whose
CI gates the full workspace `Cargo.lock` with `cargo deny check` and `cargo vet --locked`. Adding
`minifb` to a workspace crate (even behind an off-by-default feature) forces every one of those
transitive crates into the workspace lockfile and therefore into the cargo-vet ledger — i.e.
rubber-stamping ~36 unaudited GUI crates as `safe-to-deploy` in an auth project, for a tool that is
never shipped in the `.deb`.

## Decision

Ship the viewer as a **standalone crate `tools/face-preview/` that is excluded from the workspace**
(`[workspace] exclude`). It path-depends on `mug` with the `face-model` feature, so it exercises the
exact shipped detect→align→embed→match code. Because it is outside the workspace it has its **own**
`Cargo.lock`, and the workspace lockfile, `cargo deny check`, and `cargo vet --locked` never see
`minifb` or any of its dependencies.

It is `#![forbid(unsafe_code)]`, reads its model paths from the same `MUG_DETECTOR_MODEL` /
`MUG_MODEL_PATH` env vars as the CLI, and is run with
`cargo run --manifest-path tools/face-preview/Cargo.toml --release`. It touches neither the keyring
nor the TPM.

## Consequences

- Zero supply-chain churn on the auth-critical workspace: no new cargo-vet exemptions, no new
  cargo-deny clearances, the shipped `.deb` is unchanged.
- The viewer still validates the real pipeline (path dep on `mug`), satisfying the bring-up need.
- It is `cargo run --manifest-path …`, not a `tess face-preview` subcommand — a minor ergonomic cost
  acceptable for a dev/eval tool.
- Its own `Cargo.lock` is committed for reproducibility but is not gated by the workspace
  supply-chain jobs; it is never built in CI or shipped.

## Alternatives considered

- **`tess face-preview` subcommand behind an off-by-default `face-gui` feature depending on
  `minifb`.** Rejected: even feature-gated, the optional dependency lands in the workspace
  `Cargo.lock`, so `cargo vet --locked` requires `safe-to-deploy` exemptions for ~36 GUI crates
  (sdl2/winapi/wasm/redox included) and `cargo deny` must clear them — a large, permanent unaudited
  surface added to an auth project for a never-shipped tool. "Security over ergonomics where they
  conflict" (AGENTS.md) settles it.
- **Restrict `cargo deny`/`cargo vet` to the `x86_64-unknown-linux-gnu` target to prune the
  non-Linux crates.** Reduces but does not eliminate the churn (~17 Linux GUI crates remain) and
  broadens the supply-chain policy for the whole project to work around one dev tool. Rejected as
  the wrong trade for an eval-only viewer.
- **A no-window tool that dumps annotated frames to disk.** Rejected: defeats the point of a *live*
  viewer for real-time bring-up, and image I/O still wants extra deps.
