# 0017 — Face detection + alignment before embedding (YuNet via tract, 5-point similarity warp)

- Status: Accepted
- Date: 2026-06-24
- Deciders: project owner
- Supersedes/relates: ADR-0015 (tract ONNX matcher), ADR-0016 (fail closed without a model)

## Context

The IR face matcher embedded the **whole** captured frame: `TractExtractor::extract` resized the
entire GREY frame to the model input and fed that to SFace. ArcFace-family embedders (SFace included)
are trained on **detected, aligned** face crops (eyes/nose/mouth at fixed positions). Feeding a whole
scene makes the embedding encode mostly the **background**, so it barely depends on whether a face is
present. Validated on a real Logitech Brio: identity "matched" with the user **out of frame**
(background only), and a phone photo matched at cosine distance 0.47 — i.e. recognition was comparing
IR scenes, not faces. This is a correctness and security defect, not a tuning problem.

A face-recognition pipeline needs four stages: **detect → align → embed → match**. tess had only the
last two. We must add detection (locate the face + 5 landmarks) and alignment (warp to the canonical
template) before embedding, under the existing constraints: safe Rust (`mug` is
`#![deny(unsafe_code)]` with a single `#[allow(unsafe_code)] mod sys` boundary for the raw V4L2/UVC
ioctls — the new detect/align code adds no `unsafe`), inference via `tract` (no native ONNX Runtime —
ADR-0015), no model shipped (runtime-supplied, fail closed), and deterministic model-free tests.

## Decision

1. **Detector: YuNet** (OpenCV Zoo `face_detection_yunet_2023mar.onnx`, MIT, ~230 KB, opset 11, fixed
   `[1,3,640,640]`), run via `tract`. Decode and NMS are implemented in **safe Rust**: anchor-free
   per-cell `score = sqrt(cls·obj)`, `exp` box, additive 5-landmark offsets across strides 8/16/32,
   then greedy IoU NMS. YuNet emits 5 landmarks in one pass; its landmark order already matches the
   ArcFace template. Output grouping is shape-driven (per-cell width 1/1/4/10 + cell count → stride),
   so decode is robust to output ordering, and any incompatible tensor set fails closed
   (`MatcherUnavailable`). A frame with no face above threshold returns `NoFace` → PIN.

2. **Alignment: closed-form 2-D Umeyama** similarity transform (rotation + uniform scale +
   translation, no shear) from the 5 landmarks to the canonical insightface `arcface_dst` 112×112
   template, then an **inverse bilinear warp** (constant border 0) — matching OpenCV
   `FaceRecognizerSF::alignCrop` / insightface `norm_crop`. Pure safe Rust, **no SVD dependency** (the
   2×2 case reduces to `θ = atan2(A10−A01, A00+A11)`, `scale = sqrt(‖A‖_F² + 2·det A) / var`).
   Degenerate landmark sets (non-finite, coincident, collinear, reflected, near-zero scale) are
   rejected.

3. **Wiring:** enroll and unlock now embed the **aligned crop**. The real path requires **both** a
   detector model (`MUG_DETECTOR_MODEL`) and an embedder (`MUG_MODEL_PATH`); without a detector it
   fails closed. The detector-free whole-frame path remains only for the test substrate
   (`TESS_ALLOW_MOCK_FACE`) and the `face-test` diagnostic.

Validated end-to-end on a real Brio frame: YuNet loads and runs in `tract` (score 0.937, anatomically
correct landmarks); a dark/no-face frame returns `NoFace`; detect→align→embed self-matches across two
real frames at cosine distance ~0.16.

## Alternatives considered

- **SCRFD (insightface)** — strong, also emits 5 landmarks, but larger and with a more error-prone
  decode (2 anchors/cell + per-stride anchor grids). Kept as the fallback if YuNet's NIR landmark
  quality proves insufficient.
- **RetinaFace-mobile0.25 / ULFGD / BlazeFace** — RetinaFace needs SSD priorbox+variance decode (most
  bug-prone); ULFGD emits **no landmarks**; BlazeFace emits 6 non-matching keypoints and ships as
  TFLite. All rejected for this single-cooperative-face use.
- **A second inference engine (`rten`/`ort`/`candle`)** — unnecessary: `tract` runs YuNet's plain
  conv graph (confirmed: it loads and runs). `ort` reintroduces the native-runtime/supply-chain
  problem ADR-0015 rejected; `candle` is over-weight; `wonnx` is archived/GPU-only. Keep one engine.
- **`nalgebra` for the transform** — unnecessary; the fixed 5-point/2-D similarity is closed-form.

## Consequences

- Identity matching is now face-based, and a faceless/background frame is rejected rather than
  false-matched — the core defect is fixed.
- The face factor now requires two runtime models (detector + embedder); documented in the README.
- New safe-Rust surface (decode, NMS, warp), all deterministically unit-tested; YuNet op-compatibility
  with `tract` is confirmed on the real model.
- **Out of scope here:** liveness still runs on the whole frame pair (its over-strict, synthetic-tuned
  gradient gate and lack of presentation-attack resistance are tracked separately); recomputing
  liveness on the aligned crop and recalibrating is a follow-up. The biometric leg remains
  convenience, never the sole gate — the PIN is the real TPM gate.
