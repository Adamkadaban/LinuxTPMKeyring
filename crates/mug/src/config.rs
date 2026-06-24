//! Aggregate configuration for the face factor. Serializable so wave 2 can persist/operator-tune it;
//! every field has a secure-by-default value.

use serde::{Deserialize, Serialize};

use crate::liveness::LivenessConfig;

/// Top-level mug configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MugConfig {
    /// Wall-clock budget for a full liveness frame-pair capture. Keeps the factor bounded so it can
    /// never stall login; on timeout the caller degrades to the PIN.
    pub capture_deadline_ms: u64,
    /// Maximum cosine distance accepted as a face match.
    pub match_threshold: f32,
    /// Liveness thresholds.
    pub liveness: LivenessThresholds,
    /// Path to the IR face-embedding ONNX model. `None` means the matcher is unavailable and the
    /// face factor degrades to the PIN — tess ships no model.
    pub model_path: Option<String>,
    /// Path to the ONNX face-detector model (YuNet). Reserved/plumbed for the upcoming
    /// detect→align→embed wiring — **not yet read by any code path**, so setting it currently has no
    /// effect. Once wired, `None` will mean no detector is configured and the face factor degrades
    /// to the PIN (tess ships no model).
    #[serde(default)]
    pub detector_model_path: Option<String>,
    /// How raw `[0,255]` IR pixels are scaled before they reach the model. Defaults to the common
    /// ArcFace/SFace convention; override for models trained with different normalization.
    #[serde(default)]
    pub pixel_scale: PixelScale,
}

/// Pixel-value scaling applied to each `[0,255]` IR sample before it is fed to the model. The IR
/// source is single-channel grayscale, replicated across the model's channels, so only the scalar
/// mapping is configurable (channel order is irrelevant for a grayscale input).
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PixelScale {
    /// `(p - 127.5) / 127.5` → roughly `[-1, 1]`. The ArcFace/SFace default.
    #[default]
    Symmetric,
    /// `p / 255` → `[0, 1]`.
    Unit,
    /// `(p / 255 - mean) / std`. For models trained with explicit normalization.
    Standardized { mean: f32, std: f32 },
}

impl PixelScale {
    /// Map a raw `[0,255]` IR sample to the model input value.
    pub fn apply(self, p: u8) -> f32 {
        match self {
            PixelScale::Symmetric => (p as f32 - 127.5) / 127.5,
            PixelScale::Unit => p as f32 / 255.0,
            PixelScale::Standardized { mean, std } => (p as f32 / 255.0 - mean) / std,
        }
    }
}

/// Serializable mirror of [`LivenessConfig`] (kept separate so the on-disk schema is explicit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessThresholds {
    pub min_mean_delta: f32,
    pub min_delta_std: f32,
    pub min_gradient_energy: f32,
    pub max_baseline_for_live: f32,
    pub emission_min_delta: f32,
    pub max_saturated_fraction: f32,
    pub score_threshold: f32,
}

impl From<&LivenessThresholds> for LivenessConfig {
    fn from(t: &LivenessThresholds) -> Self {
        LivenessConfig {
            min_mean_delta: t.min_mean_delta,
            min_delta_std: t.min_delta_std,
            min_gradient_energy: t.min_gradient_energy,
            max_baseline_for_live: t.max_baseline_for_live,
            emission_min_delta: t.emission_min_delta,
            max_saturated_fraction: t.max_saturated_fraction,
            score_threshold: t.score_threshold,
        }
    }
}

impl Default for LivenessThresholds {
    fn default() -> Self {
        let d = LivenessConfig::default();
        Self {
            min_mean_delta: d.min_mean_delta,
            min_delta_std: d.min_delta_std,
            min_gradient_energy: d.min_gradient_energy,
            max_baseline_for_live: d.max_baseline_for_live,
            emission_min_delta: d.emission_min_delta,
            max_saturated_fraction: d.max_saturated_fraction,
            score_threshold: d.score_threshold,
        }
    }
}

impl Default for MugConfig {
    fn default() -> Self {
        Self {
            capture_deadline_ms: 2500,
            match_threshold: 0.34,
            liveness: LivenessThresholds::default(),
            model_path: None,
            detector_model_path: None,
            pixel_scale: PixelScale::default(),
        }
    }
}

impl MugConfig {
    /// Resolve the effective [`LivenessConfig`].
    pub fn liveness_config(&self) -> LivenessConfig {
        LivenessConfig::from(&self.liveness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_roundtrips_through_json() {
        let cfg = MugConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: MugConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.capture_deadline_ms, cfg.capture_deadline_ms);
        assert_eq!(back.model_path, None);
    }

    #[test]
    fn thresholds_map_to_liveness_config() {
        let cfg = MugConfig::default();
        let lc = cfg.liveness_config();
        assert_eq!(lc.min_mean_delta, LivenessConfig::default().min_mean_delta);
    }

    #[test]
    fn pixel_scale_defaults_to_symmetric() {
        assert_eq!(MugConfig::default().pixel_scale, PixelScale::Symmetric);
    }

    #[test]
    fn pixel_scale_maps_samples() {
        assert!((PixelScale::Symmetric.apply(255) - 1.0).abs() < 1e-6);
        assert!((PixelScale::Symmetric.apply(0) - -1.0).abs() < 1e-2);
        assert!((PixelScale::Unit.apply(255) - 1.0).abs() < 1e-6);
        assert!((PixelScale::Unit.apply(0)).abs() < 1e-6);
        // (128/255 - 0.5) / 0.25 = (0.50196 - 0.5)/0.25 ≈ 0.00784
        let v = PixelScale::Standardized {
            mean: 0.5,
            std: 0.25,
        }
        .apply(128);
        assert!((v - 0.007843).abs() < 1e-4, "got {v}");
    }

    #[test]
    fn pixel_scale_standardized_roundtrips_through_json() {
        let scale = PixelScale::Standardized {
            mean: 0.485,
            std: 0.229,
        };
        let json = serde_json::to_string(&scale).unwrap();
        assert_eq!(serde_json::from_str::<PixelScale>(&json).unwrap(), scale);
    }

    #[test]
    fn config_without_pixel_scale_field_defaults() {
        // Older on-disk configs predate the field; serde default keeps them loadable.
        let json = r#"{"capture_deadline_ms":2500,"match_threshold":0.34,
            "liveness":{"min_mean_delta":0.0,"min_delta_std":0.0,"min_gradient_energy":0.0,
            "max_baseline_for_live":0.0,"emission_min_delta":0.0,"max_saturated_fraction":0.0,
            "score_threshold":0.0},"model_path":null}"#;
        let cfg: MugConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.pixel_scale, PixelScale::Symmetric);
    }
}
