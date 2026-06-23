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
}
