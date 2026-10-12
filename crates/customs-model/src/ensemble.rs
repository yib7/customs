//! Logistic stacking of the component logits (DESIGN.md section 5, `ensemble.json`,
//! format `customs-ensemble-v1`).
//!
//! `risk = calibrate(sigmoid(bias + sum_c w_c * clip(logit_c)))` over the components that
//! ran, where `clip` bounds each logit to `[-clip, clip]` when the file sets `clip`. The
//! bound keeps one overconfident component from deciding a package on its own: without
//! it, a handful of benign validation packages with CNN logits near 20 set the block
//! threshold far above where it transfers to new data.
//! When a component cannot run for an input (no token stream for the CNN, no name, no
//! features), the stacker uses the entry of `fallbacks` whose `missing` set equals the set
//! of unavailable components; those weights were fitted for exactly that situation. With
//! no matching entry there is no risk, unless the file sets `partial: true` to apply the
//! primary weights to whatever ran: weights fitted with the code models present say
//! nothing about a name scored alone.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::calibration::Calibration;
use crate::{sigmoid, Decision, ModelError};

/// Component names in canonical order.
pub const COMPONENTS: [&str; 3] = ["code_gbdt", "code_nn", "name"];

/// Weights for a set of missing components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fallback {
    pub missing: Vec<String>,
    pub weights: BTreeMap<String, f64>,
    #[serde(default)]
    pub bias: f64,
    /// Optional calibration for this weight set; the top-level one is used when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration: Option<Calibration>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Thresholds {
    pub warn: f64,
    pub block: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_fpr_warn: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_fpr_block: Option<f64>,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            warn: 0.5,
            block: 0.9,
            target_fpr_warn: None,
            target_fpr_block: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ensemble {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<String>>,
    pub weights: BTreeMap<String, f64>,
    #[serde(default)]
    pub bias: f64,
    #[serde(default)]
    pub fallbacks: Vec<Fallback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration: Option<Calibration>,
    #[serde(default)]
    pub thresholds: Thresholds,
    /// Bound applied to every component logit before stacking, for all weight sets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clip: Option<f64>,
    /// Apply the primary weights to the components that ran when no fallback matches the
    /// missing set. Off by default: such a set gets no risk.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
}

/// Per-component logits; `None` means the component did not run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Logits {
    pub code_gbdt: Option<f64>,
    pub code_nn: Option<f64>,
    pub name: Option<f64>,
}

impl Logits {
    pub fn get(&self, component: &str) -> Option<f64> {
        match component {
            "code_gbdt" => self.code_gbdt,
            "code_nn" => self.code_nn,
            "name" => self.name,
            _ => None,
        }
    }

    /// Components that did not run, in canonical order.
    pub fn missing(&self) -> Vec<&'static str> {
        COMPONENTS
            .iter()
            .filter(|c| self.get(c).is_none())
            .copied()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnsembleOutput {
    /// Stacked log-odds before calibration.
    pub z: f64,
    /// `sigmoid(z)`.
    pub raw: f64,
    /// Calibrated risk in [0, 1].
    pub risk: f64,
    /// Which weights were used: `"primary"`, `"missing:<components>"` for a fallback entry,
    /// or `"partial:<components>"` when no fallback matched and the file opted in to
    /// applying the primary weights to the components that ran. Prefixed `"non_finite:"`
    /// when `z` or the risk was not finite; the risk is then 1.
    pub weight_set: String,
}

fn same_set(a: &[String], b: &[&str]) -> bool {
    a.len() == b.len() && b.iter().all(|x| a.iter().any(|y| y == x))
}

/// The weights, bias, calibration and label used for one set of missing components.
struct WeightSet<'a> {
    weights: &'a BTreeMap<String, f64>,
    bias: f64,
    calibration: Option<&'a Calibration>,
    label: String,
}

impl Ensemble {
    pub fn from_json(text: &str) -> Result<Self, ModelError> {
        const WHAT: &str = "ensemble";
        let e: Ensemble = serde_json::from_str(text).map_err(|e| ModelError::parse(WHAT, e))?;
        if let Some(f) = &e.format {
            if f != "customs-ensemble-v1" {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("unsupported format '{f}'"),
                ));
            }
        }
        let known = |k: &str, at: &str| -> Result<(), ModelError> {
            if COMPONENTS.contains(&k) {
                Ok(())
            } else {
                Err(ModelError::invalid(
                    WHAT,
                    format!("{at}: unknown component '{k}' (expected one of {COMPONENTS:?})"),
                ))
            }
        };
        for c in e.components.iter().flatten() {
            known(c, "components")?;
        }
        let check_weights = |ws: &BTreeMap<String, f64>, at: &str| -> Result<(), ModelError> {
            for (k, v) in ws {
                known(k, at)?;
                if !v.is_finite() {
                    return Err(ModelError::invalid(WHAT, format!("{at}.{k} is not finite")));
                }
            }
            Ok(())
        };
        check_weights(&e.weights, "weights")?;
        if let Some(c) = &e.calibration {
            c.validate(WHAT)?;
        }
        for (i, f) in e.fallbacks.iter().enumerate() {
            let at = format!("fallbacks[{i}]");
            for m in &f.missing {
                known(m, &format!("{at}.missing"))?;
            }
            check_weights(&f.weights, &format!("{at}.weights"))?;
            if let Some(c) = &f.calibration {
                c.validate(WHAT)?;
            }
        }
        if let Some(c) = e.clip {
            if !(c.is_finite() && c > 0.0) {
                return Err(ModelError::invalid(
                    WHAT,
                    "clip must be finite and positive",
                ));
            }
        }
        let t = e.thresholds;
        if !(0.0..=1.0).contains(&t.warn) || !(0.0..=1.0).contains(&t.block) || t.warn > t.block {
            return Err(ModelError::invalid(
                WHAT,
                "thresholds need 0 <= warn <= block <= 1",
            ));
        }
        Ok(e)
    }

    /// Equal-weight stacker used when no `ensemble.json` is shipped. Equal weights mean the
    /// same for any subset of components, so it stacks partial inputs too.
    pub fn unweighted() -> Self {
        Self {
            format: None,
            components: None,
            weights: COMPONENTS.iter().map(|c| (c.to_string(), 1.0)).collect(),
            bias: 0.0,
            fallbacks: Vec::new(),
            calibration: None,
            thresholds: Thresholds::default(),
            clip: None,
            partial: true,
        }
    }

    fn fallback_for(&self, missing: &[&str]) -> Option<&Fallback> {
        self.fallbacks
            .iter()
            .find(|f| same_set(&f.missing, missing))
    }

    /// The weight set for a set of missing components; `None` when nothing ran, or when no
    /// fallback was fitted for that set and the file did not opt in to `partial`.
    fn weight_set(&self, missing: &[&str]) -> Option<WeightSet<'_>> {
        if missing.len() == COMPONENTS.len() {
            None
        } else if missing.is_empty() {
            Some(WeightSet {
                weights: &self.weights,
                bias: self.bias,
                calibration: self.calibration.as_ref(),
                label: "primary".to_string(),
            })
        } else if let Some(f) = self.fallback_for(missing) {
            Some(WeightSet {
                weights: &f.weights,
                bias: f.bias,
                calibration: f.calibration.as_ref().or(self.calibration.as_ref()),
                label: format!("missing:{}", missing.join("+")),
            })
        } else if self.partial {
            Some(WeightSet {
                weights: &self.weights,
                bias: self.bias,
                calibration: self.calibration.as_ref(),
                label: format!("partial:{}", missing.join("+")),
            })
        } else {
            None
        }
    }

    /// Stacking weight of a component under the weight set used for `logits` (0 when
    /// there is no weight set, so nothing is attributed to a stack that did not happen).
    pub fn weight_for(&self, logits: &Logits, component: &str) -> f64 {
        self.weight_set(&logits.missing())
            .and_then(|ws| ws.weights.get(component).copied())
            .unwrap_or(0.0)
    }

    /// A component logit as the stacker sees it.
    pub fn clip_logit(&self, l: f64) -> f64 {
        match self.clip {
            Some(c) => l.clamp(-c, c),
            None => l,
        }
    }

    /// Factor that maps a raw logit to its clipped value, so per-feature contributions
    /// shown as reasons still sum to what the stacker used.
    pub fn clip_scale(&self, l: f64) -> f64 {
        if l == 0.0 {
            1.0
        } else {
            self.clip_logit(l) / l
        }
    }

    /// Combine the available logits. `None` when no component ran or there are no weights
    /// for the set that did (see [`Ensemble::partial`]).
    pub fn combine(&self, logits: &Logits) -> Option<EnsembleOutput> {
        let ws = self.weight_set(&logits.missing())?;
        let mut z = ws.bias;
        for c in COMPONENTS {
            if let Some(l) = logits.get(c) {
                z += ws.weights.get(c).copied().unwrap_or(0.0) * self.clip_logit(l);
            }
        }
        let raw = sigmoid(z);
        let risk = ws.calibration.map(|c| c.apply(raw)).unwrap_or(raw);
        if !(z.is_finite() && risk.is_finite()) {
            // A broken component must not read as "no risk": a NaN would decide Allow and
            // be stored as `null`. Fail closed.
            return Some(EnsembleOutput {
                z,
                raw,
                risk: 1.0,
                weight_set: format!("non_finite:{}", ws.label),
            });
        }
        Some(EnsembleOutput {
            z,
            raw,
            risk,
            weight_set: ws.label,
        })
    }
}

/// Map a risk to a decision with inclusive thresholds (`risk >= block` blocks). A NaN
/// risk blocks: it can only come from a broken model.
pub fn decide(risk: f64, warn: f64, block: f64) -> Decision {
    if risk.is_nan() || risk >= block {
        Decision::Block
    } else if risk >= warn {
        Decision::Warn
    } else {
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ens() -> Ensemble {
        Ensemble::from_json(
            r#"{"format": "customs-ensemble-v1", "components": ["code_gbdt", "code_nn", "name"],
                "weights": {"code_gbdt": 1.0, "code_nn": 0.5, "name": 2.0}, "bias": -1.0,
                "fallbacks": [{"missing": ["code_nn"], "weights": {"code_gbdt": 1.5, "name": 2.0}, "bias": -0.5}],
                "calibration": {"method": "isotonic", "x": [0.0, 1.0], "y": [0.0, 1.0]},
                "thresholds": {"warn": 0.5, "block": 0.9, "target_fpr_warn": 0.01, "target_fpr_block": 0.001}}"#,
        )
        .unwrap()
    }

    #[test]
    fn primary_and_fallback() {
        let e = ens();
        let all = Logits {
            code_gbdt: Some(1.0),
            code_nn: Some(2.0),
            name: Some(0.5),
        };
        let o = e.combine(&all).unwrap();
        assert_eq!(o.weight_set, "primary");
        assert!((o.z - (-1.0 + 1.0 + 1.0 + 1.0)).abs() < 1e-12);

        let no_nn = Logits {
            code_nn: None,
            ..all
        };
        let o = e.combine(&no_nn).unwrap();
        assert_eq!(o.weight_set, "missing:code_nn");
        assert!((o.z - (-0.5 + 1.5 + 1.0)).abs() < 1e-12);
        assert_eq!(e.weight_for(&no_nn, "code_gbdt"), 1.5);

        assert!(e.combine(&Logits::default()).is_none());
        assert_eq!(e.thresholds.target_fpr_warn, Some(0.01));
    }

    #[test]
    fn no_risk_for_a_missing_set_without_fitted_weights() {
        // Like the shipped ensemble: fallbacks only for the sets training fitted. The
        // primary weights were fitted with the code models present, so applying them to a
        // name alone gives a number that means nothing.
        let e = ens();
        let only_name = Logits {
            name: Some(5.0),
            ..Default::default()
        };
        assert!(e.combine(&only_name).is_none());
        assert_eq!(e.weight_for(&only_name, "name"), 0.0);
    }

    #[test]
    fn partial_stacking_only_when_the_file_opts_in() {
        let mut e = ens();
        e.partial = true;
        let only_name = Logits {
            name: Some(0.5),
            ..Default::default()
        };
        let o = e.combine(&only_name).unwrap();
        assert_eq!(o.weight_set, "partial:code_gbdt+code_nn");
        assert!((o.z - 0.0).abs() < 1e-12);
        assert_eq!(e.weight_for(&only_name, "name"), 2.0);
        // The equal-weight stacker used without an ensemble.json stacks any subset.
        let u = Ensemble::unweighted();
        assert_eq!(u.combine(&only_name).unwrap().z, 0.5);
        let parsed = Ensemble::from_json(r#"{"weights": {"name": 1.0}, "partial": true}"#);
        assert!(parsed.unwrap().partial);
    }

    #[test]
    fn clip_bounds_each_logit() {
        let mut e = ens();
        e.clip = Some(3.0);
        let l = Logits {
            code_gbdt: Some(10.0),
            code_nn: Some(-8.0),
            name: Some(0.5),
        };
        let o = e.combine(&l).unwrap();
        assert!((o.z - (-1.0 + 3.0 - 1.5 + 1.0)).abs() < 1e-12);
        assert!((e.clip_scale(10.0) - 0.3).abs() < 1e-12);
        assert_eq!(e.clip_scale(2.0), 1.0);
        assert!(Ensemble::from_json(r#"{"weights": {}, "clip": 0.0}"#).is_err());
        assert!(Ensemble::from_json(r#"{"weights": {}, "clip": 4.0}"#).is_ok());
    }

    #[test]
    fn decisions() {
        assert_eq!(decide(0.95, 0.5, 0.9), Decision::Block);
        assert_eq!(decide(0.9, 0.5, 0.9), Decision::Block);
        assert_eq!(decide(0.6, 0.5, 0.9), Decision::Warn);
        assert_eq!(decide(0.1, 0.5, 0.9), Decision::Allow);
    }

    #[test]
    fn decide_nan_blocks() {
        assert_eq!(decide(f64::NAN, 0.5, 0.9), Decision::Block);
    }

    #[test]
    fn non_finite_logit_fails_closed() {
        // No clip, so a NaN or infinite logit reaches z unbounded.
        let e = ens();
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let l = Logits {
                code_gbdt: Some(1.0),
                code_nn: None,
                name: Some(bad),
            };
            let o = e.combine(&l).unwrap();
            assert_eq!(o.risk, 1.0, "{bad}");
            assert_eq!(o.weight_set, "non_finite:missing:code_nn");
            assert_eq!(decide(o.risk, 0.5, 0.9), Decision::Block);
        }
        // Infinity times a zero weight is NaN too.
        let mut u = Ensemble::unweighted();
        u.weights.insert("name".into(), 0.0);
        let l = Logits {
            name: Some(f64::INFINITY),
            ..Default::default()
        };
        assert_eq!(u.combine(&l).unwrap().risk, 1.0);
    }

    #[test]
    fn validation() {
        assert!(Ensemble::from_json(r#"{"weights": {"bogus": 1.0}}"#).is_err());
        assert!(Ensemble::from_json(
            r#"{"weights": {}, "fallbacks": [{"missing": ["cnn"], "weights": {}}]}"#
        )
        .is_err());
        assert!(Ensemble::from_json(
            r#"{"weights": {}, "thresholds": {"warn": 0.9, "block": 0.5}}"#
        )
        .is_err());
        assert!(Ensemble::from_json(r#"{"format": "v9", "weights": {}}"#).is_err());
    }
}
