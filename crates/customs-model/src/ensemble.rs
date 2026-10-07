//! Logistic stacking of the component logits (DESIGN.md section 5, `ensemble.json`).
//!
//! `risk = calibrate(sigmoid(bias + sum_i w_i * logit_i))` over the components that ran.
//! When a component cannot run for an input (no token stream for the CNN, no name, no
//! features), the stacker uses a fallback weight set fitted for exactly the available
//! components, looked up in `fallbacks` by the canonical key, e.g. `"code_gbdt+name"`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::calibration::Calibration;
use crate::{sigmoid, Decision, ModelError};

/// Component names in canonical order. Fallback keys join the available ones with `+`.
pub const COMPONENTS: [&str; 3] = ["code_gbdt", "code_nn", "name"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WeightSet {
    pub weights: BTreeMap<String, f64>,
    #[serde(default)]
    pub bias: f64,
    /// Optional calibration specific to this weight set; the top-level one is used if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration: Option<Calibration>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Thresholds {
    pub warn: f64,
    pub block: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_fpr_block: Option<f64>,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            warn: 0.5,
            block: 0.9,
            target_fpr_block: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ensemble {
    pub weights: BTreeMap<String, f64>,
    #[serde(default)]
    pub bias: f64,
    #[serde(default)]
    pub fallbacks: BTreeMap<String, WeightSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration: Option<Calibration>,
    #[serde(default)]
    pub thresholds: Thresholds,
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

    /// Canonical key of the available components, e.g. `code_gbdt+name`.
    pub fn key(&self) -> String {
        COMPONENTS
            .iter()
            .filter(|c| self.get(c).is_some())
            .copied()
            .collect::<Vec<_>>()
            .join("+")
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
    /// Which weights were used: `"primary"`, a fallback key, or `"partial:<key>"` when no
    /// fallback was shipped and the primary weights were restricted to what ran.
    pub weight_set: String,
}

impl Ensemble {
    pub fn from_json(text: &str) -> Result<Self, ModelError> {
        const WHAT: &str = "ensemble";
        let e: Ensemble = serde_json::from_str(text).map_err(|e| ModelError::parse(WHAT, e))?;
        let check_keys = |ws: &BTreeMap<String, f64>, at: &str| -> Result<(), ModelError> {
            for (k, v) in ws {
                if !COMPONENTS.contains(&k.as_str()) {
                    return Err(ModelError::invalid(
                        WHAT,
                        format!("{at}: unknown component '{k}' (expected one of {COMPONENTS:?})"),
                    ));
                }
                if !v.is_finite() {
                    return Err(ModelError::invalid(WHAT, format!("{at}.{k} is not finite")));
                }
            }
            Ok(())
        };
        check_keys(&e.weights, "weights")?;
        if let Some(c) = &e.calibration {
            c.validate(WHAT)?;
        }
        for (key, ws) in &e.fallbacks {
            check_keys(&ws.weights, &format!("fallbacks.{key}.weights"))?;
            let canon: Vec<&str> = COMPONENTS
                .iter()
                .filter(|c| key.split('+').any(|k| k == **c))
                .copied()
                .collect();
            if canon.join("+") != *key {
                return Err(ModelError::invalid(
                    WHAT,
                    format!("fallbacks key '{key}' is not in canonical form (components joined by '+' in the order {COMPONENTS:?})"),
                ));
            }
            if let Some(c) = &ws.calibration {
                c.validate(WHAT)?;
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

    /// Equal-weight stacker used when no `ensemble.json` is shipped.
    pub fn unweighted() -> Self {
        Self {
            weights: COMPONENTS.iter().map(|c| (c.to_string(), 1.0)).collect(),
            bias: 0.0,
            fallbacks: BTreeMap::new(),
            calibration: None,
            thresholds: Thresholds::default(),
        }
    }

    /// Stacking weight for a component under the set that would be used for `logits`.
    pub fn weight_for(&self, logits: &Logits, component: &str) -> f64 {
        let key = logits.key();
        let all = COMPONENTS.join("+");
        let ws = if key == all {
            &self.weights
        } else {
            self.fallbacks
                .get(&key)
                .map(|w| &w.weights)
                .unwrap_or(&self.weights)
        };
        ws.get(component).copied().unwrap_or(0.0)
    }

    /// Combine the available logits. `None` when no component ran.
    pub fn combine(&self, logits: &Logits) -> Option<EnsembleOutput> {
        let key = logits.key();
        if key.is_empty() {
            return None;
        }
        let all = COMPONENTS.join("+");
        let (weights, bias, calibration, weight_set) = if key == all {
            (&self.weights, self.bias, self.calibration.as_ref(), "primary".to_string())
        } else if let Some(ws) = self.fallbacks.get(&key) {
            (
                &ws.weights,
                ws.bias,
                ws.calibration.as_ref().or(self.calibration.as_ref()),
                key.clone(),
            )
        } else {
            (
                &self.weights,
                self.bias,
                self.calibration.as_ref(),
                format!("partial:{key}"),
            )
        };
        let mut z = bias;
        for c in COMPONENTS {
            if let Some(l) = logits.get(c) {
                z += weights.get(c).copied().unwrap_or(0.0) * l;
            }
        }
        let raw = sigmoid(z);
        let risk = calibration.map(|c| c.apply(raw)).unwrap_or(raw);
        Some(EnsembleOutput {
            z,
            raw,
            risk,
            weight_set,
        })
    }
}

/// Map a risk to a decision with inclusive thresholds (`risk >= block` blocks).
pub fn decide(risk: f64, warn: f64, block: f64) -> Decision {
    if risk >= block {
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
            r#"{"weights": {"code_gbdt": 1.0, "code_nn": 0.5, "name": 2.0}, "bias": -1.0,
                "fallbacks": {"code_gbdt+name": {"weights": {"code_gbdt": 1.5, "name": 2.0}, "bias": -0.5}},
                "calibration": {"method": "isotonic", "x": [0.0, 1.0], "y": [0.0, 1.0]},
                "thresholds": {"warn": 0.5, "block": 0.9, "target_fpr_block": 0.001}}"#,
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
        assert_eq!(o.weight_set, "code_gbdt+name");
        assert!((o.z - (-0.5 + 1.5 + 1.0)).abs() < 1e-12);

        let only_name = Logits {
            name: Some(0.5),
            ..Default::default()
        };
        let o = e.combine(&only_name).unwrap();
        assert_eq!(o.weight_set, "partial:name");
        assert!((o.z - 0.0).abs() < 1e-12);
        assert!(e.combine(&Logits::default()).is_none());
    }

    #[test]
    fn decisions() {
        assert_eq!(decide(0.95, 0.5, 0.9), Decision::Block);
        assert_eq!(decide(0.9, 0.5, 0.9), Decision::Block);
        assert_eq!(decide(0.6, 0.5, 0.9), Decision::Warn);
        assert_eq!(decide(0.1, 0.5, 0.9), Decision::Allow);
    }

    #[test]
    fn validation() {
        assert!(Ensemble::from_json(r#"{"weights": {"bogus": 1.0}}"#).is_err());
        assert!(Ensemble::from_json(
            r#"{"weights": {}, "fallbacks": {"name+code_gbdt": {"weights": {}}}}"#
        )
        .is_err());
        assert!(Ensemble::from_json(r#"{"weights": {}, "thresholds": {"warn": 0.9, "block": 0.5}}"#).is_err());
    }
}
