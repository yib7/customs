//! Gradient-boosted tree ensemble inference (DESIGN.md section 5, `code_gbdt.json`).
//!
//! The format is independent of the training library: every node is either a split
//! (`split`, `threshold`, `left`, `right`, `default_left`, `value`) or a leaf (`leaf`).
//! Features are looked up by name, so the column order of the exporter and the scanner do
//! not have to agree.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::calibration::Calibration;
use crate::{sigmoid, ModelError};

/// On-disk node. Both shapes share one struct so the parser can give precise errors
/// instead of serde's opaque "did not match any variant".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RawNode {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    split: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    threshold: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    left: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    right: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_left: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leaf: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawTree {
    nodes: Vec<RawNode>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawEnsemble {
    feature_names: Vec<String>,
    #[serde(default)]
    base_score: f64,
    #[serde(default = "default_objective")]
    objective: String,
    trees: Vec<RawTree>,
    #[serde(default)]
    calibration: Option<Calibration>,
}

fn default_objective() -> String {
    "binary".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Node {
    Split {
        feature: usize,
        threshold: f64,
        left: usize,
        right: usize,
        default_left: bool,
        /// Expected raw output under this node, used for Saabas contributions.
        value: f64,
    },
    Leaf {
        value: f64,
    },
}

impl Node {
    fn value(&self) -> f64 {
        match *self {
            Node::Split { value, .. } => value,
            Node::Leaf { value } => value,
        }
    }
}

#[derive(Debug, Clone)]
struct Tree {
    nodes: Vec<Node>,
}

/// A loaded tree ensemble.
#[derive(Debug, Clone)]
pub struct TreeEnsemble {
    feature_names: Vec<String>,
    base_score: f64,
    trees: Vec<Tree>,
    calibration: Option<Calibration>,
}

/// Result of scoring one row.
#[derive(Debug, Clone, PartialEq)]
pub struct GbdtOutput {
    /// Raw margin (log-odds) before calibration. This is the logit fed to the stacker.
    pub raw: f64,
    /// `sigmoid(raw)`.
    pub prob: f64,
    /// Isotonic-calibrated probability (equals `prob` when no calibration is shipped).
    pub calibrated: f64,
    /// Saabas bias term: `base_score` plus the root value of every tree.
    pub bias: f64,
    /// Contribution per feature, indexed like [`TreeEnsemble::feature_names`]. They sum,
    /// together with `bias`, to `raw`.
    pub contributions: Vec<f64>,
}

/// One feature's share of a prediction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Contribution {
    pub feature: String,
    /// The input value (NaN when the feature was missing).
    pub value: f64,
    /// Change in raw log-odds attributed to this feature.
    pub contribution: f64,
}

impl TreeEnsemble {
    pub fn from_json(text: &str) -> Result<Self, ModelError> {
        let raw: RawEnsemble =
            serde_json::from_str(text).map_err(|e| ModelError::parse("code_gbdt", e))?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawEnsemble) -> Result<Self, ModelError> {
        const WHAT: &str = "code_gbdt";
        if raw.objective != "binary" {
            return Err(ModelError::invalid(
                WHAT,
                format!("unsupported objective '{}'", raw.objective),
            ));
        }
        if let Some(c) = &raw.calibration {
            c.validate(WHAT)?;
        }
        let n_features = raw.feature_names.len();
        let mut trees = Vec::with_capacity(raw.trees.len());
        for (ti, t) in raw.trees.into_iter().enumerate() {
            trees.push(build_tree(ti, t, n_features)?);
        }
        Ok(Self {
            feature_names: raw.feature_names,
            base_score: raw.base_score,
            trees,
            calibration: raw.calibration,
        })
    }

    pub fn feature_names(&self) -> &[String] {
        &self.feature_names
    }

    pub fn n_trees(&self) -> usize {
        self.trees.len()
    }

    /// Build a dense row in model column order. Absent features become NaN so they take
    /// the `default_left` branch.
    pub fn row_from_map(&self, features: &BTreeMap<String, f64>) -> Vec<f64> {
        self.feature_names
            .iter()
            .map(|n| features.get(n).copied().unwrap_or(f64::NAN))
            .collect()
    }

    pub fn predict_map(&self, features: &BTreeMap<String, f64>) -> GbdtOutput {
        self.predict_row(&self.row_from_map(features))
    }

    /// Score a dense row (`row.len()` must equal the number of model features).
    pub fn predict_row(&self, row: &[f64]) -> GbdtOutput {
        let mut contributions = vec![0.0; self.feature_names.len()];
        let mut raw = self.base_score;
        let mut bias = self.base_score;
        for tree in &self.trees {
            let mut idx = 0usize;
            bias += tree.nodes[0].value();
            loop {
                match tree.nodes[idx] {
                    Node::Leaf { value } => {
                        raw += value;
                        break;
                    }
                    Node::Split {
                        feature,
                        threshold,
                        left,
                        right,
                        default_left,
                        value,
                    } => {
                        let x = row.get(feature).copied().unwrap_or(f64::NAN);
                        let next = if x.is_nan() {
                            if default_left {
                                left
                            } else {
                                right
                            }
                        } else if x <= threshold {
                            left
                        } else {
                            right
                        };
                        contributions[feature] += tree.nodes[next].value() - value;
                        idx = next;
                    }
                }
            }
        }
        let prob = sigmoid(raw);
        let calibrated = match &self.calibration {
            Some(c) => c.apply(prob),
            None => prob,
        };
        GbdtOutput {
            raw,
            prob,
            calibrated,
            bias,
            contributions,
        }
    }

    /// Every non-zero contribution, largest absolute value first.
    pub fn ranked_contributions(&self, out: &GbdtOutput, row: &[f64]) -> Vec<Contribution> {
        let mut v: Vec<Contribution> = out
            .contributions
            .iter()
            .enumerate()
            .filter(|(_, c)| **c != 0.0)
            .map(|(i, c)| Contribution {
                feature: self.feature_names[i].clone(),
                value: row.get(i).copied().unwrap_or(f64::NAN),
                contribution: *c,
            })
            .collect();
        v.sort_by(|a, b| {
            b.contribution
                .abs()
                .partial_cmp(&a.contribution.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.feature.cmp(&b.feature))
        });
        v
    }

    /// The `k` features that pushed the score up the most (positive contributions only),
    /// which is what a user wants to see when asking "why was this flagged".
    pub fn top_positive(&self, out: &GbdtOutput, row: &[f64], k: usize) -> Vec<Contribution> {
        self.ranked_contributions(out, row)
            .into_iter()
            .filter(|c| c.contribution > 0.0)
            .take(k)
            .collect()
    }
}

fn build_tree(ti: usize, t: RawTree, n_features: usize) -> Result<Tree, ModelError> {
    const WHAT: &str = "code_gbdt";
    if t.nodes.is_empty() {
        return Err(ModelError::invalid(WHAT, format!("tree {ti} has no nodes")));
    }
    let n = t.nodes.len();
    let mut nodes = Vec::with_capacity(n);
    for (ni, rn) in t.nodes.iter().enumerate() {
        let at = || format!("tree {ti} node {ni}");
        if let Some(leaf) = rn.leaf {
            if !leaf.is_finite() {
                return Err(ModelError::invalid(WHAT, format!("{}: leaf is not finite", at())));
            }
            nodes.push(Node::Leaf { value: leaf });
            continue;
        }
        let (Some(feature), Some(threshold), Some(left), Some(right)) =
            (rn.split, rn.threshold, rn.left, rn.right)
        else {
            return Err(ModelError::invalid(
                WHAT,
                format!(
                    "{}: needs either 'leaf' or all of 'split', 'threshold', 'left', 'right'",
                    at()
                ),
            ));
        };
        if feature >= n_features {
            return Err(ModelError::invalid(
                WHAT,
                format!("{}: split feature {feature} out of range", at()),
            ));
        }
        if left >= n || right >= n || left <= ni || right <= ni {
            // Requiring children after their parent rules out cycles cheaply; every
            // exporter we know writes nodes in pre-order or breadth-first order.
            return Err(ModelError::invalid(
                WHAT,
                format!("{}: child index must point forward inside the tree", at()),
            ));
        }
        nodes.push(Node::Split {
            feature,
            threshold,
            left,
            right,
            default_left: rn.default_left.unwrap_or(true),
            value: rn.value.unwrap_or(f64::NAN),
        });
    }
    // Fill missing split `value`s with the unweighted mean of the leaves below. Exporters
    // are expected to write a cover-weighted value; this fallback keeps contributions
    // summing to the prediction even for hand-written trees.
    for i in 0..n {
        if matches!(nodes[i], Node::Split { value, .. } if value.is_nan()) {
            let mean = leaf_mean(&nodes, i);
            if let Node::Split { value, .. } = &mut nodes[i] {
                *value = mean;
            }
        }
    }
    Ok(Tree { nodes })
}

fn leaf_mean(nodes: &[Node], root: usize) -> f64 {
    let mut stack = vec![root];
    let (mut sum, mut count) = (0.0, 0usize);
    while let Some(i) = stack.pop() {
        match nodes[i] {
            Node::Leaf { value } => {
                sum += value;
                count += 1;
            }
            Node::Split { left, right, .. } => {
                stack.push(left);
                stack.push(right);
            }
        }
    }
    if count == 0 {
        0.0
    } else {
        sum / count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> TreeEnsemble {
        TreeEnsemble::from_json(
            r#"{
            "feature_names": ["a", "b"],
            "base_score": 0.5,
            "trees": [
              {"nodes": [
                {"split": 0, "threshold": 1.0, "left": 1, "right": 2, "default_left": false, "value": 0.1},
                {"leaf": -1.0},
                {"split": 1, "threshold": 0.0, "left": 3, "right": 4, "default_left": true, "value": 0.6},
                {"leaf": 0.2},
                {"leaf": 1.0}
              ]},
              {"nodes": [{"leaf": 0.25}]}
            ]
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn routes_and_sums() {
        let m = model();
        // a <= 1 goes left: leaf -1.
        let o = m.predict_row(&[1.0, 5.0]);
        assert!((o.raw - (0.5 - 1.0 + 0.25)).abs() < 1e-12);
        // a missing, default right; b missing, default left: leaf 0.2.
        let o = m.predict_row(&[f64::NAN, f64::NAN]);
        assert!((o.raw - (0.5 + 0.2 + 0.25)).abs() < 1e-12);
        let total: f64 = o.bias + o.contributions.iter().sum::<f64>();
        assert!((total - o.raw).abs() < 1e-12);
        assert!((o.contributions[0] - 0.5).abs() < 1e-12);
        assert!((o.contributions[1] - (0.2 - 0.6)).abs() < 1e-12);
    }

    #[test]
    fn by_name_lookup() {
        let m = model();
        let mut f = BTreeMap::new();
        f.insert("b".to_string(), 3.0);
        f.insert("a".to_string(), 2.0);
        f.insert("unused".to_string(), 9.0);
        let o = m.predict_map(&f);
        assert!((o.raw - (0.5 + 1.0 + 0.25)).abs() < 1e-12);
        let row = m.row_from_map(&f);
        let top = m.top_positive(&o, &row, 5);
        assert_eq!(top[0].feature, "a");
        assert_eq!(top[0].value, 2.0);
    }

    #[test]
    fn missing_values_get_filled() {
        let m = TreeEnsemble::from_json(
            r#"{"feature_names": ["a"], "trees": [{"nodes": [
                {"split": 0, "threshold": 0.0, "left": 1, "right": 2},
                {"leaf": -1.0}, {"leaf": 3.0}]}]}"#,
        )
        .unwrap();
        let o = m.predict_row(&[1.0]);
        assert!((o.bias - 1.0).abs() < 1e-12);
        assert!((o.contributions[0] - 2.0).abs() < 1e-12);
    }

    #[test]
    fn rejects_bad_trees() {
        let bad = [
            r#"{"feature_names": ["a"], "trees": [{"nodes": []}]}"#,
            r#"{"feature_names": ["a"], "trees": [{"nodes": [{"split": 3, "threshold": 0, "left": 1, "right": 2}, {"leaf": 0}, {"leaf": 0}]}]}"#,
            r#"{"feature_names": ["a"], "trees": [{"nodes": [{"split": 0, "threshold": 0, "left": 0, "right": 1}, {"leaf": 0}]}]}"#,
            r#"{"feature_names": ["a"], "trees": [{"nodes": [{"threshold": 0}]}]}"#,
            r#"{"feature_names": ["a"], "objective": "regression", "trees": []}"#,
        ];
        for b in bad {
            assert!(TreeEnsemble::from_json(b).is_err(), "{b}");
        }
    }
}
