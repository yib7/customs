//! Loading the artifact set named by `models/manifest.json` and scoring one package.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use customs_scan::Ecosystem;
use serde::{Deserialize, Serialize};

use crate::cnn::CodeCnn;
use crate::ensemble::{decide, Ensemble, EnsembleOutput, Logits, Thresholds};
use crate::gbdt::TreeEnsemble;
use crate::labels;
use crate::name::{NameModel, NameScore};
use crate::{sigmoid, Decision, ModelError};

/// `models/manifest.json`. Component entries are file names relative to the manifest; a
/// missing or null entry means the component is not shipped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub model_version: String,
    pub feature_schema_version: u32,
    #[serde(default)]
    pub code_gbdt: Option<String>,
    #[serde(default)]
    pub name_model: Option<String>,
    #[serde(default)]
    pub code_nn: Option<String>,
    #[serde(default)]
    pub ensemble: Option<String>,
    /// Informational; the name model names its own popular lists.
    #[serde(default)]
    pub popular_names: BTreeMap<String, String>,
    /// True for placeholder artifacts that were not trained on data (`models/dev`).
    #[serde(default)]
    pub untrained: bool,
    /// Optional evaluation summary, default `metrics.json` when that file exists.
    #[serde(default)]
    pub metrics: Option<String>,
    /// Anything else the exporter writes is kept and shown by `/api/model`.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Everything needed to score packages.
#[derive(Debug, Clone)]
pub struct Models {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub code_gbdt: Option<TreeEnsemble>,
    pub name_model: Option<NameModel>,
    pub code_nn: Option<CodeCnn>,
    pub ensemble: Ensemble,
    /// False when `ensemble.json` was absent and equal weights are in use.
    pub ensemble_shipped: bool,
    pub metrics: Option<serde_json::Value>,
}

/// Inputs for one assessment. Any of them may be absent.
#[derive(Debug, Clone, Copy)]
pub struct ScoreInput<'a> {
    pub ecosystem: Ecosystem,
    pub name: Option<&'a str>,
    /// Static features; `None` or empty means the archive was not scanned.
    pub features: Option<&'a BTreeMap<String, f64>>,
    pub tokens: Option<&'a [String]>,
}

/// Calibrated per-component probabilities (DESIGN.md section 6 `scores`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Scores {
    pub code_gbdt: Option<f64>,
    pub code_nn: Option<f64>,
    pub name: Option<f64>,
}

/// One explanation line (DESIGN.md section 6 `reasons`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub feature: String,
    /// Input value; `null` when the feature was missing.
    pub value: Option<f64>,
    /// Contribution to the stacked log-odds.
    pub contribution: f64,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Assessment {
    /// Calibrated ensemble risk, `None` when no component could run.
    pub risk: Option<f64>,
    /// Decision under the model thresholds (`Allow` when `risk` is `None`).
    pub decision: Decision,
    pub thresholds: Thresholds,
    pub scores: Scores,
    pub logits: Logits,
    pub ensemble: Option<EnsembleOutput>,
    pub reasons: Vec<Reason>,
    pub name: Option<NameScore>,
}

impl Models {
    /// Models with no components: every assessment has no risk. Used when no artifacts
    /// can be found, so policy rules still work.
    pub fn empty() -> Self {
        Self {
            dir: PathBuf::new(),
            manifest: Manifest {
                model_version: "none".to_string(),
                feature_schema_version: customs_scan::FEATURE_SCHEMA_VERSION,
                code_gbdt: None,
                name_model: None,
                code_nn: None,
                ensemble: None,
                popular_names: BTreeMap::new(),
                untrained: true,
                metrics: None,
                extra: Default::default(),
            },
            code_gbdt: None,
            name_model: None,
            code_nn: None,
            ensemble: Ensemble::unweighted(),
            ensemble_shipped: false,
            metrics: None,
        }
    }

    /// Load `dir/manifest.json` and every artifact it names.
    pub fn load(dir: impl AsRef<Path>) -> Result<Self, ModelError> {
        let dir = dir.as_ref().to_path_buf();
        let read = |what: &str, file: &str| -> Result<String, ModelError> {
            let path = dir.join(file);
            std::fs::read_to_string(&path).map_err(|source| ModelError::Io {
                what: what.to_string(),
                path: path.display().to_string(),
                source,
            })
        };
        let manifest: Manifest = serde_json::from_str(&read("manifest", "manifest.json")?)
            .map_err(|e| ModelError::parse("manifest", e))?;
        if manifest.feature_schema_version != customs_scan::FEATURE_SCHEMA_VERSION {
            return Err(ModelError::invalid(
                "manifest",
                format!(
                    "models expect feature schema {} but customs-scan produces {}",
                    manifest.feature_schema_version,
                    customs_scan::FEATURE_SCHEMA_VERSION
                ),
            ));
        }
        let code_gbdt = manifest
            .code_gbdt
            .as_deref()
            .map(|f| TreeEnsemble::from_json(&read("code_gbdt", f)?))
            .transpose()?;
        let name_model = manifest
            .name_model
            .as_deref()
            .map(|f| NameModel::from_json(&read("name_model", f)?, |p| read("popular_names", p)))
            .transpose()?;
        let code_nn = manifest
            .code_nn
            .as_deref()
            .map(|f| CodeCnn::from_json(&read("code_nn", f)?))
            .transpose()?;
        let (ensemble, ensemble_shipped) = match manifest.ensemble.as_deref() {
            Some(f) => (Ensemble::from_json(&read("ensemble", f)?)?, true),
            None => (Ensemble::unweighted(), false),
        };
        let metrics_file = manifest.metrics.clone().or_else(|| {
            dir.join("metrics.json")
                .exists()
                .then(|| "metrics.json".to_string())
        });
        let metrics = match metrics_file {
            Some(f) => Some(
                serde_json::from_str(&read("metrics", &f)?)
                    .map_err(|e| ModelError::parse("metrics", e))?,
            ),
            None => None,
        };
        Ok(Self {
            dir,
            manifest,
            code_gbdt,
            name_model,
            code_nn,
            ensemble,
            ensemble_shipped,
            metrics,
        })
    }

    pub fn model_version(&self) -> &str {
        &self.manifest.model_version
    }

    pub fn thresholds(&self) -> Thresholds {
        self.ensemble.thresholds
    }

    /// Score the name alone (used for packages that do not exist on the registry).
    pub fn score_name(&self, eco: Ecosystem, name: &str) -> Option<NameScore> {
        self.name_model.as_ref().and_then(|m| m.score(eco, name))
    }

    /// Size of the popular-name list for an ecosystem.
    pub fn popular_count(&self, eco: Ecosystem) -> usize {
        self.name_model
            .as_ref()
            .and_then(|m| m.ecosystem(eco))
            .map(|e| e.popular.len())
            .unwrap_or(0)
    }

    /// Run every component that has inputs and combine them.
    pub fn assess(&self, input: &ScoreInput<'_>) -> Assessment {
        self.assess_with(input, None)
    }

    /// Like [`Models::assess`] with explicit thresholds (policy overrides).
    pub fn assess_with(
        &self,
        input: &ScoreInput<'_>,
        thresholds: Option<Thresholds>,
    ) -> Assessment {
        let thresholds = thresholds.unwrap_or(self.ensemble.thresholds);
        let mut scores = Scores::default();
        let mut logits = Logits::default();

        let gbdt = match (&self.code_gbdt, input.features) {
            (Some(m), Some(f)) if !f.is_empty() => {
                let row = m.row_from_map(f);
                let out = m.predict_row(&row);
                scores.code_gbdt = Some(out.calibrated);
                logits.code_gbdt = Some(out.raw);
                Some((m, row, out))
            }
            _ => None,
        };
        if let (Some(m), Some(t)) = (&self.code_nn, input.tokens) {
            if !t.is_empty() {
                let l = m.logit(t) as f64;
                scores.code_nn = Some(sigmoid(l));
                logits.code_nn = Some(l);
            }
        }
        let name = input
            .name
            .filter(|n| !n.trim().is_empty())
            .and_then(|n| self.score_name(input.ecosystem, n));
        if let Some(ns) = &name {
            scores.name = Some(ns.prob);
            logits.name = Some(ns.logit);
        }

        let ensemble = self.ensemble.combine(&logits);
        let risk = ensemble.as_ref().map(|e| e.risk);
        let decision = risk
            .map(|r| decide(r, thresholds.warn, thresholds.block))
            .unwrap_or(Decision::Allow);

        let mut reasons = Vec::new();
        if let Some((m, row, out)) = &gbdt {
            let w = self.ensemble.weight_for(&logits, "code_gbdt");
            for c in m.top_positive(out, row, 8) {
                reasons.push(Reason {
                    label: labels::label_or_name(&c.feature),
                    value: c.value.is_finite().then_some(c.value),
                    contribution: w * c.contribution,
                    feature: c.feature,
                });
            }
        }
        if let Some(ns) = &name {
            let w = self.ensemble.weight_for(&logits, "name");
            // Prefer the human explanation (edit distance to a popular name, typo, scope)
            // when the name model leans malicious; otherwise report its largest term.
            let explained = ns
                .explanation
                .as_ref()
                .zip(ns.features.explanation_feature())
                .filter(|_| w * ns.logit > 0.0);
            if let Some((text, (feat, value))) = explained {
                reasons.push(Reason {
                    feature: format!("name_{feat}"),
                    value: Some(value),
                    contribution: w * ns.logit,
                    label: text.clone(),
                });
            } else if let Some((feat, value, c)) = ns.contributions.first() {
                if *c > 0.0 && w * c > 0.0 {
                    let feature = format!("name_{feat}");
                    let label = ns
                        .explanation
                        .clone()
                        .unwrap_or_else(|| labels::label_or_name(&feature));
                    reasons.push(Reason {
                        feature,
                        value: Some(*value),
                        contribution: w * c,
                        label,
                    });
                }
            }
        }
        reasons.sort_by(|a, b| {
            b.contribution
                .partial_cmp(&a.contribution)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        reasons.truncate(6);

        Assessment {
            risk,
            decision,
            thresholds,
            scores,
            logits,
            ensemble,
            reasons,
            name,
        }
    }
}
