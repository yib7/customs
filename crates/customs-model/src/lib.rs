//! Model inference for Customs (DESIGN.md section 5).
//!
//! Three components score a package, then a logistic stacker combines them:
//!
//! - [`gbdt::TreeEnsemble`]: gradient-boosted trees over the static features from
//!   `customs-scan`, with Saabas per-feature contributions for explanations.
//! - [`name::NameModel`]: logistic regression over package-name features (edit distance to
//!   popular packages, token wrapping, scope squatting) and hashed character n-grams.
//! - [`cnn::CodeCnn`]: a small convolutional network over the install-surface tokens.
//!
//! [`Models`] loads `manifest.json` and everything it names, and [`Models::assess`] runs
//! whichever components have inputs, so a missing token stream or a missing artifact
//! degrades the score instead of failing it.

pub mod bundle;
pub mod calibration;
pub mod cnn;
pub mod ensemble;
pub mod gbdt;
pub mod labels;
pub mod name;

use serde::{Deserialize, Serialize};

pub use bundle::{Assessment, Manifest, Models, Reason, ScoreInput, Scores};
pub use ensemble::{decide, Thresholds};

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("{what}: cannot read {path}: {source}")]
    Io {
        what: String,
        path: String,
        source: std::io::Error,
    },
    #[error("{what}: invalid JSON: {source}")]
    Parse {
        what: String,
        source: serde_json::Error,
    },
    #[error("{what}: {msg}")]
    Invalid { what: String, msg: String },
}

impl ModelError {
    pub(crate) fn parse(what: &str, source: serde_json::Error) -> Self {
        Self::Parse {
            what: what.to_string(),
            source,
        }
    }

    pub(crate) fn invalid(what: &str, msg: impl Into<String>) -> Self {
        Self::Invalid {
            what: what.to_string(),
            msg: msg.into(),
        }
    }
}

/// A verdict decision. Ordered by severity so `max` picks the most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Warn,
    Block,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Warn => "warn",
            Decision::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Decision::Allow),
            "warn" => Some(Decision::Warn),
            "block" => Some(Decision::Block),
            _ => None,
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Numerically stable logistic function.
pub fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigmoid_is_stable() {
        assert_eq!(sigmoid(0.0), 0.5);
        assert!(sigmoid(-1000.0) >= 0.0);
        assert!(sigmoid(1000.0) <= 1.0);
        assert!((sigmoid(2.0) + sigmoid(-2.0) - 1.0).abs() < 1e-15);
    }

    #[test]
    fn decision_order() {
        assert!(Decision::Block > Decision::Warn);
        assert!(Decision::Warn > Decision::Allow);
        assert_eq!(Decision::parse("warn"), Some(Decision::Warn));
    }
}
