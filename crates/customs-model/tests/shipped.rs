//! Parity of the Rust inference against the Python training pipeline, on the trained models
//! shipped in `models/`.
//!
//! The fixtures in `models/parity/` are written by `customs_ml.evaluate.export` from the
//! reference implementations (`gbdt.predict_raw_exported`, `nn.numpy_forward`,
//! `name_model.score_exported`). If training and serving ever disagree, this fails.
//! Skipped when no trained models are present (for example in a fresh checkout that only
//! has `models/dev`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use customs_model::{Decision, Models, ScoreInput};
use customs_scan::Ecosystem;
use serde_json::Value;

fn models_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models")
}

fn fixture(name: &str) -> Option<Vec<Value>> {
    let text = std::fs::read_to_string(models_dir().join("parity").join(name)).ok()?;
    Some(serde_json::from_str(&text).expect("parity fixture is valid JSON"))
}

fn shipped() -> Option<Models> {
    if !models_dir().join("manifest.json").exists() {
        eprintln!("no trained models in models/, skipping");
        return None;
    }
    Some(Models::load(models_dir()).expect("shipped models load"))
}

#[test]
fn tree_ensemble_matches_training() {
    let (Some(models), Some(cases)) = (shipped(), fixture("code_gbdt.json")) else {
        return;
    };
    let gbdt = models.code_gbdt.as_ref().expect("code_gbdt loaded");
    for case in cases {
        let features: BTreeMap<String, f64> = case["features"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_f64().unwrap()))
            .collect();
        let out = gbdt.predict_map(&features);
        let want = case["raw"].as_f64().unwrap();
        assert!((out.raw - want).abs() < 1e-6, "raw {} vs {want}", out.raw);
        let bias = case["bias"].as_f64().unwrap();
        assert!(
            (out.bias - bias).abs() < 1e-6,
            "bias {} vs {bias}",
            out.bias
        );
    }
}

#[test]
fn code_cnn_matches_training() {
    let (Some(models), Some(cases)) = (shipped(), fixture("code_nn.json")) else {
        return;
    };
    let cnn = models.code_nn.as_ref().expect("code_nn loaded");
    for case in cases {
        let tokens: Vec<String> = case["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect();
        let got = f64::from(cnn.logit(&tokens));
        let want = case["logit"].as_f64().unwrap();
        // f32 accumulation over up to max_len x kernel x dim terms.
        assert!((got - want).abs() < 1e-3, "cnn logit {got} vs {want}");
    }
}

#[test]
fn name_model_matches_training() {
    let (Some(models), Some(cases)) = (shipped(), fixture("name_model.json")) else {
        return;
    };
    let nm = models.name_model.as_ref().expect("name_model loaded");
    for case in cases {
        let eco = match case["ecosystem"].as_str().unwrap() {
            "pypi" => Ecosystem::Pypi,
            _ => Ecosystem::Npm,
        };
        let name = case["name"].as_str().unwrap();
        let got = nm.score(eco, name).expect("ecosystem present").logit;
        let want = case["logit"].as_f64().unwrap();
        assert!((got - want).abs() < 1e-4, "{name}: {got} vs {want}");
    }
}

#[test]
fn popular_rank_reads_the_shipped_lists() {
    let Some(models) = shipped() else {
        return;
    };
    assert_eq!(models.popular_rank(Ecosystem::Pypi, "requests"), Some(6));
    assert_eq!(
        models.popular_rank(Ecosystem::Pypi, "Typing_Extensions"),
        Some(2)
    );
    assert_eq!(models.popular_rank(Ecosystem::Npm, "postcss"), Some(48));
    assert_eq!(models.popular_rank(Ecosystem::Pypi, "reqeusts"), None);
    assert_eq!(models.popular_rank(Ecosystem::Npm, "requests"), None);
    assert_eq!(
        Models::empty().popular_rank(Ecosystem::Pypi, "requests"),
        None
    );
}

#[test]
fn a_name_alone_gets_no_model_risk_but_keeps_the_nearest_popular_name() {
    let Some(models) = shipped() else {
        return;
    };
    // The shipped ensemble fits no weights for a name without code, so a package that was
    // not scanned (nonexistent, or above the size limits) has no model risk...
    let a = models.assess(&ScoreInput {
        ecosystem: Ecosystem::Pypi,
        name: Some("reqeusts"),
        features: None,
        tokens: None,
    });
    assert!(a.name.is_some());
    assert_eq!(a.risk, None);
    assert_eq!(a.decision, Decision::Allow);
    // ...but the verdict still names the package it imitates.
    let r = a
        .reasons
        .iter()
        .find(|r| r.feature == "name_dist1")
        .expect("nearest popular name reason");
    assert!(r.label.contains("'requests'"), "{}", r.label);
    assert!(r.contribution >= 0.0);
}
