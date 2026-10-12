//! Parity of the Rust inference against the Python training pipeline, on the trained models
//! shipped in `models/`.
//!
//! The fixtures in `models/parity/` are written by `customs_ml.evaluate.export` from the
//! reference implementations (`gbdt.predict_raw_exported`, `nn.numpy_forward`,
//! `name_model.score_exported`). If training and serving ever disagree, this fails.
//! The repository ships trained models, so a missing `models/manifest.json` or parity
//! fixture fails the tests; set `CUSTOMS_SKIP_SHIPPED_MODELS=1` to skip them on purpose
//! (for example in a checkout without `models/`). Untrained placeholder models have no
//! parity fixtures and are skipped.

use std::collections::BTreeMap;
use std::path::PathBuf;

use customs_model::ensemble::Logits;
use customs_model::{Decision, Models, ScoreInput};
use customs_scan::Ecosystem;
use serde_json::Value;

fn models_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models")
}

fn skip_requested() -> bool {
    std::env::var_os("CUSTOMS_SKIP_SHIPPED_MODELS").is_some_and(|v| v == "1")
}

fn shipped() -> Option<Models> {
    if !models_dir().join("manifest.json").exists() {
        assert!(
            skip_requested(),
            "models/manifest.json is missing; set CUSTOMS_SKIP_SHIPPED_MODELS=1 to skip"
        );
        eprintln!("CUSTOMS_SKIP_SHIPPED_MODELS=1 and no models/manifest.json, skipping");
        return None;
    }
    let models = Models::load(models_dir()).expect("shipped models load");
    if models.manifest.untrained {
        eprintln!("models/ holds untrained placeholders, skipping");
        return None;
    }
    Some(models)
}

fn fixture(name: &str) -> Option<Vec<Value>> {
    let path = models_dir().join("parity").join(name);
    if !path.exists() && (skip_requested() || shipped().is_none()) {
        return None;
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("trained models need {}: {e}", path.display()));
    Some(serde_json::from_str(&text).expect("parity fixture is valid JSON"))
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

#[test]
fn ensemble_matches_reference_on_shipped_weights() {
    // Written by gen_fixtures.py's independent `ensemble_combine` from models/ensemble.json:
    // clip, Platt calibration, each fallback, and the sets with no fitted weights.
    let Some(models) = shipped() else {
        return;
    };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/expected_shipped_ensemble.json");
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 56);
    let mut sets = std::collections::BTreeSet::new();
    for (i, c) in cases.iter().enumerate() {
        let l = &c["logits"];
        let logits = Logits {
            code_gbdt: l["code_gbdt"].as_f64(),
            code_nn: l["code_nn"].as_f64(),
            name: l["name"].as_f64(),
        };
        let out = models.ensemble.combine(&logits);
        let want = &c["out"];
        match &out {
            None => assert!(
                want.is_null(),
                "case {i}: rust has no risk, reference {want}"
            ),
            Some(o) => {
                assert!(
                    !want.is_null(),
                    "case {i}: rust {o:?}, reference has no risk"
                );
                assert_eq!(
                    o.weight_set,
                    want["weight_set"].as_str().unwrap(),
                    "case {i}"
                );
                for (got, key) in [(o.z, "z"), (o.risk, "risk")] {
                    let w = want[key].as_f64().unwrap();
                    assert!((got - w).abs() < 1e-9, "case {i} {key}: {got} vs {w}");
                }
                sets.insert(o.weight_set.clone());
            }
        }
    }
    assert_eq!(sets.len(), 4, "{sets:?}");
}

#[test]
fn shipped_bundle_assesses_a_scanned_package() {
    let (Some(models), Some(rows), Some(streams)) = (
        shipped(),
        fixture("code_gbdt.json"),
        fixture("code_nn.json"),
    ) else {
        return;
    };
    let features: BTreeMap<String, f64> = rows[0]["features"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_f64().unwrap()))
        .collect();
    let tokens: Vec<String> = streams[2]["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect();
    let a = models.assess(&ScoreInput {
        ecosystem: Ecosystem::Pypi,
        name: Some("requests"),
        features: Some(&features),
        tokens: Some(&tokens),
    });
    assert!((a.logits.code_gbdt.unwrap() - rows[0]["raw"].as_f64().unwrap()).abs() < 1e-6);
    assert!((a.logits.code_nn.unwrap() - streams[2]["logit"].as_f64().unwrap()).abs() < 1e-3);
    let e = a
        .ensemble
        .as_ref()
        .expect("a fully scanned package has a risk");
    assert_eq!(e.weight_set, "primary");
    let risk = a.risk.unwrap();
    assert!((0.0..=1.0).contains(&risk), "{risk}");
    assert_eq!(
        a.decision,
        customs_model::ensemble::decide(risk, a.thresholds.warn, a.thresholds.block)
    );
}
