//! Parity against the numpy reference implementation in `gen_fixtures.py`.
//!
//! Regenerate the fixtures with `python3 crates/customs-model/tests/gen_fixtures.py`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use customs_model::cnn::CodeCnn;
use customs_model::ensemble::{Ensemble, Logits};
use customs_model::gbdt::TreeEnsemble;
use customs_model::name::{distinct_buckets, NameModel, PopularIndex};
use customs_model::{Models, ScoreInput};
use customs_scan::Ecosystem;
use serde_json::Value;

const TOL: f64 = 1e-5;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(fixtures().join(name)).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn model_text(name: &str) -> String {
    std::fs::read_to_string(fixtures().join("models").join(name)).unwrap()
}

fn close(a: f64, b: f64, what: &str) {
    assert!(
        (a - b).abs() <= TOL,
        "{what}: rust {a} vs reference {b} (diff {})",
        (a - b).abs()
    );
}

fn features(v: &Value) -> BTreeMap<String, f64> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_f64().unwrap()))
        .collect()
}

fn eco(s: &str) -> Ecosystem {
    match s {
        "pypi" => Ecosystem::Pypi,
        "npm" => Ecosystem::Npm,
        _ => panic!("{s}"),
    }
}

fn opt(v: &Value) -> Option<f64> {
    v.as_f64()
}

#[test]
fn gbdt_parity() {
    let m = TreeEnsemble::from_json(&model_text("code_gbdt.json")).unwrap();
    let cases = load("expected_gbdt.json");
    let cases = cases["cases"].as_array().unwrap();
    assert!(cases.len() > 50);
    for (i, c) in cases.iter().enumerate() {
        let f = features(&c["features"]);
        let o = m.predict_map(&f);
        close(o.raw, c["raw"].as_f64().unwrap(), &format!("case {i} raw"));
        close(
            o.prob,
            c["prob"].as_f64().unwrap(),
            &format!("case {i} prob"),
        );
        close(
            o.calibrated,
            c["calibrated"].as_f64().unwrap(),
            &format!("case {i} calibrated"),
        );
        close(
            o.bias,
            c["bias"].as_f64().unwrap(),
            &format!("case {i} bias"),
        );
        let exp = c["contributions"].as_array().unwrap();
        assert_eq!(exp.len(), o.contributions.len());
        for (j, (a, b)) in o.contributions.iter().zip(exp).enumerate() {
            close(
                *a,
                b.as_f64().unwrap(),
                &format!("case {i} contribution {j}"),
            );
        }
        let sum: f64 = o.bias + o.contributions.iter().sum::<f64>();
        close(sum, o.raw, &format!("case {i} contributions sum to raw"));
    }
}

#[test]
fn name_parity() {
    let dir = fixtures().join("models");
    let model = NameModel::from_json(&model_text("name_model.json"), |p| {
        Ok(std::fs::read_to_string(dir.join(p)).unwrap())
    })
    .unwrap();
    let cases = load("expected_name.json");
    for c in cases["cases"].as_array().unwrap() {
        let e = eco(c["ecosystem"].as_str().unwrap());
        let name = c["name"].as_str().unwrap();
        let s = model.score(e, name).unwrap();
        let f = &c["features"];
        let what = name.to_string();
        assert_eq!(
            s.features.normalized,
            f["normalized"].as_str().unwrap(),
            "{what}"
        );
        assert_eq!(s.features.bare, f["bare"].as_str().unwrap(), "{what}");
        for k in [
            "len",
            "n_digits",
            "n_hyphens",
            "n_underscores",
            "n_dots",
            "has_scope",
            "is_popular",
            "dist1",
            "dist2",
            "dist3",
            "digit_suffix",
        ] {
            assert_eq!(
                s.features.get(k).unwrap(),
                f[k].as_f64().unwrap(),
                "{what}: {k}"
            );
        }
        assert_eq!(
            s.features.distance as u64,
            f["distance"].as_u64().unwrap(),
            "{what}: distance"
        );
        assert_eq!(
            s.features.nearest_popular.as_deref(),
            f["nearest_popular"].as_str(),
            "{what}: nearest"
        );
        assert_eq!(
            s.features.contains_popular_token.as_deref(),
            f["contains_popular_token"].as_str(),
            "{what}: token"
        );
        let buckets: Vec<u32> = c["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(
            distinct_buckets(&s.features.normalized, 1, 4, model.n_buckets()),
            buckets,
            "{what}: buckets"
        );
        close(
            s.features.char_ngram_score,
            f["char_ngram_score"].as_f64().unwrap(),
            &format!("{what}: ngram"),
        );
        close(
            s.logit,
            c["logit"].as_f64().unwrap(),
            &format!("{what}: logit"),
        );
        close(
            s.prob,
            c["prob"].as_f64().unwrap(),
            &format!("{what}: prob"),
        );
    }
}

#[test]
fn cnn_parity() {
    let m = CodeCnn::from_json(&model_text("code_nn.json")).unwrap();
    let cases = load("expected_cnn.json");
    for (i, c) in cases["cases"].as_array().unwrap().iter().enumerate() {
        let tokens: Vec<String> = c["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect();
        let ids: Vec<u32> = c["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_u64().unwrap() as u32)
            .collect();
        assert_eq!(m.encode(&tokens), ids, "case {i} ids");
        close(
            m.logit(&tokens) as f64,
            c["logit"].as_f64().unwrap(),
            &format!("case {i} logit"),
        );
    }
}

#[test]
fn ensemble_parity() {
    let e = Ensemble::from_json(&model_text("ensemble.json")).unwrap();
    let cases = load("expected_ensemble.json");
    for (i, c) in cases["cases"].as_array().unwrap().iter().enumerate() {
        let l = &c["logits"];
        let logits = Logits {
            code_gbdt: opt(&l["code_gbdt"]),
            code_nn: opt(&l["code_nn"]),
            name: opt(&l["name"]),
        };
        let out = e.combine(&logits);
        match (&out, c["out"].is_null()) {
            (None, true) => {}
            (Some(o), false) => {
                close(o.z, c["out"]["z"].as_f64().unwrap(), &format!("case {i} z"));
                close(
                    o.risk,
                    c["out"]["risk"].as_f64().unwrap(),
                    &format!("case {i} risk"),
                );
                assert_eq!(o.weight_set, c["out"]["weight_set"].as_str().unwrap());
            }
            _ => panic!("case {i}: availability mismatch"),
        }
    }
}

#[test]
fn bundle_assess_parity() {
    let models = Models::load(fixtures().join("models")).unwrap();
    assert_eq!(models.model_version(), "fixture.2");
    assert!(models.manifest.untrained);
    let cases = load("expected_assess.json");
    for (i, c) in cases["cases"].as_array().unwrap().iter().enumerate() {
        let feats = features(&c["features"]);
        let tokens: Vec<String> = c["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect();
        let input = ScoreInput {
            ecosystem: eco(c["ecosystem"].as_str().unwrap()),
            name: c["name"].as_str(),
            features: Some(&feats),
            tokens: Some(&tokens),
        };
        let a = models.assess(&input);
        let s = &c["scores"];
        for (got, key) in [
            (a.scores.code_gbdt, "code_gbdt"),
            (a.scores.code_nn, "code_nn"),
            (a.scores.name, "name"),
        ] {
            match (got, opt(&s[key])) {
                (None, None) => {}
                (Some(g), Some(e)) => close(g, e, &format!("case {i} {key}")),
                other => panic!("case {i} {key}: {other:?}"),
            }
        }
        match (a.risk, opt(&c["risk"])) {
            (None, None) => {}
            (Some(g), Some(e)) => close(g, e, &format!("case {i} risk")),
            other => panic!("case {i} risk: {other:?}"),
        }
        assert_eq!(
            a.ensemble.as_ref().map(|e| e.weight_set.as_str()),
            c["weight_set"].as_str()
        );
        // Reasons are sorted, labelled, and positive.
        for w in a.reasons.windows(2) {
            assert!(w[0].contribution >= w[1].contribution);
        }
        assert!(a
            .reasons
            .iter()
            .all(|r| r.contribution > 0.0 && !r.label.is_empty()));
    }
}

#[test]
fn name_search_is_fast() {
    // About 5,000 synthetic popular names; scoring one query must take well under a
    // millisecond in release builds. Debug builds are much slower, so the assertion here
    // is loose and the precise number is printed for manual runs with --release.
    let names: Vec<String> = (0..5000u32)
        .map(|i| {
            let len = 4 + (i % 14) as usize;
            (0..len)
                .map(|j| (b'a' + ((i.wrapping_mul(2654435761) >> (j % 24)) % 26) as u8) as char)
                .collect::<String>()
                + &format!("{}", i % 7)
        })
        .collect();
    let pop = PopularIndex::new(Ecosystem::Pypi, names.iter().map(|s| s.as_str()));
    let mut scratch = customs_model::name::Scratch::default();
    let queries = [
        "reqeusts",
        "numpy-helper",
        "abcdefghijk",
        "x",
        "djangorestframwork",
    ];
    let start = std::time::Instant::now();
    let rounds = 50;
    for _ in 0..rounds {
        for q in queries {
            std::hint::black_box(pop.nearest(q, 4, &mut scratch));
        }
    }
    let per = start.elapsed().as_secs_f64() / (rounds * queries.len()) as f64;
    eprintln!(
        "nearest-name search: {:.1} us per query over 5000 names",
        per * 1e6
    );
    assert!(per < 0.02, "too slow: {per}s per query");
}
