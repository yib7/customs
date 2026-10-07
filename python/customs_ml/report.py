"""Render docs/EVALUATION.md from the evaluation artifacts in $CUSTOMS_DATA/work.

Run after `evaluate` and `robustness`:  python -m customs_ml.report
"""

from __future__ import annotations

import json

from . import config
from .pipeline import SCHEME, work


def _load(name: str) -> dict | None:
    p = work() / name
    return json.loads(p.read_text()) if p.exists() else None


def pct(x, digits: int = 1) -> str:
    if x is None:
        return "n/a"
    v = x["value"] if isinstance(x, dict) else x
    return f"{100 * v:.{digits}f}%"


def ci(x, digits: int = 1, scale: float = 100.0, unit: str = "%") -> str:
    if not isinstance(x, dict):
        return pct(x, digits)
    return (
        f"{scale * x['value']:.{digits}f}{unit} "
        f"({scale * x['ci_low']:.{digits}f} to {scale * x['ci_high']:.{digits}f})"
    )


def num(x, digits: int = 3) -> str:
    v = x["value"] if isinstance(x, dict) else x
    return "n/a" if v is None else f"{v:.{digits}f}"


def render(scheme: str = SCHEME) -> str:
    ev = _load(f"eval_{scheme}.json")
    base = _load(f"baseline_eval_{scheme}.json")
    rob = _load(f"robustness_{scheme}.json")
    base_rob = _load(f"baseline_robustness_{scheme}.json")
    abl = _load(f"ablation_{scheme}.json")
    base_abl = _load(f"baseline_ablation_{scheme}.json")
    names_rep = _load("name_report.json")
    ens = _load(f"ensemble_{scheme}.json")
    h = ev["headline"]
    c = ev["counts"]
    sm = ev["split_meta"]
    L: list[str] = []
    add = L.append

    add("# Customs: evaluation report\n")
    add(
        f"Generated {ev['generated']} by `python -m customs_ml.report` from the artifacts of "
        "`python -m customs_ml.pipeline`. Every number below is on held-out test data with "
        "thresholds frozen on the validation split, unless a row says otherwise.\n"
    )

    add("## Data\n")
    add("| Split | Malicious | Benign |\n|---|---:|---:|")
    for s in ("train", "val", "test"):
        add(f"| {s} | {c[s]['malicious']:,} | {c[s]['benign']:,} |")
    add("")
    add(
        f"* **Temporal split.** Test malware was discovered on or after {sm['test_cutoff']}; "
        f"validation malware between {sm['val_cutoff']} and that date; training malware "
        "before. The model never saw a sample from the test period."
    )
    add(
        "* **Benign packages** are split at random by near-duplicate cluster in the same "
        "proportions, sampled across three popularity tiers (top, mid, long tail) of PyPI "
        "and npm."
    )
    add(
        "* **Near-duplicates.** MinHash LSH clusters (Jaccard about 0.7 on install-time token "
        "5-grams) group malware campaigns. Clusters are the unit for benign splitting, "
        "sample weighting (1/sqrt(cluster size)) and for every confidence interval (cluster "
        "bootstrap, 1,000 resamples)."
    )
    add(
        "* **Canonicalization.** Both classes are repacked into identical deterministic "
        "tarballs before scanning, so archive format cannot leak the label.\n"
    )

    add("## Headline (ensemble)\n")
    add("| Metric | Test value (95% CI) |\n|---|---|")
    add(f"| ROC AUC | {ci(h['roc_auc'], 3, 1, '')} |")
    add(f"| PR AUC | {ci(h['pr_auc'], 3, 1, '')} |")
    add(
        f"| Detection rate at the **block** threshold (target FPR 0.1%) | "
        f"{ci(h['recall_at_fpr_0_001'])} |"
    )
    add(f"| Realized test FPR at block | {ci(h['test_fpr_block'], 2)} |")
    add(
        f"| Detection rate at the **warn** threshold (target FPR 1%) | "
        f"{ci(h['recall_at_fpr_0_01'])} |"
    )
    add(f"| Realized test FPR at warn | {ci(h['test_fpr_warn'], 2)} |")
    if "roc_recall_at_fpr_0_001" in h:
        add(
            f"| Detection at exactly 0.1% FPR on the test ROC (threshold-free) | "
            f"{ci(h['roc_recall_at_fpr_0_001'])} |"
        )
        add(
            f"| Detection at exactly 1% FPR on the test ROC (threshold-free) | "
            f"{ci(h['roc_recall_at_fpr_0_01'])} |"
        )
    add(f"| Brier score | {num(h['brier'])} |")
    add(f"| Expected calibration error | {num(h['ece'])} |")
    add("")
    add("![ROC curves](figures/roc.png)\n")

    add("## Components\n")
    add("Each component's thresholds were chosen on validation at the same target FPRs.\n")
    add(
        "| Model | ROC AUC | PR AUC | Recall at block | FPR at block | Recall at warn | "
        "FPR at warn |\n|---|---:|---:|---:|---:|---:|---:|"
    )
    for name, m in ev["components"].items():
        add(
            f"| {name} | {m['roc_auc']:.3f} | {m['pr_auc']:.3f} | {pct(m['recall_at']['block'])} "
            f"| {pct(m['fpr_at']['block'], 2)} | {pct(m['recall_at']['warn'])} | "
            f"{pct(m['fpr_at']['warn'], 2)} |"
        )
    add("")
    if ens:
        w = ens["weights"]
        add(
            f"Stacking weights on component logits: code GBDT {w['code_gbdt']:.2f}, code CNN "
            f"{w['code_nn']:.2f}, name {w['name']:.2f} (fit on validation with 5-fold "
            "cluster-grouped cross-fitting; calibration and thresholds use out-of-fold "
            "scores).\n"
        )

    gd = ev.get("guarddog") or {}
    if gd:
        add("## Against GuardDog\n")
        add(
            "[GuardDog](https://github.com/DataDog/guarddog) (Datadog's open-source scanner, "
            "v3.2) on the same canonical test archives, a fixed random sample of "
            f"{gd['n_malicious']:,} malicious and {gd['n_benign']:,} benign. Note the bias: "
            "most samples in Datadog's dataset were originally found with GuardDog's rules, "
            "so this comparison favours GuardDog.\n"
        )
        add("| | GuardDog | Customs |\n|---|---:|---:|")
        add(
            f"| ROC AUC (GuardDog risk score vs Customs risk) | {gd['roc_auc']:.3f} | "
            f"{gd['customs_roc_auc_same_rows']:.3f} |"
        )
        add(f"| Any finding: FPR | {pct(gd['fpr'])} | same FPR by construction |")
        add(
            f"| Any finding: detection rate | {pct(gd['recall'])} | "
            f"{pct(gd['customs_recall_at_matched_fpr'])} |"
        )
        if "customs_recall_at_high_risk_fpr" in gd:
            add(
                f"| `high_risk` label: FPR | {pct(gd['high_risk_fpr'])} | same FPR by "
                "construction |"
            )
            add(
                f"| `high_risk` label: detection rate | {pct(gd['high_risk_recall'])} | "
                f"{pct(gd['customs_recall_at_high_risk_fpr'])} |"
            )
        lo, hi = gd["recall_gain_ci"]
        add("")
        add(
            "At GuardDog's own false-positive rate, Customs' detection-rate gain has a "
            f"paired cluster-bootstrap 95% CI of {100 * lo:.1f} to {100 * hi:.1f} points. "
            "(For this comparison only, Customs' threshold is set on the test benign "
            "packages to match GuardDog's realized FPR; that is what matched-FPR means.)\n"
        )

    add("## Where it is weak\n")
    add("| Slice | n malicious | n benign | ROC AUC | Recall at block | FPR at block |")
    add("|---|---:|---:|---:|---:|---:|")
    for name, s in ev["slices"].items():
        if "roc_auc" not in s:
            continue
        add(
            f"| {name} | {s['n_pos']:,} | {s['n_neg']:,} | {s['roc_auc']:.3f} | "
            f"{pct(s['recall_at']['block'])} | {pct(s['fpr_at']['block'], 2)} |"
        )
    add("")
    add("False-positive rate on benign packages by popularity tier:\n")
    add("| Tier | n | FPR at block | FPR at warn |\n|---|---:|---:|---:|")
    for tier in ("top", "mid", "tail"):
        s = ev["slices"].get(f"benign:{tier}")
        if s:
            add(f"| {tier} | {s['n']:,} | {pct(s['fpr_block'], 2)} | {pct(s['fpr_warn'], 2)} |")
    add("")
    add(
        "`malicious:*` slices are each malicious subset against all benign test packages. "
        "`novel_campaigns` are test samples whose near-duplicate cluster has no member in "
        "training: the closest thing to a never-seen attack. Size terciles cut on benign "
        "source-line counts, to expose any small-package shortcut.\n"
    )

    if abl:
        add("## Ablation: what does the code itself say?\n")
        add(
            f"The tree model retrained on {abl['n_features']} behavior features only "
            "(indicator counts and obfuscation statistics; no manifest metadata, sizes, or "
            "file counts):\n"
        )
        add("| Feature set | ROC AUC | Recall at block | Recall at warn |\n|---|---:|---:|---:|")
        rows = [("All features", abl["all_features"]), ("Behavior only", abl["behavior_only"])]
        if base_abl:
            rows = [("All features (before augmentation)", base_abl["all_features"])] + rows
        for label, m in rows:
            add(
                f"| {label} | {m['roc_auc']:.3f} | {pct(m['recall_at']['block'])} | "
                f"{pct(m['recall_at']['warn'])} |"
            )
        add("")

    if rob:
        add("## Adversarial robustness\n")
        add(
            "Held-out test malware rewritten as text (never executed), re-scanned and "
            "re-scored. Detection rate at the block and warn thresholds. *Seen* transforms "
            "are families the augmentation stage trained on (with donors from the training "
            "split; the test donors are different packages). *Unseen* ones were never "
            "used in training.\n"
        )
        seen = set(rob.get("seen_in_training", []))
        hdr = "| Transform | Seen in training | Block | Warn |"
        sep = "|---|---|---:|---:|"
        if base_rob:
            hdr = (
                "| Transform | Seen in training | Block (before) | Block (after) | "
                "Warn (before) | Warn (after) |"
            )
            sep = "|---|---|---:|---:|---:|---:|"
        add(hdr)
        add(sep)
        for t, r in rob.items():
            if not isinstance(r, dict) or "recall_block" not in r:
                continue
            flag = "n/a" if t == "none" else ("yes" if t in seen else "no")
            if base_rob and t in base_rob:
                b = base_rob[t]
                add(
                    f"| {t} | {flag} | {pct(b['recall_block'])} | {pct(r['recall_block'])} | "
                    f"{pct(b['recall_warn'])} | {pct(r['recall_warn'])} |"
                )
            else:
                add(f"| {t} | {flag} | {pct(r['recall_block'])} | {pct(r['recall_warn'])} |")
        add("")
        if base:
            bh = base["headline"]
            add("Clean test performance before and after augmentation:\n")
            add("| | ROC AUC | Recall at block | Recall at warn | FPR at block |")
            add("|---|---:|---:|---:|---:|")
            add(
                f"| Before | {num(bh['roc_auc'])} | {pct(bh['recall_at_fpr_0_001'])} | "
                f"{pct(bh['recall_at_fpr_0_01'])} | {pct(bh['test_fpr_block'], 2)} |"
            )
            add(
                f"| After | {num(h['roc_auc'])} | {pct(h['recall_at_fpr_0_001'])} | "
                f"{pct(h['recall_at_fpr_0_01'])} | {pct(h['test_fpr_block'], 2)} |"
            )
            add("")

    if names_rep:
        add("## Name model\n")
        add(
            "Logistic regression on name structure, typosquat distance to the 5,000 most "
            "popular packages, and hashed character n-grams, trained on OSSF "
            "malicious-package names reported before the validation cutoff against "
            "registry names, with every name in the code dataset held out.\n"
        )
        add("| Ecosystem | Train names | Holdout ROC AUC | Holdout PR AUC |\n|---|---:|---:|---:|")
        for eco, r in names_rep.items():
            add(
                f"| {eco} | {r['n_train']:,} | {r['holdout']['roc_auc']:.3f} | "
                f"{r['holdout']['pr_auc']:.3f} |"
            )
        add("")
        add(
            "The name model's job is the pre-download check (typosquats and names an agent "
            "hallucinated), before any archive exists to scan. Once the archive is scanned "
            "it adds nothing: its stacking weight is near zero. An earlier run gave it a "
            "clearly positive weight; that turned out to be a leak (the source dataset "
            "spells scoped npm names `@scope@name`, a form no benign name has), found by "
            "the end-to-end replay and fixed.\n"
        )

    rep = _load("replay.json")
    if rep:
        add("## End to end through the Rust firewall\n")
        add(
            "`scripts/replay.py` serves held-out test archives from a local fake registry and "
            "requests each one through the real `customs serve` binary (nothing is installed "
            "or executed). This exercises the shipped scanner, Rust inference and policy "
            "engine together, and checks them against the Python evaluation.\n"
        )
        add("| | Value |\n|---|---:|")
        add(f"| Requests | {rep['requests']:,} |")
        add(
            f"| Mean latency per request (scan + score + policy) | "
            f"{1000 * rep['seconds_per_request']:.0f} ms |"
        )
        add(f"| Malicious: blocked (HTTP 403) | {pct(rep['malicious_blocked'])} |")
        add(f"| Malicious: blocked or warned | {pct(rep['malicious_block_or_warn'])} |")
        add(f"| Benign: blocked | {pct(rep['benign_blocked'])} |")
        add(f"| Benign: warned | {pct(rep['benign_warned'])} |")
        add(
            f"| Decisions identical to the Python pipeline | "
            f"{pct(rep['decision_agreement_with_python'])} |"
        )
        add(f"| Largest risk difference vs Python | {rep['max_abs_risk_diff']:.2e} |")
        add("")

    ext = _load("external_malregistry.json")
    ext_base = _load("external_malregistry_baseline.json")
    if ext:
        add("## Independent dataset: MalRegistry\n")
        add(
            "All training and test malware above comes from one collector. MalRegistry "
            "(the PyPI malware corpus from *An Empirical Study of Malicious Code In PyPI "
            "Ecosystem*, ASE 2023) was gathered separately and is never trained on. Its "
            f"{ext['archives']:,} unique archives are canonicalized like the corpus and scored "
            "by the shipped binary. Samples whose name appears in the training data "
            f"({ext['name_seen_in_training_data']:,}) or whose code is a MinHash near-duplicate "
            f"of training malware ({ext['near_duplicate_of_training']:,}) are set aside; the "
            "rest are **novel**. Novel clusters are split in half: misses in the dev half "
            "drove the scanner changes below, and the held-out half was not looked at.\n"
        )
        rows = [
            ("All archives", "all"),
            ("Novel, dev half", "novel_dev"),
            ("Novel, held-out half", "novel_heldout"),
            ("Novel, held-out, one per cluster", "novel_heldout_one_per_cluster"),
        ]
        if ext_base:
            add(
                "| Subset | n | Warn or block (before) | Warn or block (after) | "
                "Block (before) | Block (after) |"
            )
            add("|---|---:|---:|---:|---:|---:|")
            for label, k in rows:
                a, b = ext_base.get(k), ext.get(k)
                if a and b:
                    add(
                        f"| {label} | {b['n']:,} | {pct(a['warn_or_block'])} | "
                        f"{pct(b['warn_or_block'])} | {pct(a['block'])} | {pct(b['block'])} |"
                    )
        else:
            add("| Subset | n | Warn or block | Block |\n|---|---:|---:|---:|")
            for label, k in rows:
                if ext.get(k):
                    r = ext[k]
                    add(f"| {label} | {r['n']:,} | {pct(r['warn_or_block'])} | {pct(r['block'])} |")
        add(
            "\nError analysis on the dev half found that most misses carried clear behavior "
            "indicators but none on the install surface: the payload sat in a module that "
            "`__init__.py` or `setup.py` imports, which runs on install or import just the "
            "same. The scanner now follows a package's own imports from the install surface "
            "(relative imports, and absolute imports of packages shipped in the archive, up to "
            "three hops), and gained two features for code hidden past a long run of blanks "
            "and for running decoded data on the line that decodes it.\n"
        )

    dif = _load("diff_eval.json")
    if dif and "matched_fpr" in dif.get("real_compromised_test", {}):
        rt = dif["real_compromised_test"]
        add("## Experiment: release diff model\n")
        add(
            "A hijacked release of a popular library is mostly the previous release plus a "
            "payload, so the payload is a small share of the package. This experiment scores "
            "only what a release adds: files new since the previous release, plus the new "
            "lines of changed files (`customs-scan delta`). The model is trained on "
            f"{dif['pairs']['benign']:,} benign release pairs and as many synthetic compromises "
            "(training-split malware payloads injected into benign releases in seven ways), "
            "and tested on the real compromised releases, which never enter training.\n"
        )
        add("| | Base model | Diff model |\n|---|---:|---:|")
        add(
            f"| ROC AUC, real compromised test releases (n={rt['n_pos']}) | "
            f"{num(rt['base']['roc_auc'])} | {num(rt['diff']['roc_auc'])} |"
        )
        add(
            f"| ROC AUC, synthetic compromises (test) | n/a | "
            f"{num(dif['synthetic_test']['diff']['roc_auc'])} |"
        )
        add("\n| Test FPR | Base recall | Base + diff recall |\n|---:|---:|---:|")
        for f, r in rt["matched_fpr"].items():
            add(f"| {pct(float(f))} | {pct(r['base_recall'])} | {pct(r['combined_recall'])} |")
        ov = rt["overlap_at_fpr_0.005"]
        add(
            f"\nAt 0.5% FPR the two models disagree often: {ov['both']} releases are caught "
            f"by both, {ov['base_only']} only by the base model and {ov['diff_only']} only by "
            "the diff model (among them litellm 1.82.7 and 1.82.8, which the base model "
            "scores near zero). The diff model misses releases whose previous version was "
            "already compromised, since the payload is then not new. Combined at a matched "
            "false positive rate the two do not beat the base model alone, so the diff model "
            "is not part of the shipped decision.\n"
        )

    live = _load("live_study.json")
    if live:
        add("## Prospective study: live PyPI traffic\n")
        add(
            "Every number above is about malware someone already found. Here the frozen "
            "models ran forward in time: `scripts/live_watch.py` followed PyPI's changelog "
            "and sent every new release published during the window through a running "
            "`customs serve` (downloaded and scanned in memory, never installed). Outcomes "
            "were read off later from PyPI itself (the project was removed) and from OpenSSF "
            "malicious-package reports.\n"
        )
        add(f"Window: {live['window'][0]} to {live['window'][1]} (UTC).\n")
        add("| Decision | Releases | Later removed from PyPI | OpenSSF report |")
        add("|---|---:|---:|---:|")
        for k in ("allow", "warn", "block"):
            r = live["removed_by_decision"].get(k)
            if r:
                add(f"| {k} | {r['n']:,} | {r['removed']:,} | {r['ossf']:,} |")
        add(
            f"\n{live['scanned']:,} of {live['releases']:,} releases were scanned "
            f"({live['new_projects']:,} from projects created during the window).\n"
        )
        flagged = sum(live["removed_by_decision"].get(k, {}).get("n", 0) for k in ("warn", "block"))
        add(
            f"The window is hours long, and malicious uploads usually stay up for days, so "
            f"the removal columns are a floor. What the window does measure is the alert "
            f"load on real traffic: {flagged} of {live['scanned']:,} fresh releases "
            f"({pct(flagged / max(live['scanned'], 1))}) were warned or blocked, the rate a "
            "user installing brand-new releases would see.\n"
        )

    add("## Calibration\n")
    add("![Calibration](figures/calibration.png)\n")
    add(
        "Risk is calibrated (Platt scaling on out-of-fold validation scores) at the "
        "class balance of the evaluation data, roughly even. In the wild malware is far "
        "rarer, so treat the risk as a ranking with frozen thresholds rather than as the "
        "literal probability that a random package from the registry is malicious.\n"
    )
    add("![Feature importance](figures/feature_importance.png)\n")

    add("## Limitations\n")
    add(
        "* **Label source bias.** Malware comes from Datadog's dataset, mostly found by "
        "GuardDog's heuristics, so the positives over-represent what heuristics already "
        "catch. Novel techniques that neither GuardDog nor these features describe are "
        "under-represented in both training and test."
    )
    add(
        "* **Benign label noise.** Long-tail benign packages could include undiscovered "
        "malware. They were filtered against all 234K OSSF reports and required to be at "
        "least 90 days old, which removes most of it but not all."
    )
    add(
        "* **Static analysis only.** Code that fetches its payload at runtime from a clean "
        "host, or hides logic in native binaries, gives little static signal. The policy "
        "rules (minimum age, nonexistent names, install scripts in new packages) are the "
        "backstop."
    )
    add(
        "* **Adaptive attackers.** The robustness table covers a handful of cheap evasions. "
        "An attacker who can query the model can do better; published work on prompt and "
        "malware detectors shows adaptive attacks break most static classifiers. Customs is "
        "one layer, not a guarantee.\n"
    )
    return "\n".join(L) + "\n"


def main() -> None:
    out = config.DOCS_DIR / "EVALUATION.md"
    out.write_text(render())
    print("wrote", out)


if __name__ == "__main__":
    main()
