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
    if _load("external_malregistry_before_training.json"):
        add(
            "* **Second source.** Training malware also includes the dev half of MalRegistry "
            "(collected in 2022 and 2023, before the test period); its held-out half is a "
            "separate test, below. The training counts include augmented copies."
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
            "scores)."
            + (
                f" Each component logit is clipped to [-{ens['clip']:g}, {ens['clip']:g}] "
                "before stacking, the bound with the best out-of-fold recall up to 1% FPR on "
                "validation. Without it, a few benign validation packages with extreme CNN "
                "logits set the block threshold well past its 0.1% target."
                if ens.get("clip")
                else ""
            )
            + "\n"
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
    if ev.get("registry_snapshot"):
        add(
            "`registry_removed` and `registry_still_published` split test malware by whether "
            "npm or PyPI still served the flagged version on "
            f"{ev['registry_snapshot'][:10]} (`customs_ml/registry_status.py`). Registries "
            "remove confirmed malware within days, so the removed group is the cleaner label. "
            "The still-published group mixes malware the registry left up (proof-of-concept "
            "and dependency-confusion probes) with collector false positives, such as "
            "per-platform prebuilt binaries of open-source projects; part of its misses are "
            "correct calls.\n"
        )

    mis = _load("misses.json")
    if mis:
        cats = mis["categories"]
        add("## What the misses are\n")
        add(
            f"Of {mis['n_test_malware']:,} test malware packages, {mis['n_missed']:,} fall "
            "below the warn threshold. Grouped by what the scanner saw:\n"
        )
        add("| Scanner saw | n malicious | Missed | Miss rate |\n|---|---:|---:|---:|")
        labels = {
            "indicators_on_surface": "Behavior indicators on the install surface",
            "indicators_off_surface": "Indicators only outside the install surface",
            "no_indicator": "No behavior indicator anywhere",
        }
        for k, label in labels.items():
            c = cats[k]
            add(f"| {label} | {c['n']:,} | {c['missed']:,} | {pct(c['miss_rate'])} |")
        add("")
        bo = mis["binary_only"]
        add(
            "A hand audit of 20 missed packages with no indicator anywhere (one per "
            "campaign, sampled at random) found 12 whose payload is a compiled binary "
            "(`.node`, `.exe`, `.so`, a macOS app), 1 that ships no code and depends on a "
            "malicious package (which the proxy scans on its own when the client fetches "
            "it), and 7 with no malicious content in the archive: two placeholders (a "
            "name reserved against dependency confusion that only raises an error, and "
            "the PyPA sample project) and five releases that read as clean. Those seven "
            "are label noise, so part of this row is not detectable by any scanner.\n"
        )
        add(
            f"Binary-only packages (a compiled binary and under 50 lines of source) are a "
            f"temporal blind spot: {bo['n_test_malware']:,} test malware packages against "
            f"{bo['n_train_malware']:,} in training, and {pct(bo['miss_rate'])} of the test "
            "ones are missed at warn."
        )
        br = bo.get("by_registry")
        if br and br["removed"]["n"] and br["still_published"]["n"]:
            sp, rm = br["still_published"], br["removed"]
            add(
                f" Most of that is likely label noise: {sp['n']:,} of them are versions the "
                f"registry still serves, {sp['platform_named']:,} of which are named as "
                "per-platform prebuilt binaries (`<name>-win32-x64-msvc` and the like), and "
                f"{pct(sp['miss_rate'])} of those are "
                f"missed. Of the {rm['n']:,} the registry removed, {pct(rm['miss_rate'])} "
                "are missed."
            )
        bs = mis.get("binary_strings") or {}
        tr_m, tr_b = bs.get("train:malicious"), bs.get("train:benign")
        te_m = bs.get("test:malicious")
        if tr_m and tr_b and te_m:
            add(
                " Searching every packaged binary for infostealer and dropper strings "
                "(webhook and bot endpoints, browser credential stores, wallet and SSH key "
                "paths, anti-VM process names, autorun commands, IP-literal URLs) does not "
                f"separate the classes: at least one appears in {pct(tr_m['any_stealer_string'])} "
                f"of malicious and {pct(tr_b['any_stealer_string'])} of benign training "
                f"binaries, and in {pct(te_m['any_stealer_string'])} of malicious test ones. "
                f"PyInstaller marks {pct(tr_m.get('pyinstaller', 0))} of malicious training "
                f"binaries but {pct(te_m.get('pyinstaller', 0))} in test, so a feature built "
                "on it would learn the past. Binary payloads stay with the policy rules "
                "(minimum package age, install scripts in new packages) rather than the "
                "classifier.\n"
            )
        else:
            add("\n")

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
            elif base_rob:
                # A transform added after the baseline run has no before column.
                add(
                    f"| {t} | {flag} | n/a | {pct(r['recall_block'])} | "
                    f"n/a | {pct(r['recall_warn'])} |"
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

    lt = _load("loadtest.json")
    if lt:
        add("### Latency under concurrent installs\n")
        add(
            f"`scripts/loadtest.py` serves {lt['archives']:,} test archives (median "
            f"{lt['archive_kb']['p50']:.0f} KB, 95th percentile "
            f"{lt['archive_kb']['p95']:.0f} KB) from a local fake registry and requests "
            f"them through the firewall in enforce mode on a {lt['cpus']}-core machine. "
            "Cold requests fetch, scan, score and decide; warm requests hit the verdict "
            "and artifact cache. Each concurrency level gets its own archives.\n"
        )
        add("| Run | Clients | Requests/s | p50 ms | p95 ms | p99 ms |")
        add("|---|---:|---:|---:|---:|---:|")
        d = lt["direct"]
        rows = [("Upstream directly (no firewall)", d)]
        rows += [("Cold", lt["cold"][c]) for c in lt["cold"]]
        rows += [("Warm (cached)", lt["warm"])]
        for label, r in rows:
            add(
                f"| {label} | {r['concurrency']} | {r['throughput_per_s']:.1f} | "
                f"{r['p50_ms']:.0f} | {r['p95_ms']:.0f} | {r['p99_ms']:.0f} |"
            )
        c1 = next(iter(lt["cold"].values()))
        sz = c1.get("p50_ms_by_size", {})
        sf = lt["single_flight"]
        add(
            f"\nThe server's own scan-and-score time averages {lt['server_scan_mean_ms']:.0f} "
            "ms. Sequential cold latency grows with archive size (median "
            + ", ".join(
                f"{v:.0f} ms {k.replace('_', ' ').replace('kb', ' KB').replace('mb', ' MB')}"
                for k, v in sz.items()
                if v is not None
            )
            + f"). When {sf['clients_per_package']} clients request the same uncached "
            f"archive at once, {sf['packages']} such bursts ({sf['requests']} requests) "
            f"cost {sf['scans']} scans: {sf['joins']} requests waited on the scan already "
            "in flight and the rest arrived after it finished and hit the cache.\n"
        )

    ext = _load("external_malregistry.json")
    ext_base = _load("external_malregistry_baseline.json")
    adapt = _load("external_adapt_100.json")
    # Scanner-change comparison: the run before the dev half became training data.
    ext_scan = _load("external_malregistry_before_training.json") or ext
    if ext:
        add("## Independent dataset: MalRegistry\n")
        add(
            "The time-split test above uses one collector's malware. MalRegistry "
            "(the PyPI malware corpus from *An Empirical Study of Malicious Code In PyPI "
            "Ecosystem*, ASE 2023) was gathered separately. Its "
            f"{ext['archives']:,} unique archives are canonicalized like the corpus and scored "
            "by the shipped binary. Samples whose name appears in the training data "
            f"({ext['name_seen_in_training_data']:,}) or whose code is a MinHash near-duplicate "
            f"of training malware ({ext['near_duplicate_of_training']:,}) are set aside; the "
            "rest are **novel**. Novel clusters are split in half: misses in the dev half "
            "were studied and drove scanner changes, the held-out half was never looked at. "
            "Both halves are frozen by archive hash, so every run below is measured on the "
            "same samples.\n"
        )
        add("| Subset | n | Warn or block | Block |\n|---|---:|---:|---:|")
        for label, k in (
            ("All archives", "all"),
            (
                "Novel, dev half (in training)" if ext_scan is not ext else "Novel, dev half",
                "novel_dev",
            ),
            ("Novel, held-out half", "novel_heldout"),
            ("Novel, held-out, one per cluster", "novel_heldout_one_per_cluster"),
        ):
            if ext.get(k):
                r = ext[k]
                add(f"| {label} | {r['n']:,} | {pct(r['warn_or_block'])} | {pct(r['block'])} |")
        add(
            "\nNovel malware from another collector is much harder than the time-split test "
            "set. Thresholds move between retrains, so the comparisons below are made at "
            "matched false positive rates on the benign test split.\n"
        )
        mf = ext_scan.get("recall_at_matched_fpr")
        if ext_base and mf and ext_base.get("dev_recall_at_matched_fpr"):
            add(
                "**Dev-half error analysis.** Most dev misses carried clear behavior "
                "indicators, but none on the install surface: the payload sat in a module "
                "that `setup.py` imports, or after a long run of blanks on one line, or in "
                "decoded data executed on the line that decodes it. The scanner now follows "
                "the package's own imports from setup-time files and has features for the "
                "other two. (Following imports from `__init__.py` as well was tried and "
                "made things worse: it pulls each benign library onto the install surface.)\n"
            )
            add(
                "| FPR | Dev, before | Dev, after | Held-out, before | Held-out, after |\n"
                "|---:|---:|---:|---:|---:|"
            )
            dev_a = ext_base["dev_recall_at_matched_fpr"]
            dev_b = ext_scan["dev_recall_at_matched_fpr"]
            held_a = ext_base["recall_at_matched_fpr"]
            for f in ("0.001", "0.005", "0.01"):
                add(
                    f"| {pct(float(f))} | {pct(dev_a[f]['recall'])} | {pct(dev_b[f]['recall'])} | "
                    f"{pct(held_a[f]['recall'])} | {pct(mf[f]['recall'])} |"
                )
            add(
                "\nThe changes helped the half they were designed on and barely moved the "
                "half that was held out. Error analysis on a handful of campaigns fits those "
                "campaigns; it is the held-out column that says how a fix generalizes, and "
                "these did not much.\n"
            )
        co = ext_scan.get("code_only_recall_at_matched_fpr")
        if co and mf:
            add(
                "**Name leakage check.** The name model is trained on OpenSSF malicious "
                "package names, and most MalRegistry names are among them (it is the same "
                "malware, reported). The in-domain test holds its names out of name-model "
                "training; here the binary was also run without the name model, using the "
                "ensemble's code-only fallback. Held-out recall at 0.1% / 0.5% / 1% FPR: "
                + " / ".join(pct(mf[f]["recall"]) for f in ("0.001", "0.005", "0.01"))
                + " with the name model, "
                + " / ".join(pct(co[f]["recall"]) for f in ("0.001", "0.005", "0.01"))
                + " without. The name model carries almost no weight once code is scanned, "
                "so the leak does not inflate these numbers.\n"
            )
        if adapt:
            h, i = adapt["heldout_code_only"], adapt["in_domain"]
            add(
                "**Training on the second source.** The dev half "
                f"({adapt['added_training_archives']:,} archives in "
                f"{adapt['added_training_clusters']:,} clusters, novel or not) was added to "
                "the training split and every model retrained; the held-out half "
                f"({adapt['heldout_novel_archives']:,} novel archives, "
                f"{adapt['heldout_novel_clusters']:,} clusters, none sharing a cluster with "
                "the added data) was scored code-only.\n"
            )
            add(
                "| | Held-out recall at 0.1% FPR | at 0.5% | at 1% | In-domain ROC AUC | "
                "In-domain block recall |\n|---|---:|---:|---:|---:|---:|"
            )
            for label, k in (
                ("Primary corpus only", "main"),
                ("Plus MalRegistry dev half", "adapted"),
            ):
                add(
                    f"| {label} | {pct(h[k]['0.001']['recall'])} | "
                    f"{pct(h[k]['0.005']['recall'])} | "
                    f"{pct(h[k]['0.01']['recall'])} | {num(i[k]['roc_auc'])} | "
                    f"{pct(i[k]['recall_block'])} |"
                )
            curve = [_load(f"external_adapt_{p}.json") for p in (25, 50)]
            curve = [c for c in curve if c] + [adapt]
            if len(curve) > 1:
                add(
                    "\nHeld-out recall at 0.5% FPR by share of dev clusters added: "
                    + ", ".join(
                        f"{c['fraction'] * 100:.0f}% ({c['added_training_clusters']} clusters): "
                        f"{pct(c['heldout_code_only']['adapted']['0.005']['recall'])}"
                        for c in curve
                    )
                    + "."
                )
            if ext_scan is not ext:
                add(
                    "\nThe shipped models include the dev half (pipeline stage `malregistry`). "
                    "Rerun through the binary, they score the held-out half at "
                    + " / ".join(
                        pct(ext["code_only_recall_at_matched_fpr"][f]["recall"])
                        for f in ("0.001", "0.005", "0.01")
                    )
                    + " (code only, 0.1% / 0.5% / 1% FPR)."
                )
                co = ext["code_only_recall_at_matched_fpr"]
                if "cluster_weighted_recall" in co["0.001"]:
                    sizes = ext.get("heldout_largest_cluster") or {}
                    add(
                        "\n**Read the campaign-weighted numbers.** Weighting each held-out "
                        "campaign equally, the shipped models catch "
                        + " / ".join(
                            pct(co[f]["cluster_weighted_recall"])
                            for f in ("0.001", "0.005", "0.01")
                        )
                        + " at the same rates."
                        + (
                            f" One campaign holds {sizes['n']:,} near-identical archives "
                            f"({pct(sizes['share'])} of the held-out half) with code-only "
                            f"risk near {sizes['median_risk']:.2f}, so per-archive recall "
                            "jumps by that share whenever a retrain moves that score across a "
                            "threshold; per-archive numbers between runs are only comparable "
                            "when that campaign stays on the same side."
                            if sizes
                            else ""
                        )
                    )
            add("")

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
            "scores far below its warn threshold). The diff model misses releases whose "
            "previous version was already compromised, since the payload is then not new.\n"
        )
        mf = rt["matched_fpr"]
        gains = {f: mf[f]["combined_recall"] - mf[f]["base_recall"] for f in mf}
        lo = min(mf, key=float)
        add(
            "Combined at a matched false positive rate (each model's score turned into a "
            "tail probability on benign validation pairs, then the maximum), the pair gains "
            + ", ".join(
                f"{gains[f] * 100:+.1f} points at {pct(float(f))}" for f in sorted(mf, key=float)
            )
            + f" FPR, on {rt['n_pos']} releases. Taking the maximum of two scores spends the "
            "false positive budget on both"
            + (
                f", which costs recall at the block operating point ({pct(mf[lo]['base_recall'])}"
                f" to {pct(mf[lo]['combined_recall'])} at {pct(float(lo))})"
                if gains[lo] < 0
                else ""
            )
            + ". The diff model is therefore not part of the shipped decision: "
            + (
                f"the only gain is {max(gains.values()) * 100:.1f} points at "
                f"{pct(float(max(gains, key=gains.get)))} FPR on {rt['n_pos']} releases, "
                "and the loss lands on the decision that blocks.\n"
                if max(gains.values()) > 0 and sum(g > 0 for g in gains.values()) == 1
                else f"the gains at looser rates are a handful of releases out of {rt['n_pos']}, "
                "and the loss lands on the decision that blocks.\n"
                if max(gains.values()) > 0
                else "the combination loses recall at every rate measured.\n"
            )
        )

    hist = _load("history_eval.json")
    if hist:
        hc, hb = hist["compromised"], hist["benign"]
        add("## Release history rules on compromised npm releases\n")
        add(
            "The proxy's release history rules (`provenance_dropped`, `install_script_added`, "
            "`publisher_changed`, `dormant_revival`, `version_anomaly`, "
            "`nonregistry_dependency_added`, `young_dependency_added`) read registry metadata, "
            "not code, so they can catch hijacked releases the model scores low. "
            "`python -m customs_ml.history_eval` replays them on every compromised npm "
            f"release in the corpus with an earlier release ({hc['n_releases']} releases of "
            f"{hc['n_names']} packages) and on every release from the last "
            f"{hist['benign_window_years']:g} years of {hb['n_packages']} benign npm packages "
            f"from the corpus ({hb['n_releases']:,} releases). Most compromised versions were "
            f"unpublished ({hc['n_releases'] - hc['n_listed']} of {hc['n_releases']}): their "
            "publish time survives and their install scripts and dependencies come from the "
            "archive, but "
            "whether they carried provenance and who published them is gone, so those two "
            "rules give a range (unknown counted as silent, then as firing). The dependency "
            "rules compare with the previous release's dependencies, which are gone too when "
            "that release was itself unpublished, so they give a range as well.\n"
        )
        add(
            "| Rule | Default | Compromised releases | Benign releases | Benign packages "
            "alarmed in the window |\n|---|---|---:|---:|---:|"
        )
        defaults = {
            "provenance_dropped": "warn",
            "install_script_added": "block",
            "publisher_changed": "warn",
            "dormant_revival": "warn",
            "version_anomaly": "off",
            "nonregistry_dependency_added": "block",
            "young_dependency_added": "block",
        }

        def rng(r):
            return pct(r["low"]) if r["unknown"] == 0 else f"{pct(r['low'])} to {pct(r['high'])}"

        for k, d in defaults.items():
            add(
                f"| `{k}` | {d} | {rng(hc['rules'][k])} | {pct(hb['rules'][k]['low'], 2)} | "
                f"{pct(hb['packages_with_alarm'][k])} |"
            )
        add(
            f"| any rule on by default | | {rng(hc['rules']['any_default'])} | "
            f"{pct(hb['rules']['any_default']['low'], 2)} | |"
        )
        u = hc.get("union_test")
        if u:
            add(
                f"\nOn the {u['n']} compromised releases in the test period, together with the "
                "model:\n"
            )
            add("| | Model alone | With the rules |\n|---|---:|---:|")
            add(
                f"| Warned or blocked (any default rule) | {pct(u['model_warn'])} | "
                f"{pct(u['model_or_rules_low'])} to {pct(u['model_or_rules_high'])} |"
            )
            add(
                f"| Blocked, `install_script_added` only | {pct(u['model_block'])} | "
                f"{pct(u['block_with_install_rule_low'])} to "
                f"{pct(u['block_with_install_rule_high'])} |"
            )
            if "block_with_rules_low" in u:
                add(
                    f"| Blocked, every blocking rule | {pct(u['model_block'])} | "
                    f"{pct(u['block_with_rules_low'])} to {pct(u['block_with_rules_high'])} |"
                )
        isa = hb["rules"]["install_script_added"]
        add(
            f"\n`install_script_added` is the rule that earns its place: it fired on "
            f"{isa['fired']} of {hb['n_releases']:,} legitimate releases "
            f"({pct(isa['low'], 2)}, under the block budget of 0.1%) and on at least "
            f"{pct(hc['rules']['install_script_added']['low'])} of compromised ones, because "
            "the classic takeover adds a `postinstall` and established packages rarely change "
            "theirs. It compares with the previous release and, when that shows no change, "
            "with the newest release at least a day older: attackers often publish several "
            "malicious versions within hours, and each one matches the one before it. It "
            "therefore blocks by default. `publisher_changed` is the noisiest rule "
            f"on by default ({pct(hb['rules']['publisher_changed']['low'], 2)} of releases; "
            f"{pct(hb['packages_with_alarm']['publisher_changed'])} of packages over the "
            "window, since large projects rotate release managers), and its value on "
            "compromised releases cannot be measured once they are unpublished, so it stays "
            "at warn. Provenance cannot be judged from what survives: of the "
            f"{hc['n_listed']} compromised releases still listed, "
            f"{hc['listed_after_attested']} followed a release with provenance, and "
            f"{hc['listed_after_attested_still_attested']} of those carry valid provenance "
            "themselves, because the attacker published through the project's own CI. A "
            "takeover by stolen token drops provenance; a takeover of the build does not.\n"
        )
        nr = hb["rules"].get("nonregistry_dependency_added")
        yd = hb["rules"].get("young_dependency_added")
        if nr and yd and u and "dependency_rules_on_missed" in u:
            add(
                "The two dependency rules target waves whose payload arrives through a "
                "dependency, not the package's own files, so the scanner sees nothing in the "
                "archive: a new `optionalDependencies` entry pointing at a GitHub commit, or a "
                "new dependency on a package the attacker published days earlier. "
                "`nonregistry_dependency_added` fires when a git, URL or file dependency is new "
                "or changed since the previous release; `young_dependency_added` fires when a "
                "new dependency is not on the registry, or was first published less than 7 "
                "days before the release by someone who maintains or publishes none of the "
                "package's releases (a maintainer's own new platform package is routine). They "
                f"fired on {rng(hc['rules']['nonregistry_dependency_added'])} and "
                f"{rng(hc['rules']['young_dependency_added'])} of compromised releases, and on "
                f"{nr['fired']} and {yd['fired']} of {hb['n_releases']:,} legitimate ones. Of "
                f"the {u['missed_by_model']} test-period compromised releases the model lets "
                f"through, they catch {u['dependency_rules_on_missed']}"
                + (
                    ". "
                    if u["dependency_rules_on_missed_strict"] == u["dependency_rules_on_missed"]
                    else f" ({u['dependency_rules_on_missed_strict']} without counting "
                    "dependencies that are gone from the registry today). "
                )
                + "Both block by default.\n"
            )
        fams = hc.get("families_test")
        if fams:
            add(
                "Takeovers come in waves, one attacker working through every package a stolen "
                "account or token can publish. Grouping the test-period releases by npm scope, "
                "or by name prefix for unscoped packages, shows which waves each layer stops "
                "(groups of at least 3 releases; blocked means under the default policy):\n"
            )
            add(
                "| Group | Releases | Packages | Model blocks | A blocking rule fires "
                "| Blocked |\n|---|---:|---:|---:|---:|---:|"
            )
            for f in fams:
                add(
                    f"| `{f['family']}` | {f['n']} | {f['packages']} | {f['model_block']} | "
                    f"{f['rules_block']} | {f['block_with_rules']} |"
                )
            add(
                "\nThe model and the rules fail in different places: a wave that ships its "
                "payload in the archive is the model's to catch, and a wave that pulls it in "
                "through a new install script or dependency is the rules'. A wave with neither "
                "(an obfuscated payload in a file the install surface does not reach, published "
                "by the usual account with no change to scripts or dependencies) gets past "
                "both.\n"
            )
        par = _load("history_parity.json")
        if par:
            add(
                f"The Python replay agrees with the proxy's own `customs check` on "
                f"{par['agree']} of {par['checked']} benign releases sampled across the rules "
                "(every rule set to warn).\n"
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
        version = f", models {live['model_version']}" if live.get("model_version") else ""
        add(f"Window: {live['window'][0]} to {live['window'][1]} (UTC{version}).\n")
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
            f"({pct(flagged / max(live['scanned'], 1))}) {'was' if flagged == 1 else 'were'} "
            "warned or blocked, the rate a "
            "user installing brand-new releases would see.\n"
        )

    var = _load("seed_variance.json")
    if var and len(var.get("runs", [])) > 1:
        sp = var["spread"]
        add("## Retrain variance\n")
        add(
            f"The tree model and the CNN retrained with {len(var['runs'])} seeds "
            f"({', '.join(map(str, var['seeds'][: len(var['runs'])]))}) on identical data, "
            "each stacked and thresholded the same way as the shipped model. A change "
            "between two training runs smaller than these ranges is not evidence that "
            "anything improved or regressed.\n"
        )
        add("| Test metric | Mean | SD | Min | Max |\n|---|---:|---:|---:|---:|")
        rows = [
            ("ROC AUC", "roc_auc", False),
            ("Recall at block", "recall_block", True),
            ("FPR at block", "fpr_block", True),
            ("Recall at warn", "recall_warn", True),
            ("Recall at exactly 0.1% FPR (test ROC)", "roc_recall_0_001", True),
            ("Compromised libraries: ROC AUC", "compromised_lib_roc_auc", False),
            ("Compromised libraries: recall at block", "compromised_lib_recall_block", True),
            ("PyPI malware vs all benign: ROC AUC", "pypi_roc_auc", False),
            ("PyPI malware: recall at block", "pypi_recall_block", True),
        ]
        for label, k, is_pct in rows:
            v = sp.get(k)
            if not v:
                continue
            if is_pct:
                d = 2 if k.startswith("fpr") else 1
                add(
                    f"| {label} | {pct(v['mean'], d)} | {100 * v['std']:.{d}f} pts | "
                    f"{pct(v['min'], d)} | {pct(v['max'], d)} |"
                )
            else:
                add(
                    f"| {label} | {v['mean']:.3f} | {v['std']:.3f} | {v['min']:.3f} | "
                    f"{v['max']:.3f} |"
                )
        add(
            "\nROC AUC and recall at warn barely move between seeds. Everything at 0.1% "
            "FPR is a tail statistic: the block threshold rests on two or three of about "
            "2,000 benign validation packages, and the threshold-free row on four of 4,217 "
            "benign test packages, so both move several points between retrains: recall at "
            f"block spans {100 * (sp['recall_block']['max'] - sp['recall_block']['min']):.1f} "
            "points across these seeds, and a difference at the block rate between two runs "
            "needs to exceed that before it says anything about the model. Training is "
            "reproducible: the same seed in a fresh process (different string hash seed) "
            "produces bit-identical tree and CNN outputs, after the CNN vocabulary stopped "
            "breaking document-frequency ties by set order.\n"
        )
        bag = _load("seed_bagging.json")
        if bag:
            add(
                "Averaging the tree and CNN logits of several seeds before stacking (seed "
                "bagging), over every subset of the seeds of each size:\n"
            )
            add(
                "| Seeds averaged | Subsets | Recall at block (min to max) | FPR at block "
                "(min to max) | Recall at warn | ROC AUC |\n|---:|---:|---:|---:|---:|---:|"
            )
            for k in sorted(bag, key=int):
                b = bag[k]["spread"]
                add(
                    f"| {k} | {bag[k]['n']} | {pct(b['recall_block']['mean'])} "
                    f"({pct(b['recall_block']['min'])} to {pct(b['recall_block']['max'])}) | "
                    f"{pct(b['fpr_block']['mean'], 2)} ({pct(b['fpr_block']['min'], 2)} to "
                    f"{pct(b['fpr_block']['max'], 2)}) | {pct(b['recall_warn']['mean'])} | "
                    f"{b['roc_auc']['mean']:.3f} |"
                )
            one, full = bag["1"]["spread"], bag[max(bag, key=int)]["spread"]
            add(
                "\nBagging mostly steadies the block threshold: single seeds realize between "
                f"{pct(one['fpr_block']['min'], 2)} and {pct(one['fpr_block']['max'], 2)} FPR "
                f"at block, the full bag {pct(full['fpr_block']['mean'], 2)}, and recall at "
                f"block moves from a {pct(one['recall_block']['mean'])} mean to "
                f"{pct(full['recall_block']['mean'])}, inside the single-seed range. It costs "
                "one tree model and one CNN per seed at serve time, so the shipped model "
                "stays a single seed.\n"
            )
        cmp_ = _load("model_compare.json")
        if cmp_:
            add(
                "Exported model sets scored on today's features (the current scanner's "
                "view of the test set), which separates what a scanner change did to the "
                "test data from what retraining did to the model:\n"
            )
            add(
                "| Models | ROC AUC | Recall at block | FPR at block | Recall at exactly "
                "0.1% FPR | Compromised libraries ROC AUC |"
            )
            add("|---|---:|---:|---:|---:|---:|")
            for label, m in cmp_.items():
                add(
                    f"| {label} | {m['roc_auc']:.4f} | {pct(m['recall_block'])} | "
                    f"{pct(m['fpr_block'], 2)} | {pct(m['roc_recall_0_001'])} | "
                    f"{m['compromised_lib_roc_auc']:.3f} |"
                )
            add("")

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
