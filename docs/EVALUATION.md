# Customs: evaluation report

Generated 2026-10-07T14:38:12+00:00 by `python -m customs_ml.report` from the artifacts of `python -m customs_ml.pipeline`. Every number below is on held-out test data with thresholds frozen on the validation split, unless a row says otherwise.

## Data

| Split | Malicious | Benign |
|---|---:|---:|
| train | 29,907 | 15,869 |
| val | 2,048 | 2,172 |
| test | 4,100 | 4,217 |

* **Temporal split.** Test malware was discovered on or after 2026-02-13; validation malware between 2025-12-10 and that date; training malware before. The model never saw a sample from the test period.
* **Second source.** Training malware also includes the dev half of MalRegistry (collected in 2022 and 2023, before the test period); its held-out half is a separate test, below. The training counts include augmented copies.
* **Benign packages** are split at random by near-duplicate cluster in the same proportions, sampled across three popularity tiers (top, mid, long tail) of PyPI and npm.
* **Near-duplicates.** MinHash LSH clusters (Jaccard about 0.7 on install-time token 5-grams) group malware campaigns. Clusters are the unit for benign splitting, sample weighting (1/sqrt(cluster size)) and for every confidence interval (cluster bootstrap, 1,000 resamples).
* **Canonicalization.** Both classes are repacked into identical deterministic tarballs before scanning, so archive format cannot leak the label.

## Headline (ensemble)

| Metric | Test value (95% CI) |
|---|---|
| ROC AUC | 0.972 (0.965 to 0.977) |
| PR AUC | 0.977 (0.971 to 0.981) |
| Detection rate at the **block** threshold (target FPR 0.1%) | 68.0% (64.1 to 71.9) |
| Realized test FPR at block | 0.12% (0.02 to 0.24) |
| Detection rate at the **warn** threshold (target FPR 1%) | 78.8% (75.5 to 82.1) |
| Realized test FPR at warn | 0.74% (0.48 to 1.02) |
| Detection at exactly 0.1% FPR on the test ROC (threshold-free) | 63.6% (57.5 to 73.3) |
| Detection at exactly 1% FPR on the test ROC (threshold-free) | 80.4% (76.7 to 84.4) |
| Brier score | 0.064 |
| Expected calibration error | 0.035 |

![ROC curves](figures/roc.png)

## Components

Each component's thresholds were chosen on validation at the same target FPRs.

| Model | ROC AUC | PR AUC | Recall at block | FPR at block | Recall at warn | FPR at warn |
|---|---:|---:|---:|---:|---:|---:|
| Customs (ensemble) | 0.972 | 0.977 | 68.0% | 0.12% | 78.8% | 0.74% |
| Code model (GBDT) | 0.967 | 0.974 | 60.2% | 0.07% | 79.7% | 0.92% |
| Code model (CNN) | 0.927 | 0.933 | 20.7% | 0.00% | 58.8% | 0.43% |
| Name model | 0.680 | 0.685 | 0.5% | 0.02% | 9.9% | 1.04% |

Stacking weights on component logits: code GBDT 0.98, code CNN 0.42, name 0.09 (fit on validation with 5-fold cluster-grouped cross-fitting; calibration and thresholds use out-of-fold scores). Each component logit is clipped to [-4, 4] before stacking, the bound with the best out-of-fold recall up to 1% FPR on validation. Without it, a few benign validation packages with extreme CNN logits set the block threshold well past its 0.1% target.

## Against GuardDog

[GuardDog](https://github.com/DataDog/guarddog) (Datadog's open-source scanner, v3.2) on the same canonical test archives, a fixed random sample of 1,500 malicious and 1,500 benign. Note the bias: most samples in Datadog's dataset were originally found with GuardDog's rules, so this comparison favours GuardDog.

| | GuardDog | Customs |
|---|---:|---:|
| ROC AUC (GuardDog risk score vs Customs risk) | 0.837 | 0.973 |
| Any finding: FPR | 18.0% | same FPR by construction |
| Any finding: detection rate | 79.4% | 95.3% |
| `high_risk` label: FPR | 5.0% | same FPR by construction |
| `high_risk` label: detection rate | 49.7% | 88.3% |

At GuardDog's own false-positive rate, Customs' detection-rate gain has a paired cluster-bootstrap 95% CI of 12.5 to 19.5 points. (For this comparison only, Customs' threshold is set on the test benign packages to match GuardDog's realized FPR; that is what matched-FPR means.)

## Where it is weak

| Slice | n malicious | n benign | ROC AUC | Recall at block | FPR at block |
|---|---:|---:|---:|---:|---:|
| ecosystem:pypi | 209 | 2,332 | 0.977 | 51.2% | 0.00% |
| ecosystem:npm | 3,891 | 1,885 | 0.961 | 68.9% | 0.27% |
| malicious:novel_campaigns | 3,550 | 4,217 | 0.970 | 69.0% | 0.12% |
| malicious:seen_campaigns | 550 | 4,217 | 0.979 | 62.0% | 0.12% |
| malicious:malicious_intent | 3,903 | 4,217 | 0.976 | 69.1% | 0.12% |
| malicious:compromised_lib | 197 | 4,217 | 0.878 | 46.2% | 0.12% |
| size:tercile_1 | 2,877 | 1,406 | 0.983 | 79.9% | 0.36% |
| size:tercile_2 | 747 | 1,405 | 0.953 | 53.7% | 0.00% |
| size:tercile_3 | 476 | 1,406 | 0.924 | 18.5% | 0.00% |

False-positive rate on benign packages by popularity tier:

| Tier | n | FPR at block | FPR at warn |
|---|---:|---:|---:|
| top | 574 | 0.00% | 0.52% |
| mid | 1,490 | 0.13% | 0.60% |
| tail | 2,153 | 0.14% | 0.88% |

`malicious:*` slices are each malicious subset against all benign test packages. `novel_campaigns` are test samples whose near-duplicate cluster has no member in training: the closest thing to a never-seen attack. Size terciles cut on benign source-line counts, to expose any small-package shortcut.

## Ablation: what does the code itself say?

The tree model retrained on 47 behavior features only (indicator counts and obfuscation statistics; no manifest metadata, sizes, or file counts):

| Feature set | ROC AUC | Recall at block | Recall at warn |
|---|---:|---:|---:|
| All features (before augmentation) | 0.976 | 73.0% | 81.1% |
| All features | 0.967 | 60.2% | 79.7% |
| Behavior only | 0.937 | 34.4% | 60.0% |

## Adversarial robustness

Held-out test malware rewritten as text (never executed), re-scanned and re-scored. Detection rate at the block and warn thresholds. *Seen* transforms are families the augmentation stage trained on (with donors from the training split; the test donors are different packages). *Unseen* ones were never used in training.

| Transform | Seen in training | Block (before) | Block (after) | Warn (before) | Warn (after) |
|---|---|---:|---:|---:|---:|
| none | n/a | 53.0% | 67.5% | 80.0% | 77.4% |
| string_split | no | 47.6% | 62.3% | 78.0% | 75.6% |
| base64_wrap | no | 68.4% | 85.0% | 91.6% | 92.4% |
| trojan_padding | yes | 35.4% | 67.4% | 68.0% | 79.1% |
| indirection | no | 52.5% | 67.5% | 79.9% | 77.4% |
| metadata_mimicry | yes | 38.6% | 56.9% | 63.2% | 74.6% |
| starjack | yes | 29.8% | 54.6% | 57.9% | 73.6% |

Clean test performance before and after augmentation:

| | ROC AUC | Recall at block | Recall at warn | FPR at block |
|---|---:|---:|---:|---:|
| Before | 0.979 | 53.9% | 80.0% | 0.00% |
| After | 0.972 | 68.0% | 78.8% | 0.12% |

## Name model

Logistic regression on name structure, typosquat distance to the 5,000 most popular packages, and hashed character n-grams, trained on OSSF malicious-package names reported before the validation cutoff against registry names, with every name in the code dataset held out.

| Ecosystem | Train names | Holdout ROC AUC | Holdout PR AUC |
|---|---:|---:|---:|
| pypi | 14,463 | 0.946 | 0.958 |
| npm | 192,090 | 0.980 | 0.983 |

The name model's job is the pre-download check (typosquats and names an agent hallucinated), before any archive exists to scan. Once the archive is scanned it adds nothing: its stacking weight is near zero. An earlier run gave it a clearly positive weight; that turned out to be a leak (the source dataset spells scoped npm names `@scope@name`, a form no benign name has), found by the end-to-end replay and fixed.

## End to end through the Rust firewall

`scripts/replay.py` serves held-out test archives from a local fake registry and requests each one through the real `customs serve` binary (nothing is installed or executed). This exercises the shipped scanner, Rust inference and policy engine together, and checks them against the Python evaluation.

| | Value |
|---|---:|
| Requests | 706 |
| Mean latency per request (scan + score + policy) | 61 ms |
| Malicious: blocked (HTTP 403) | 66.3% |
| Malicious: blocked or warned | 76.8% |
| Benign: blocked | 0.0% |
| Benign: warned | 0.8% |
| Decisions identical to the Python pipeline | 100.0% |
| Largest risk difference vs Python | 1.05e-07 |

## Independent dataset: MalRegistry

The time-split test above uses one collector's malware. MalRegistry (the PyPI malware corpus from *An Empirical Study of Malicious Code In PyPI Ecosystem*, ASE 2023) was gathered separately. Its 11,630 unique archives are canonicalized like the corpus and scored by the shipped binary. Samples whose name appears in the training data (1,523) or whose code is a MinHash near-duplicate of training malware (7,575) are set aside; the rest are **novel**. Novel clusters are split in half: misses in the dev half were studied and drove scanner changes, the held-out half was never looked at. Both halves are frozen by archive hash, so every run below is measured on the same samples.

| Subset | n | Warn or block | Block |
|---|---:|---:|---:|
| All archives | 11,630 | 97.1% | 86.5% |
| Novel, dev half (in training) | 1,698 | 96.1% | 87.6% |
| Novel, held-out half | 2,174 | 91.2% | 43.0% |
| Novel, held-out, one per cluster | 660 | 81.7% | 68.5% |

Novel malware from another collector is much harder than the time-split test set. Thresholds move between retrains, so the comparisons below are made at matched false positive rates on the benign test split.

**Dev-half error analysis.** Most dev misses carried clear behavior indicators, but none on the install surface: the payload sat in a module that `setup.py` imports, or after a long run of blanks on one line, or in decoded data executed on the line that decodes it. The scanner now follows the package's own imports from setup-time files and has features for the other two. (Following imports from `__init__.py` as well was tried and made things worse: it pulls each benign library onto the install surface.)

| FPR | Dev, before | Dev, after | Held-out, before | Held-out, after |
|---:|---:|---:|---:|---:|
| 0.1% | 39.0% | 44.4% | 28.8% | 30.8% |
| 0.5% | 54.8% | 59.0% | 37.3% | 37.2% |
| 1.0% | 67.7% | 67.5% | 40.1% | 40.2% |

The changes helped the half they were designed on and barely moved the half that was held out. Error analysis on a handful of campaigns fits those campaigns; it is the held-out column that says how a fix generalizes, and these did not much.

**Name leakage check.** The name model is trained on OpenSSF malicious package names, and most MalRegistry names are among them (it is the same malware, reported). The in-domain test holds its names out of name-model training; here the binary was also run without the name model, using the ensemble's code-only fallback. Held-out recall at 0.1% / 0.5% / 1% FPR: 30.8% / 37.2% / 40.2% with the name model, 31.1% / 37.4% / 40.8% without. The name model carries almost no weight once code is scanned, so the leak does not inflate these numbers.

**Training on the second source.** The dev half (8,658 archives in 853 clusters, novel or not) was added to the training split and every model retrained; the held-out half (2,174 novel archives, 660 clusters, none sharing a cluster with the added data) was scored code-only.

| | Held-out recall at 0.1% FPR | at 0.5% | at 1% | In-domain ROC AUC | In-domain block recall |
|---|---:|---:|---:|---:|---:|
| Primary corpus only | 31.1% | 37.4% | 40.8% | 0.972 | 57.4% |
| Plus MalRegistry dev half | 40.2% | 48.7% | 51.7% | 0.970 | 57.7% |

Held-out recall at 0.5% FPR by share of dev clusters added: 25% (213 clusters): 43.0%, 50% (426 clusters): 46.1%, 100% (853 clusters): 48.7%.

The shipped models include the dev half (pipeline stage `malregistry`). Rerun through the binary, they score the held-out half at 41.2% / 90.4% / 92.1% (code only, 0.1% / 0.5% / 1% FPR).

**Read the campaign-weighted numbers.** Weighting each held-out campaign equally, the shipped models catch 65.9% / 80.0% / 83.5% at the same rates. One campaign holds 901 near-identical archives (41.4% of the held-out half) with code-only risk near 0.93, so per-archive recall jumps by that share whenever a retrain moves that score across a threshold; per-archive numbers between runs are only comparable when that campaign stays on the same side.

## Experiment: release diff model

A hijacked release of a popular library is mostly the previous release plus a payload, so the payload is a small share of the package. This experiment scores only what a release adds: files new since the previous release, plus the new lines of changed files (`customs-scan delta`). The model is trained on 19,333 benign release pairs and as many synthetic compromises (training-split malware payloads injected into benign releases in seven ways), and tested on the real compromised releases, which never enter training.

| | Base model | Diff model |
|---|---:|---:|
| ROC AUC, real compromised test releases (n=178) | 0.868 | 0.881 |
| ROC AUC, synthetic compromises (test) | n/a | 0.994 |

| Test FPR | Base recall | Base + diff recall |
|---:|---:|---:|
| 0.1% | 36.5% | 0.0% |
| 0.5% | 60.1% | 55.1% |
| 1.0% | 64.6% | 60.1% |

At 0.5% FPR the two models disagree often: 59 releases are caught by both, 48 only by the base model and 6 only by the diff model (among them litellm 1.82.7 and 1.82.8, which the base model scores far below its warn threshold). The diff model misses releases whose previous version was already compromised, since the payload is then not new.

Combined at a matched false positive rate (each model's score turned into a tail probability on benign validation pairs, then the maximum), the pair gains -36.5 points at 0.1%, -5.1 points at 0.5%, -4.5 points at 1.0% FPR, on 178 releases. Taking the maximum of two scores spends the false positive budget on both, which costs recall at the block operating point (36.5% to 0.0% at 0.1%). The diff model is therefore not part of the shipped decision: the combination loses recall at every rate measured.

## Prospective study: live PyPI traffic

Every number above is about malware someone already found. Here the frozen models ran forward in time: `scripts/live_watch.py` followed PyPI's changelog and sent every new release published during the window through a running `customs serve` (downloaded and scanned in memory, never installed). Outcomes were read off later from PyPI itself (the project was removed) and from OpenSSF malicious-package reports.

Window: 2026-10-07T07:56:21Z to 2026-10-07T10:30:07Z (UTC).

| Decision | Releases | Later removed from PyPI | OpenSSF report |
|---|---:|---:|---:|
| allow | 1,163 | 0 | 0 |
| warn | 1 | 0 | 0 |

1,164 of 1,164 releases were scanned (88 from projects created during the window).

The window is hours long, and malicious uploads usually stay up for days, so the removal columns are a floor. What the window does measure is the alert load on real traffic: 1 of 1,164 fresh releases (0.1%) was warned or blocked, the rate a user installing brand-new releases would see.

## Calibration

![Calibration](figures/calibration.png)

Risk is calibrated (Platt scaling on out-of-fold validation scores) at the class balance of the evaluation data, roughly even. In the wild malware is far rarer, so treat the risk as a ranking with frozen thresholds rather than as the literal probability that a random package from the registry is malicious.

![Feature importance](figures/feature_importance.png)

## Limitations

* **Label source bias.** Malware comes from Datadog's dataset, mostly found by GuardDog's heuristics, so the positives over-represent what heuristics already catch. Novel techniques that neither GuardDog nor these features describe are under-represented in both training and test.
* **Benign label noise.** Long-tail benign packages could include undiscovered malware. They were filtered against all 234K OSSF reports and required to be at least 90 days old, which removes most of it but not all.
* **Static analysis only.** Code that fetches its payload at runtime from a clean host, or hides logic in native binaries, gives little static signal. The policy rules (minimum age, nonexistent names, install scripts in new packages) are the backstop.
* **Adaptive attackers.** The robustness table covers a handful of cheap evasions. An attacker who can query the model can do better; published work on prompt and malware detectors shows adaptive attacks break most static classifiers. Customs is one layer, not a guarantee.

