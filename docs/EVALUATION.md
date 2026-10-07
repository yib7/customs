# Customs: evaluation report

Generated 2026-10-07T04:40:19+00:00 by `python -m customs_ml.report` from the artifacts of `python -m customs_ml.pipeline`. Every number below is on held-out test data with thresholds frozen on the validation split, unless a row says otherwise.

## Data

| Split | Malicious | Benign |
|---|---:|---:|
| train | 21,250 | 15,869 |
| val | 2,048 | 2,172 |
| test | 4,100 | 4,217 |

* **Temporal split.** Test malware was discovered on or after 2026-02-13; validation malware between 2025-12-10 and that date; training malware before. The model never saw a sample from the test period.
* **Benign packages** are split at random by near-duplicate cluster in the same proportions, sampled across three popularity tiers (top, mid, long tail) of PyPI and npm.
* **Near-duplicates.** MinHash LSH clusters (Jaccard about 0.7 on install-time token 5-grams) group malware campaigns. Clusters are the unit for benign splitting, sample weighting (1/sqrt(cluster size)) and for every confidence interval (cluster bootstrap, 1,000 resamples).
* **Canonicalization.** Both classes are repacked into identical deterministic tarballs before scanning, so archive format cannot leak the label.

## Headline (ensemble)

| Metric | Test value (95% CI) |
|---|---|
| ROC AUC | 0.972 (0.966 to 0.977) |
| PR AUC | 0.976 (0.970 to 0.981) |
| Detection rate at the **block** threshold (target FPR 0.1%) | 55.3% (50.6 to 59.7) |
| Realized test FPR at block | 0.05% (0.00 to 0.12) |
| Detection rate at the **warn** threshold (target FPR 1%) | 79.5% (76.3 to 82.5) |
| Realized test FPR at warn | 0.71% (0.47 to 0.96) |
| Detection at exactly 0.1% FPR on the test ROC (threshold-free) | 64.2% (53.4 to 72.4) |
| Detection at exactly 1% FPR on the test ROC (threshold-free) | 80.6% (77.1 to 83.7) |
| Brier score | 0.067 |
| Expected calibration error | 0.040 |

![ROC curves](figures/roc.png)

## Components

Each component's thresholds were chosen on validation at the same target FPRs.

| Model | ROC AUC | PR AUC | Recall at block | FPR at block | Recall at warn | FPR at warn |
|---|---:|---:|---:|---:|---:|---:|
| Customs (ensemble) | 0.972 | 0.976 | 55.3% | 0.05% | 79.5% | 0.71% |
| Code model (GBDT) | 0.969 | 0.974 | 68.1% | 0.12% | 79.1% | 0.81% |
| Code model (CNN) | 0.923 | 0.927 | 26.7% | 0.02% | 58.1% | 0.45% |
| Name model | 0.680 | 0.685 | 0.5% | 0.02% | 9.9% | 1.04% |

Stacking weights on component logits: code GBDT 0.83, code CNN 0.34, name -0.06 (fit on validation with 5-fold cluster-grouped cross-fitting; calibration and thresholds use out-of-fold scores).

## Against GuardDog

[GuardDog](https://github.com/DataDog/guarddog) (Datadog's open-source scanner, v3.2) on the same canonical test archives, a fixed random sample of 1,500 malicious and 1,500 benign. Note the bias: most samples in Datadog's dataset were originally found with GuardDog's rules, so this comparison favours GuardDog.

| | GuardDog | Customs |
|---|---:|---:|
| ROC AUC (GuardDog risk score vs Customs risk) | 0.837 | 0.973 |
| Any finding: FPR | 18.0% | same FPR by construction |
| Any finding: detection rate | 79.4% | 94.9% |
| `high_risk` label: FPR | 5.0% | same FPR by construction |
| `high_risk` label: detection rate | 49.7% | 86.3% |

At GuardDog's own false-positive rate, Customs' detection-rate gain has a paired cluster-bootstrap 95% CI of 12.2 to 19.1 points. (For this comparison only, Customs' threshold is set on the test benign packages to match GuardDog's realized FPR; that is what matched-FPR means.)

## Where it is weak

| Slice | n malicious | n benign | ROC AUC | Recall at block | FPR at block |
|---|---:|---:|---:|---:|---:|
| ecosystem:pypi | 209 | 2,332 | 0.971 | 32.1% | 0.04% |
| ecosystem:npm | 3,891 | 1,885 | 0.956 | 56.5% | 0.05% |
| malicious:novel_campaigns | 3,550 | 4,217 | 0.972 | 55.5% | 0.05% |
| malicious:seen_campaigns | 550 | 4,217 | 0.975 | 54.0% | 0.05% |
| malicious:malicious_intent | 3,903 | 4,217 | 0.976 | 56.7% | 0.05% |
| malicious:compromised_lib | 197 | 4,217 | 0.888 | 26.9% | 0.05% |
| size:tercile_1 | 2,877 | 1,406 | 0.984 | 69.3% | 0.14% |
| size:tercile_2 | 747 | 1,405 | 0.960 | 30.5% | 0.00% |
| size:tercile_3 | 476 | 1,406 | 0.921 | 9.2% | 0.00% |

False-positive rate on benign packages by popularity tier:

| Tier | n | FPR at block | FPR at warn |
|---|---:|---:|---:|
| top | 574 | 0.00% | 0.52% |
| mid | 1,490 | 0.00% | 0.54% |
| tail | 2,153 | 0.09% | 0.88% |

`malicious:*` slices are each malicious subset against all benign test packages. `novel_campaigns` are test samples whose near-duplicate cluster has no member in training: the closest thing to a never-seen attack. Size terciles cut on benign source-line counts, to expose any small-package shortcut.

## Ablation: what does the code itself say?

The tree model retrained on 40 behavior features only (indicator counts and obfuscation statistics; no manifest metadata, sizes, or file counts):

| Feature set | ROC AUC | Recall at block | Recall at warn |
|---|---:|---:|---:|
| All features (before augmentation) | 0.976 | 73.0% | 81.1% |
| All features | 0.969 | 68.1% | 79.1% |
| Behavior only | 0.937 | 41.0% | 58.6% |

## Adversarial robustness

Held-out test malware rewritten as text (never executed), re-scanned and re-scored. Detection rate at the block and warn thresholds. *Seen* transforms are families the augmentation stage trained on (with donors from the training split; the test donors are different packages). *Unseen* ones were never used in training.

| Transform | Seen in training | Block (before) | Block (after) | Warn (before) | Warn (after) |
|---|---|---:|---:|---:|---:|
| none | n/a | 53.0% | 54.6% | 80.0% | 79.0% |
| string_split | no | 47.6% | 51.6% | 78.0% | 76.2% |
| base64_wrap | no | 68.4% | 75.4% | 91.6% | 93.9% |
| trojan_padding | yes | 35.4% | 50.7% | 68.0% | 79.2% |
| indirection | no | 52.5% | 53.9% | 79.9% | 78.9% |
| metadata_mimicry | yes | 38.6% | 47.8% | 63.2% | 76.0% |
| starjack | yes | 29.8% | 46.0% | 57.9% | 74.2% |

Clean test performance before and after augmentation:

| | ROC AUC | Recall at block | Recall at warn | FPR at block |
|---|---:|---:|---:|---:|
| Before | 0.979 | 53.9% | 80.0% | 0.00% |
| After | 0.972 | 55.3% | 79.5% | 0.05% |

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
| Mean latency per request (scan + score + policy) | 51 ms |
| Malicious: blocked (HTTP 403) | 54.9% |
| Malicious: blocked or warned | 77.8% |
| Benign: blocked | 0.2% |
| Benign: warned | 0.5% |
| Decisions identical to the Python pipeline | 100.0% |
| Largest risk difference vs Python | 1.05e-07 |

## Calibration

![Calibration](figures/calibration.png)

Risk is calibrated (Platt scaling on out-of-fold validation scores) at the class balance of the evaluation data, roughly even. In the wild malware is far rarer, so treat the risk as a ranking with frozen thresholds rather than as the literal probability that a random package from the registry is malicious.

![Feature importance](figures/feature_importance.png)

## Limitations

* **Label source bias.** Malware comes from Datadog's dataset, mostly found by GuardDog's heuristics, so the positives over-represent what heuristics already catch. Novel techniques that neither GuardDog nor these features describe are under-represented in both training and test.
* **Benign label noise.** Long-tail benign packages could include undiscovered malware. They were filtered against all 234K OSSF reports and required to be at least 90 days old, which removes most of it but not all.
* **Static analysis only.** Code that fetches its payload at runtime from a clean host, or hides logic in native binaries, gives little static signal. The policy rules (minimum age, nonexistent names, install scripts in new packages) are the backstop.
* **Adaptive attackers.** The robustness table covers a handful of cheap evasions. An attacker who can query the model can do better; published work on prompt and malware detectors shows adaptive attacks break most static classifiers. Customs is one layer, not a guarantee.

