# Credits

Customs is trained and evaluated on data other people collected and published. Nothing
below is redistributed in its original form: the repository holds trained model files,
package-name lists and aggregate metrics, never a malware sample.

## Datasets

| Source | License | Used for | In this repository |
|---|---|---|---|
| [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | Apache-2.0 | Malicious npm and PyPI archives for training and testing | Model weights trained on it, aggregate metrics |
| [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | Apache-2.0 | Names of reported malware, used to keep them out of the benign set and to measure takedowns | Aggregate metrics |
| [MalRegistry](https://github.com/lxyeternal/pypi_malregistry) (Guo et al., ASE 2023) | No license file published | Second, independent PyPI malware collection for evaluation and for training on its dev half | Model weights trained on part of it, aggregate metrics |
| [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) by Hugo van Kemenade | No license file published | Popular PyPI names for benign sampling and the name model | `models/popular_pypi.txt` (package names only) |
| [npm-high-impact](https://github.com/wooorm/npm-high-impact) by Titus Wormer | MIT | Popular npm names for benign sampling and the name model | `models/popular_npm.txt` (package names only) |
| PyPI and the npm registry | Each package's own license | Benign archives for training and testing, downloaded at build time | Model weights and metrics only |

## Tools compared against

[GuardDog](https://github.com/DataDog/guarddog) (Apache-2.0) is the baseline in
[EVALUATION.md](EVALUATION.md). It is run during evaluation and is not bundled.

## Software

Rust, Python and npm dependencies are listed in `Cargo.lock`, `python/uv.lock` and
`web/package-lock.json`. All of them are under permissive licenses (MIT, Apache-2.0, BSD,
ISC, Zlib, Unicode-3.0 and similar). Build-only npm tools include lightningcss (MPL-2.0)
and the caniuse-lite data (CC-BY-4.0); they run at build time and are not shipped.
