"""Command line for rebuilding the dataset and models from scratch.

    customs-ml ossf --repo /path/to/ossf/malicious-packages      # git clone first
    customs-ml malicious                                         # Datadog samples
    customs-ml benign                                            # PyPI + npm downloads
    customs-ml names                                             # name-model data
    customs-ml train                                             # every pipeline stage
    customs-ml report                                            # docs/EVALUATION.md

All data goes under $CUSTOMS_DATA (default: customs-data in the system temp directory).
"""

from __future__ import annotations

import argparse
import random
import subprocess
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

from . import benign, config, malicious, names, ossf

DATADOG_REPO = "https://github.com/DataDog/malicious-software-packages-dataset"
DATADOG_RAW = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/"


def cmd_ossf(args) -> None:
    df = ossf.build_table(Path(args.repo))
    out = config.sub("ossf") / "ossf_reports.parquet"
    df.to_parquet(out)
    print(f"{len(df)} reports -> {out}")


def _datadog_listing(repo_url: str = DATADOG_REPO) -> list[str]:
    """List sample paths with a blobless clone (no sample content is downloaded)."""
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--depth",
                "1",
                "--filter=blob:none",
                "--no-checkout",
                repo_url,
                td,
            ],
            check=True,
        )
        # quotepath off and -z: otherwise git C-quotes non-ASCII paths and they fail SAMPLE_RE.
        out = subprocess.run(
            [
                "git",
                "-c",
                "core.quotepath=off",
                "-C",
                td,
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                "HEAD",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        ).stdout
    return [p for p in out.split("\0") if malicious.SAMPLE_RE.search(p)]


def pick_samples(paths: list[str], cap_intent: int, cap_compromised: int, seed: int) -> list[str]:
    """Cap samples per (ecosystem, kind, discovery date): campaigns cluster on dates, and
    one worm can contribute hundreds of copies. PyPI is kept whole (it is small)."""
    groups: dict[tuple, list[str]] = defaultdict(list)
    for p in paths:
        s = malicious.parse_sample_path(p)
        groups[(s.ecosystem, s.kind, s.discovered)].append(p)
    rng = random.Random(seed)
    picked = []
    for (eco, kind, _), items in groups.items():
        rng.shuffle(items)
        cap = (
            len(items)
            if eco == "pypi"
            else (cap_compromised if kind == "compromised_lib" else cap_intent)
        )
        picked += items[:cap]
    rng.shuffle(picked)
    return picked


def cmd_malicious(args) -> None:
    picked = pick_samples(_datadog_listing(), args.cap_intent, args.cap_compromised, args.seed)
    raw_dir = config.sub("datadog_raw")
    print(f"{len(picked)} samples selected")
    session = requests.Session()

    def fetch(rel: str) -> None:
        dest = raw_dir / rel
        if dest.exists():
            return
        r = session.get(DATADOG_RAW + requests.utils.quote(rel), timeout=60)
        if r.ok:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(r.content)

    # Download and ingest in chunks, deleting the encrypted zips after each chunk, so the
    # disk only ever holds one chunk of raw samples.
    for start in range(0, len(picked), args.chunk):
        chunk = picked[start : start + args.chunk]
        with ThreadPoolExecutor(16) as ex:
            list(ex.map(fetch, chunk))
        listing = raw_dir / "chunk.txt"
        listing.write_text("\n".join(chunk) + "\n", encoding="utf-8")
        malicious.ingest(raw_dir, workers=args.workers, tree_listing=listing)
        for p in raw_dir.rglob("*.zip"):
            p.unlink()
        print(f"ingested {min(start + args.chunk, len(picked))}/{len(picked)}")


def cmd_benign(args) -> None:
    from .features import canonicalize_benign_corpus

    for seed, mid, tail in ((7, 2000, 3000), (8, 4000, 7000)):
        benign.build(n_top=1500, n_mid=mid, n_tail=tail, seed=seed)
    canonicalize_benign_corpus(
        config.sub("benign") / "manifest.jsonl",
        config.sub("benign_canonical"),
        delete_original=True,
    )


def cmd_names(args) -> None:
    df = names.build()
    print(df.groupby(["ecosystem", "label"]).size())


def cmd_train(args) -> None:
    from . import nn as cnn
    from . import pipeline, robustness

    pipeline.main(["table", "cluster", "split", "gbdt", "ablation"])
    pipeline.stage_cnn(cfg=cnn.Config(max_len=768, epochs=10, patience=3))
    pipeline.main(["names", "ensemble", "evaluate", "export"])
    robustness.run(n=800)
    if args.augment:
        work = pipeline.work()
        for f in ("eval", "robustness", "ensemble", "ablation"):
            src = work / f"{f}_{pipeline.SCHEME}.json"
            (work / f"baseline_{src.name}").write_text(
                src.read_text(encoding="utf-8"), encoding="utf-8"
            )
        pipeline.main(["augment", "gbdt", "ablation"])
        pipeline.stage_cnn(cfg=cnn.Config(max_len=768, epochs=10, patience=3))
        pipeline.main(["ensemble", "evaluate", "export"])
        robustness.run(n=800)


def cmd_report(args) -> None:
    from . import report

    report.main()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(
        prog="customs-ml", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ossf", help="parse a clone of ossf/malicious-packages")
    p.add_argument("--repo", required=True)
    p.set_defaults(fn=cmd_ossf)
    p = sub.add_parser("malicious", help="download and canonicalize Datadog samples")
    p.add_argument("--cap-intent", type=int, default=40)
    p.add_argument("--cap-compromised", type=int, default=20)
    p.add_argument("--chunk", type=int, default=500)
    p.add_argument("--workers", type=int, default=3)
    p.add_argument("--seed", type=int, default=11)
    p.set_defaults(fn=cmd_malicious)
    sub.add_parser("benign", help="download benign PyPI and npm archives").set_defaults(
        fn=cmd_benign
    )
    sub.add_parser("names", help="build name-model data").set_defaults(fn=cmd_names)
    p = sub.add_parser("train", help="run every training and evaluation stage")
    p.add_argument("--no-augment", dest="augment", action="store_false")
    p.set_defaults(fn=cmd_train)
    sub.add_parser("report", help="write docs/EVALUATION.md").set_defaults(fn=cmd_report)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
