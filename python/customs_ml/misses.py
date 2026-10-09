"""Where the test misses come from, and whether packaged binaries could close the gap.

Two analyses feed the report's "What the misses are" section:

* ``categorize``: every test malware sample the ensemble lets through at the warn
  threshold, grouped by what the scanner saw (behavior indicators on the install surface,
  only elsewhere, or nowhere), plus the share of misses whose only code is a compiled
  binary.
* ``binary_strings``: for every corpus archive holding an ELF, PE or Mach-O file, which
  infostealer and command-and-control strings appear in those binaries. Archives are read
  in memory and nothing is executed. This is slow (about 20 minutes), so results are
  cached in ``work/binary_strings.jsonl`` and resumed.

    python -m customs_ml.misses
"""

from __future__ import annotations

import json
import re
import tarfile
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from . import registry_status, splits
from .pipeline import SCHEME, load_table, log, work

BEHAVIOR = (
    "proc_exec",
    "dyn_code",
    "network",
    "decode_obf",
    "env_access",
    "secret_paths",
    "persistence",
    "recon",
    "download_exec",
    "exfil_endpoint",
    "ip_url",
    "crypto_wallet",
)

MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

# Strings an infostealer or dropper carries in clear text. Matched case-insensitively.
STEALER_STRINGS = {
    "discord_webhook": (b"discord.com/api/webhooks", b"discordapp.com/api/webhooks"),
    "telegram_bot": (b"api.telegram.org/bot",),
    "browser_login_data": (b"login data", b"web data", b"local state"),
    "leveldb": (b"local storage\\leveldb", b"local storage/leveldb"),
    "wallet": (b"wallet.dat", b"exodus", b"electrum", b"metamask"),
    "ssh_keys": (b".ssh/id_", b".ssh\\id_"),
    "keychain": (b"login.keychain", b"find-generic-password"),
    "paste_or_tunnel": (b"pastebin.com", b"transfer.sh", b"ngrok", b"webhook.site"),
    "anti_vm": (b"vboxservice", b"vmtoolsd", b"wireshark", b"x64dbg", b"ollydbg"),
    "powershell": (b"-encodedcommand", b"-executionpolicy bypass"),
    "autorun": (b"schtasks", b"currentversion\\run"),
}
# Per-platform prebuilt packages: `<name>-win32-x64-msvc`, `@scope/pkg-darwin-arm64`.
PLATFORM_RE = r"-(?:win32|darwin|linux|freebsd|android|windows|macos)(?:-|$)"
PACKERS = {"pyinstaller": (b"pyinstaller", b"_meipass"), "go_binary": (b"go build id",)}
IP_URL = re.compile(rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
SCAN_CAP = 24 << 20
MAX_MEMBER = 96 << 20


def _members(path: str):
    if path.endswith((".zip", ".whl")):
        z = zipfile.ZipFile(path)
        for i in z.infolist():
            if not i.is_dir() and i.file_size <= MAX_MEMBER:
                yield z.read(i)
        return
    with tarfile.open(path) as t:
        for m in t.getmembers():
            if m.isfile() and m.size <= MAX_MEMBER:
                f = t.extractfile(m)
                if f is not None:
                    yield f.read()


def binary_hits(path: str) -> dict:
    """Count binaries in one archive and which string families appear in them."""
    out: dict = {"n_binaries": 0}
    for data in _members(path):
        if not data.startswith(MAGIC):
            continue
        out["n_binaries"] += 1
        low = data[:SCAN_CAP].lower()
        for k, lits in (STEALER_STRINGS | PACKERS).items():
            if any(x in low for x in lits):
                out[k] = out.get(k, 0) + 1
        if IP_URL.search(data[:SCAN_CAP]):
            out["ip_url"] = out.get("ip_url", 0) + 1
    return out


def binary_strings(df: pd.DataFrame, scheme: str = SCHEME) -> pd.DataFrame:
    path = work() / "binary_strings.jsonl"
    done = {}
    if path.exists():
        done = {r["path"]: r for r in map(json.loads, path.read_text().splitlines())}
    rows = df[df.f_n_binary > 0]
    with path.open("a") as f:
        for p in rows.canonical_path:
            if p in done:
                continue
            try:
                r = {"path": p, **binary_hits(p)}
            except OSError, tarfile.TarError, zipfile.BadZipFile, EOFError:
                r = {"path": p, "n_binaries": 0, "error": 1}
            done[p] = r
            f.write(json.dumps(r) + "\n")
    hits = pd.DataFrame([done[p] for p in rows.canonical_path]).fillna(0)
    hits["label"] = rows.label.to_numpy()
    hits["split"] = rows[f"split_{scheme}"].to_numpy()
    return hits[hits.n_binaries > 0]


def categorize(df: pd.DataFrame, thr_warn: float, scheme: str = SCHEME) -> dict:
    """Group test malware the ensemble misses at warn; ``df`` holds corpus rows only."""
    te = df[(df[f"split_{scheme}"] == splits.TEST) & (df.label == 1)]
    beh_all = te[[f"f_all_{b}" for b in BEHAVIOR]].sum(axis=1)
    beh_inst = te[[f"f_inst_{b}" for b in BEHAVIOR]].sum(axis=1)
    miss = te[f"ens_risk_{scheme}"] < thr_warn
    cat = np.where(
        beh_all == 0,
        "no_indicator",
        np.where(beh_inst == 0, "indicators_off_surface", "indicators_on_surface"),
    )
    out = {"n_test_malware": len(te), "n_missed": int(miss.sum()), "categories": {}}
    for c in ("indicators_on_surface", "indicators_off_surface", "no_indicator"):
        m = cat == c
        out["categories"][c] = {
            "n": int(m.sum()),
            "missed": int((miss & m).sum()),
            "miss_rate": float(miss[m].mean()) if m.any() else None,
        }
    binonly = (te.f_n_binary > 0) & (te.f_all_n_lines < 50)
    out["binary_only"] = {
        "n_test_malware": int(binonly.sum()),
        "missed": int((miss & binonly).sum()),
        "miss_rate": float(miss[binonly].mean()) if binonly.any() else None,
        "n_train_malware": int(
            (
                (df[f"split_{scheme}"] == splits.TRAIN)
                & (df.label == 1)
                & (df.f_n_binary > 0)
                & (df.f_all_n_lines < 50)
            ).sum()
        ),
    }
    snap = registry_status.load()
    if snap is not None:
        reg = np.array(registry_status.status_column(te, snap), dtype=object)
        platform = te.name.str.contains(PLATFORM_RE).to_numpy()
        out["binary_only"]["by_registry"] = {
            c: {
                "n": int((binonly & (reg == c)).sum()),
                "platform_named": int((binonly & (reg == c) & platform).sum()),
                "miss_rate": float(miss[binonly & (reg == c)].mean())
                if (binonly & (reg == c)).any()
                else None,
            }
            for c in ("removed", "still_published")
        }
    return out


def run(scheme: str = SCHEME) -> dict:
    df = load_table()
    if "augmented" in df:
        df = df[df.augmented.isna()]
    if "source" in df:
        df = df[df.source.isna()]
    ens = json.loads((work() / f"ensemble_{scheme}.json").read_text())
    res = categorize(df, ens["thresholds"]["warn"], scheme)
    hits = binary_strings(df, scheme)
    stealer = [k for k in [*STEALER_STRINGS, "ip_url"] if k in hits]
    hits["any_stealer_string"] = (hits[stealer] > 0).any(axis=1)
    prev = {}
    for (sp, lab), g in hits.groupby(["split", "label"]):
        prev[f"{sp}:{'malicious' if lab else 'benign'}"] = {
            "n": len(g),
            "any_stealer_string": float(g.any_stealer_string.mean()),
            **{k: float((g[k] > 0).mean()) for k in PACKERS if k in g},
        }
    res["binary_strings"] = prev
    Path(work() / "misses.json").write_text(json.dumps(res, indent=1))
    log("misses", res["categories"], res["binary_only"])
    return res


if __name__ == "__main__":
    print(json.dumps(run(), indent=1))
