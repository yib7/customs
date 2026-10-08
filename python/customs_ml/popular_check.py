"""Popular packages at their latest release: how often does the firewall stop one?

The benign test set measures false positives on a sample frozen before training. This asks
the question a user meets on the first day: the most-downloaded packages, at whatever
version the registry serves today, sent through a running ``customs serve`` (downloaded and
scanned in memory, never installed). Every package here is benign in practice, so each
warn or block is a false positive or a policy rule doing what it was set to do (a release
younger than ``min_age_days``, a change of publisher), and the report keeps the two apart:
``model`` is the classifier's own decision, ``final`` includes the rules.

    customs serve --bind 127.0.0.1:7979 --data-dir work/popular
    python -m customs_ml.popular_check --server http://127.0.0.1:7979 --n 300

Names come from ``models/popular_{pypi,npm}.txt`` (the name model's popularity lists).
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DECISIONS = ("allow", "warn", "block")
REPO = Path(__file__).resolve().parents[2]


def record(eco: str, name: str, verdict: dict) -> dict:
    """One row from a ``/api/check`` verdict."""
    return {
        "eco": eco,
        "name": name,
        "version": verdict.get("version"),
        "artifact": verdict.get("artifact"),
        "decision": verdict["decision"],
        "model_decision": verdict.get("model_decision"),
        "risk": verdict.get("risk"),
        "rules": [h["rule"] for h in verdict["policy_hits"] if h["severity"] != "allow"],
        "top": [r["feature"] for r in verdict["reasons"][:4]],
    }


def check(server: str, eco: str, name: str) -> dict:
    body = {"ecosystem": eco, "name": name, "client": "popular_check", "resolve": "upstream"}
    req = urllib.request.Request(
        server.rstrip("/") + "/api/check",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return record(eco, name, json.load(r))
    except urllib.error.HTTPError as e:
        try:
            error = json.load(e).get("error", str(e.code))
        except ValueError:
            error = str(e.code)
        return {"eco": eco, "name": name, "error": error}
    except (urllib.error.URLError, TimeoutError) as e:
        return {"eco": eco, "name": name, "error": str(e)}


def summarize(rows: list[dict]) -> dict:
    out = {}
    for eco in sorted({r["eco"] for r in rows}):
        xs = [r for r in rows if r["eco"] == eco]
        ok = [r for r in xs if "error" not in r]
        model = Counter(r["model_decision"] for r in ok)
        final = Counter(r["decision"] for r in ok)
        risks = [r["risk"] for r in ok if r["risk"] is not None]
        out[eco] = {
            "n": len(xs),
            "errors": len(xs) - len(ok),
            "checked": len(ok),
            "model": {d: model[d] for d in DECISIONS},
            "final": {d: final[d] for d in DECISIONS},
            "rules": dict(Counter(rule for r in ok for rule in r["rules"]).most_common()),
            "model_flagged": [r for r in ok if r["model_decision"] != "allow"],
            "risk_max": max(risks, default=None),
        }
    return out


def names(eco: str, n: int) -> list[str]:
    path = REPO / "models" / f"popular_{eco}.txt"
    return [x.strip() for x in path.read_text().splitlines() if x.strip()][:n]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--server", default="http://127.0.0.1:7979")
    ap.add_argument("--n", type=int, default=300, help="packages per ecosystem")
    ap.add_argument("--out", type=Path, default=Path("work/popular_check.json"))
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    jobs = [(eco, x) for eco in ("pypi", "npm") for x in names(eco, args.n)]
    with ThreadPoolExecutor(args.workers) as ex:
        rows = list(ex.map(lambda j: check(args.server, *j), jobs))
    summary = summarize(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"rows": rows, "summary": summary}, indent=1) + "\n")
    for eco, s in summary.items():
        print(
            f"{eco}: {s['checked']} checked, {s['errors']} errors; model {s['model']}; "
            f"with rules {s['final']}; rules {s['rules']}"
        )
        for r in s["model_flagged"]:
            flag, risk = r["model_decision"], r["risk"]
            print(f"  model {flag}: {r['name']} {r['version']} {risk:.3f} {r['top']}")


if __name__ == "__main__":
    main()
