"""Build the benign corpus: real package archives downloaded from PyPI and npm.

Sampling matters more than volume here. Malicious packages are mostly small, young, and
obscure, so a benign set made only of popular packages would teach the model "small and
unknown means malicious". The corpus therefore mixes three popularity tiers per ecosystem:

* ``top``: the most downloaded packages,
* ``mid``: ranks beyond the top tier of the popularity list,
* ``tail``: packages drawn uniformly from the whole registry (PyPI) or reached through
  dependency crawling and keyword search (npm), which is where most real uploads live.

Any candidate whose name appears in the OSSF malicious-packages reports is dropped. Tail
packages are also required to be at least ``min_age_days`` old, since malicious uploads
are usually removed within days; surviving that long is weak evidence of benign intent.
Residual label noise from undiscovered malware is expected and discussed in the report.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import requests

from . import config

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
PYPI_SIMPLE = "https://pypi.org/simple/"
TOP_PYPI = (
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
)
NPM_PACKUMENT = "https://registry.npmjs.org/{name}"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"

MAX_ARCHIVE_BYTES = 15 * 1024 * 1024
USER_AGENT = "customs-ml dataset builder (research; static analysis only)"


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def normalize(ecosystem: str, name: str) -> str:
    return normalize_pypi(name) if ecosystem == "pypi" else name.lower()


@dataclass
class Candidate:
    ecosystem: str
    name: str
    tier: str
    downloads: int | None = None


@dataclass
class Artifact:
    ecosystem: str
    name: str
    version: str
    tier: str
    file: str
    path: str
    sha256: str
    size: int
    artifact_type: str
    upload_time: str | None
    downloads: int | None


_local = threading.local()


def session() -> requests.Session:
    s = getattr(_local, "s", None)
    if s is None:
        s = requests.Session()
        s.headers["User-Agent"] = USER_AGENT
        _local.s = s
    return s


def get_json(url: str, **kw) -> dict | None:
    for _ in range(3):
        try:
            r = session().get(url, timeout=30, **kw)
        except requests.RequestException:
            continue
        if r.status_code == 404:
            return None
        if r.ok:
            return r.json()
    return None


def malicious_names(ossf: pd.DataFrame, ecosystem: str) -> set[str]:
    names = ossf.loc[ossf.ecosystem == ecosystem, "name"].dropna()
    return {normalize(ecosystem, n) for n in names}


# ---------------------------------------------------------------- candidates


def pypi_candidates(
    bad: set[str], n_top: int, n_mid: int, n_tail: int, rng: random.Random
) -> list[Candidate]:
    rows = session().get(TOP_PYPI, timeout=60).json()["rows"]
    ranked = [(r["project"], int(r["download_count"])) for r in rows]
    top = ranked[:n_top]
    mid_pool = ranked[n_top:]
    mid = rng.sample(mid_pool, min(n_mid, len(mid_pool)))
    popular = {normalize_pypi(n) for n, _ in ranked}

    idx = (
        session()
        .get(PYPI_SIMPLE, headers={"Accept": "application/vnd.pypi.simple.v1+json"}, timeout=120)
        .json()
    )
    pool = [p["name"] for p in idx["projects"] if normalize_pypi(p["name"]) not in popular]
    # Oversample the tail: many uniformly drawn projects have no files or are too young.
    tail = rng.sample(pool, min(n_tail * 3, len(pool)))

    out = [Candidate("pypi", n, "top", d) for n, d in top]
    out += [Candidate("pypi", n, "mid", d) for n, d in mid]
    out += [Candidate("pypi", n, "tail") for n in tail]
    return [c for c in out if normalize_pypi(c.name) not in bad]


NPM_SEEDS = [
    "react",
    "express",
    "lodash",
    "axios",
    "typescript",
    "webpack",
    "vite",
    "next",
    "vue",
    "eslint",
    "jest",
    "commander",
    "chalk",
    "yargs",
    "moment",
    "dayjs",
    "uuid",
    "debug",
    "dotenv",
    "cors",
    "body-parser",
    "mongoose",
    "pg",
    "redis",
    "ws",
    "socket.io",
    "@babel/core",
    "@types/node",
    "prettier",
    "rollup",
    "esbuild",
    "tailwindcss",
    "postcss",
    "zod",
    "rxjs",
    "graphql",
    "@apollo/client",
    "three",
    "d3",
    "chart.js",
    "sharp",
    "jsdom",
    "puppeteer",
    "playwright",
    "nodemon",
    "pm2",
    "koa",
    "fastify",
    "hapi",
    "sequelize",
    "prisma",
    "knex",
    "aws-sdk",
    "@aws-sdk/client-s3",
    "firebase",
    "stripe",
    "openai",
    "electron",
    "react-native",
    "@angular/core",
    "svelte",
    "nuxt",
    "gatsby",
    "storybook",
    "mocha",
    "chai",
    "sinon",
    "cypress",
    "husky",
    "lint-staged",
    "semver",
    "glob",
    "minimist",
    "inquirer",
    "ora",
    "boxen",
    "figlet",
    "marked",
    "highlight.js",
    "nanoid",
]

NPM_KEYWORDS = [
    "cli",
    "util",
    "parser",
    "logger",
    "config",
    "http",
    "json",
    "math",
    "string",
    "date",
    "color",
    "file",
    "stream",
    "plugin",
    "react-component",
    "vue-component",
    "eslint-plugin",
    "babel-plugin",
    "webpack-plugin",
    "express-middleware",
    "cache",
    "crypto",
    "validation",
    "test",
    "mock",
    "template",
    "markdown",
    "image",
    "audio",
    "game",
    "bot",
    "discord",
    "telegram",
    "api",
    "sdk",
    "client",
    "wrapper",
    "hooks",
    "state",
    "router",
    "form",
    "chart",
    "map",
    "geo",
    "time",
    "queue",
    "worker",
    "redis",
    "mongodb",
    "sql",
    "orm",
    "auth",
    "jwt",
    "oauth",
    "email",
    "sms",
    "pdf",
    "csv",
    "excel",
    "xml",
    "yaml",
    "ui",
    "icons",
    "css",
    "theme",
    "animation",
    "canvas",
    "svg",
    "webgl",
    "three",
    "ai",
    "llm",
    "openai",
    "blockchain",
    "ethereum",
    "solana",
    "nft",
    "wallet",
    "scraper",
    "crawler",
    "boilerplate",
    "starter",
    "template-project",
    "homework",
    "demo",
    "example",
    "tutorial",
]


def npm_search(text: str, size: int = 250, frm: int = 0) -> list[dict]:
    d = get_json(NPM_SEARCH, params={"text": text, "size": size, "from": frm})
    return (d or {}).get("objects", [])


def npm_candidates(
    bad: set[str], n_top: int, n_mid: int, n_tail: int, rng: random.Random
) -> list[Candidate]:
    seen: dict[str, int | None] = {}

    # Keyword search reaches long-tail packages; the result carries download counts.
    for kw in NPM_KEYWORDS:
        for frm in (0, 250, 500):
            for obj in npm_search(f"keywords:{kw}", frm=frm):
                name = obj["package"]["name"]
                monthly = (obj.get("downloads") or {}).get("monthly")
                seen[name] = monthly

    # Dependency crawl from popular seeds adds packages real projects actually pull in.
    frontier = list(NPM_SEEDS)
    crawled: set[str] = set()
    while frontier and len(crawled) < 3000:
        batch, frontier = frontier[:64], frontier[64:]
        with ThreadPoolExecutor(16) as ex:
            for name, deps in ex.map(_npm_latest_deps, batch):
                crawled.add(name)
                seen.setdefault(name, None)
                for d in deps:
                    if d not in crawled and d not in seen:
                        seen[d] = None
                        frontier.append(d)

    names = [n for n in seen if n.lower() not in bad]
    known = sorted((n for n in names if seen[n] is not None), key=lambda n: -seen[n])
    unknown = [n for n in names if seen[n] is None]
    top = known[:n_top]
    rest = known[n_top:]
    # Search results with fewer than 1,000 monthly downloads behave like the tail.
    mid_pool = [n for n in rest if seen[n] >= 1000]
    tail_pool = [n for n in rest if seen[n] < 1000] + unknown
    mid = rng.sample(mid_pool, min(n_mid, len(mid_pool)))
    tail = rng.sample(tail_pool, min(n_tail * 2, len(tail_pool)))
    out = [Candidate("npm", n, "top", seen[n]) for n in top]
    out += [Candidate("npm", n, "mid", seen[n]) for n in mid]
    out += [Candidate("npm", n, "tail", seen[n]) for n in tail]
    return out


def _npm_latest_deps(name: str) -> tuple[str, list[str]]:
    d = get_json(NPM_PACKUMENT.format(name=name.replace("/", "%2f")))
    if not d:
        return name, []
    latest = (d.get("dist-tags") or {}).get("latest")
    v = (d.get("versions") or {}).get(latest) or {}
    return name, list((v.get("dependencies") or {}).keys())


# ---------------------------------------------------------------- downloads


def _pick_pypi_file(meta: dict) -> tuple[str, dict] | None:
    version = meta["info"]["version"]
    files = [f for f in meta.get("urls", []) if not f.get("yanked")]
    sdists = [f for f in files if f["packagetype"] == "sdist"]
    wheels = [f for f in files if f["packagetype"] == "bdist_wheel"]
    # Malicious PyPI uploads are overwhelmingly sdists, so prefer sdists to keep the
    # artifact type from becoming a label shortcut.
    pick = (sdists or wheels or [None])[0]
    return (version, pick) if pick else None


def fetch_pypi(c: Candidate, dest: Path, min_age: timedelta) -> Artifact | None:
    meta = get_json(PYPI_JSON.format(name=c.name))
    if not meta:
        return None
    picked = _pick_pypi_file(meta)
    if not picked:
        return None
    version, f = picked
    if f["size"] > MAX_ARCHIVE_BYTES:
        return None
    uploaded = f.get("upload_time_iso_8601")
    if c.tier == "tail" and uploaded:
        first = _first_upload(meta) or uploaded
        if datetime.now(UTC) - _parse_ts(first) < min_age:
            return None
    return _download(c, version, f["url"], f["filename"], dest, f["packagetype"], uploaded)


def _first_upload(meta: dict) -> str | None:
    times = [
        f["upload_time_iso_8601"]
        for files in (meta.get("releases") or {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    return min(times) if times else None


def fetch_npm(c: Candidate, dest: Path, min_age: timedelta) -> Artifact | None:
    d = get_json(NPM_PACKUMENT.format(name=c.name.replace("/", "%2f")))
    if not d:
        return None
    latest = (d.get("dist-tags") or {}).get("latest")
    v = (d.get("versions") or {}).get(latest)
    if not v or "dist" not in v:
        return None
    if (v["dist"].get("unpackedSize") or 0) > 4 * MAX_ARCHIVE_BYTES:
        return None
    times = d.get("time") or {}
    created = times.get("created")
    if c.tier == "tail" and created and datetime.now(UTC) - _parse_ts(created) < min_age:
        return None
    url = v["dist"]["tarball"]
    fname = url.rsplit("/", 1)[-1]
    return _download(c, latest, url, fname, dest, "tgz", times.get(latest))


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _download(
    c: Candidate, version: str, url: str, fname: str, dest: Path, atype: str, uploaded: str | None
) -> Artifact | None:
    safe = re.sub(r"[^A-Za-z0-9._@-]+", "_", c.name)
    out_dir = dest / c.ecosystem / safe
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / re.sub(r"[^A-Za-z0-9._@+-]+", "_", fname)
    try:
        r = session().get(url, timeout=120, stream=True)
        if not r.ok:
            return None
        h = hashlib.sha256()
        size = 0
        with path.open("wb") as fh:
            for chunk in r.iter_content(1 << 16):
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise ValueError("too large")
                h.update(chunk)
                fh.write(chunk)
    except (requests.RequestException, ValueError):
        path.unlink(missing_ok=True)
        return None
    return Artifact(
        c.ecosystem,
        c.name,
        version,
        c.tier,
        fname,
        str(path),
        h.hexdigest(),
        size,
        atype,
        uploaded,
        c.downloads,
    )


def download_all(
    cands: Iterable[Candidate],
    dest: Path,
    manifest: Path,
    quotas: dict[tuple[str, str], int],
    workers: int = 12,
    min_age_days: int = 90,
) -> pd.DataFrame:
    """Download candidates until each (ecosystem, tier) quota is met. Resumable."""
    done: dict[tuple[str, str], int] = {}
    have: set[tuple[str, str]] = set()
    if manifest.exists():
        for line in manifest.read_text().splitlines():
            a = json.loads(line)
            have.add((a["ecosystem"], normalize(a["ecosystem"], a["name"])))
            key = (a["ecosystem"], a["tier"])
            done[key] = done.get(key, 0) + 1
    min_age = timedelta(days=min_age_days)
    lock = threading.Lock()
    todo = [
        c
        for c in cands
        if (c.ecosystem, normalize(c.ecosystem, c.name)) not in have
        and done.get((c.ecosystem, c.tier), 0) < quotas.get((c.ecosystem, c.tier), 0)
    ]

    def work(c: Candidate) -> Artifact | None:
        key = (c.ecosystem, c.tier)
        with lock:
            if done.get(key, 0) >= quotas.get(key, 0):
                return None
        fn = fetch_pypi if c.ecosystem == "pypi" else fetch_npm
        try:
            return fn(c, dest, min_age)
        except Exception:  # noqa: BLE001 - one bad package must not stop the crawl
            return None

    with ThreadPoolExecutor(workers) as ex, manifest.open("a") as mf:
        futs = [ex.submit(work, c) for c in todo]
        for fut in as_completed(futs):
            a = fut.result()
            if a is None:
                continue
            key = (a.ecosystem, a.tier)
            with lock:
                if done.get(key, 0) >= quotas.get(key, 0):
                    Path(a.path).unlink(missing_ok=True)
                    continue
                done[key] = done.get(key, 0) + 1
                mf.write(json.dumps(asdict(a)) + "\n")
                mf.flush()
    return pd.read_json(manifest, lines=True)


def build(n_top: int = 1500, n_mid: int = 2000, n_tail: int = 3000, seed: int = 7) -> pd.DataFrame:
    rng = random.Random(seed)
    ossf = pd.read_parquet(config.sub("ossf") / "ossf_reports.parquet")
    dest = config.sub("benign")
    cands: list[Candidate] = []
    cands += pypi_candidates(malicious_names(ossf, "pypi"), n_top, n_mid, n_tail, rng)
    cands += npm_candidates(malicious_names(ossf, "npm"), n_top, n_mid, n_tail, rng)
    rng.shuffle(cands)
    quotas = {
        (eco, tier): n
        for eco in ("pypi", "npm")
        for tier, n in (("top", n_top), ("mid", n_mid), ("tail", n_tail))
    }
    return download_all(cands, dest, dest / "manifest.jsonl", quotas)
