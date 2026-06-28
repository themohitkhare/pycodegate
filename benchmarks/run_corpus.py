"""Precision benchmark: run pycodegate against a corpus of respected PyPI packages.

A quality gate lives and dies by precision. This harness downloads the source
distributions of widely used, idiomatic Python packages and runs pycodegate over
each, aggregating findings by rule. Any rule that lights up heavily on well-written
code is a false-positive suspect.

Usage:
    python benchmarks/run_corpus.py            # default corpus, lint only
    python benchmarks/run_corpus.py --with-dead-code
    python benchmarks/run_corpus.py flask django sqlalchemy   # custom package list

The corpus is fetched from PyPI (no GitHub needed) into benchmarks/.corpus/ and
cached between runs. Nothing here is imported by the package itself.
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

DEFAULT_CORPUS = [
    "requests", "flask", "click", "rich", "httpx", "sqlalchemy", "fastapi",
    "starlette", "pydantic", "jinja2", "werkzeug", "urllib3", "django", "celery",
    "black", "isort", "pytest", "attrs", "typer", "pyyaml", "redis", "scrapy",
    "beautifulsoup4", "loguru", "pandas", "numpy", "pillow", "tornado", "aiohttp",
]

CORPUS_DIR = Path(__file__).parent / ".corpus"


def _sdist_url(pkg: str) -> tuple[str, str] | None:
    with urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30) as response:
        data = json.load(response)
    for entry in data["urls"]:
        if entry["packagetype"] == "sdist":
            return entry["url"], entry["filename"]
    return None


def _fetch(pkg: str) -> Path | None:
    dest = CORPUS_DIR / pkg
    if dest.exists():
        return dest
    found = _sdist_url(pkg)
    if not found:
        print(f"  no sdist for {pkg}", file=sys.stderr)
        return None
    url, filename = found
    with urllib.request.urlopen(url, timeout=120) as response:
        blob = response.read()
    dest.mkdir(parents=True)
    if filename.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
            archive.extractall(dest, filter="data")
    elif filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            archive.extractall(dest)
    return dest


def _source_root(pkg_dir: Path) -> Path:
    candidates = [
        parent
        for parent in pkg_dir.rglob("*")
        if parent.is_dir() and (parent / "pyproject.toml").exists()
    ]
    return min(candidates, key=lambda p: len(p.parts)) if candidates else pkg_dir


def _scan(root: Path, with_dead_code: bool) -> dict:
    cmd = [sys.executable, "-m", "pycodegate", str(root), "--json"]
    if not with_dead_code:
        cmd.append("--no-dead-code")
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return json.loads(out.stdout)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="*", default=DEFAULT_CORPUS)
    parser.add_argument("--with-dead-code", action="store_true")
    args = parser.parse_args()
    packages = args.packages or DEFAULT_CORPUS

    rule_counts: Counter[str] = Counter()
    scores: list[int] = []
    print(f"{'package':16s} {'score':>5}  {'files':>6}  findings")
    for pkg in packages:
        pkg_dir = _fetch(pkg)
        if pkg_dir is None:
            continue
        data = _scan(_source_root(pkg_dir), args.with_dead_code)
        scores.append(data["score"])
        for diag in data["diagnostics"]:
            rule_counts[diag["rule"]] += 1
        files = data["project"]["source_file_count"]
        print(f"{pkg:16s} {data['score']:>5}  {files:>6}  {len(data['diagnostics'])}")

    print(f"\nmean score: {sum(scores) / len(scores):.1f}" if scores else "no results")
    print("\nfindings by rule:")
    for rule, count in rule_counts.most_common():
        print(f"  {count:6d}  {rule}")


if __name__ == "__main__":
    main()
