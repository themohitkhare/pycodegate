"""Verify the source-reviewed sample against local scan output."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

BENCHMARKS = Path(__file__).resolve().parent
PER_SEVERITY = 5
SEVERITIES = ("error", "warning")
VERDICTS = {"actionable", "context-dependent", "false-positive"}


def digest(diagnostic: dict) -> str:
    canonical = json.dumps(diagnostic, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def select_sample(diagnostics: list[dict]) -> list[tuple[str, str]]:
    selected = []
    for severity in SEVERITIES:
        hashes = sorted(digest(item) for item in diagnostics if item["severity"] == severity)
        selected.extend((severity, value) for value in hashes[:PER_SEVERITY])
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scans", type=Path, help="Directory containing the five local scan reports")
    parser.add_argument(
        "--review", type=Path, default=BENCHMARKS / "results" / "large-repo-review.json"
    )
    args = parser.parse_args()
    pins = json.loads((BENCHMARKS / "large_repo_pins.json").read_text())
    review = json.loads(args.review.read_text())
    expected = Counter()
    for name, pin in pins.items():
        scan = json.loads((args.scans / f"{name}.json").read_text())
        for severity, key in select_sample(scan["diagnostics"]):
            expected[pin["repository"], severity, key] += 1
    actual = Counter((row["repo"], row["severity"], row["sha256"]) for row in review)
    if actual != expected:
        raise SystemExit("The reviewed diagnostics differ from the deterministic sample")
    if any(digest(row["diagnostic"]) != row["sha256"] for row in review):
        raise SystemExit("A published diagnostic differs from the reviewed scan output")
    classifications = Counter(row["classification"] for row in review)
    if classifications.keys() - VERDICTS:
        raise SystemExit("Unknown classification in the review")
    print(json.dumps(classifications, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
