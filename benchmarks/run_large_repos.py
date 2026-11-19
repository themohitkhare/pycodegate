"""Scan pinned upstream Git checkouts and summarize the JSON diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = json.loads((ROOT / "benchmarks/large_repo_pins.json").read_text())
SCANNER_COMMIT = "edcf65bbc34f18b911ef8eeec56f87e79d9561db"
SCAN_FLAGS = ["--json", "--no-dead-code"]
DEFAULT_JOBS = 2
SCAN_TIMEOUT_SECONDS = 3600
HEADER_BYTES = 1200
TRANSFORMERS_MARKER = b"this file was automatically generated from"


def git_text(directory: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=directory, text=True).strip()


def prepare_repo(workspace: Path, name: str, pin: dict) -> Path:
    checkout = workspace / "repos" / name
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/{pin['repository']}.git"
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", "--branch", pin["tag"], url, str(checkout)],
            check=True,
        )
    if git_text(checkout, "rev-parse", "HEAD") != pin["commit"]:
        raise ValueError(f"Unexpected commit for {name}")
    if git_text(checkout, "status", "--porcelain", "--ignored", "--untracked-files=all"):
        raise ValueError(f"Expected a clean checkout of {name}")
    return checkout


def scan_environment(workspace: Path, scratch: Path) -> dict:
    archive = subprocess.check_output(["git", "archive", SCANNER_COMMIT, "src"], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(scratch, filter="data")
    git = shutil.which("git")
    if not git:
        raise ValueError("Git is required")
    commands = scratch / "bin"
    commands.mkdir()
    (commands / "git").symlink_to(git)
    return {
        "PATH": str(commands),
        "PYTHONPATH": str(scratch / "src"),
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CEILING_DIRECTORIES": str(workspace),
    }


def scan(checkout: Path, scratch: Path, environment: dict) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "pycodegate", str(checkout), *SCAN_FLAGS],
        cwd=scratch,
        check=True,
        capture_output=True,
        env=environment,
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    output = json.loads(result.stdout)
    for diagnostic in output["diagnostics"]:
        path = Path(diagnostic["file_path"])
        if path.is_absolute():
            diagnostic["file_path"] = path.relative_to(checkout).as_posix()
    output["diagnostics"].sort(key=lambda item: json.dumps(item, sort_keys=True))
    output["path"] = "."
    del output["elapsed_ms"]
    return output


def summarize(output: dict) -> dict:
    diagnostics = output["diagnostics"]
    counts = {
        f"by_{field}": dict(sorted(Counter(item[field] for item in diagnostics).items()))
        for field in ("severity", "category", "rule")
    }
    encoded = json.dumps(output, sort_keys=True).encode()
    return {
        "score": output["score"],
        "profile": output["profile"],
        "discovered_python_files": output["project"]["source_file_count"],
        "findings": len(diagnostics),
        "normalized_output_sha256": hashlib.sha256(encoded).hexdigest(),
        **counts,
    }


def generated_file_counts(checkout: Path, output: dict, scratch: Path, environment: dict) -> dict:
    query = (
        "import json, sys\n"
        "from pycodegate.utils.file_discovery import find_python_files\n"
        "print(json.dumps([str(path) for path in find_python_files(sys.argv[1])]))"
    )
    files = json.loads(
        subprocess.check_output(
            [sys.executable, "-c", query, str(checkout)], cwd=scratch, env=environment
        )
    )
    if len(files) != output["project"]["source_file_count"]:
        raise ValueError("Discovered file count changed after scanning")
    generated = set()
    for filename in files:
        path = Path(filename)
        with path.open("rb") as source:
            if TRANSFORMERS_MARKER in source.read(HEADER_BYTES).lower():
                generated.add(path.relative_to(checkout).as_posix())
    findings = [item for item in output["diagnostics"] if item["file_path"] in generated]
    return {
        "case_insensitive_ascii_marker": TRANSFORMERS_MARKER.decode(),
        "header_bytes": HEADER_BYTES,
        "discovered_files_with_marker": len(generated),
        "findings_on_marked_files": len(findings),
        "by_severity": dict(sorted(Counter(item["severity"] for item in findings).items())),
        "by_rule": dict(sorted(Counter(item["rule"] for item in findings).items())),
    }


def run(workspace: Path, scratch: Path, jobs: int) -> dict:
    environment = scan_environment(workspace, scratch)
    scans = workspace / "scans"
    scans.mkdir(exist_ok=True)

    def scan_one(name: str) -> tuple[str, dict]:
        checkout = prepare_repo(workspace, name, PINS[name])
        print(f"Scanning {name} {PINS[name]['tag']}", flush=True)
        output = scan(checkout, scratch, environment)
        report = scans / f"{name}.json"
        staging = report.with_suffix(".tmp")
        staging.write_text(json.dumps(output, indent=2) + "\n")
        staging.replace(report)
        print(f"Finished {name}: {len(output['diagnostics'])} findings", flush=True)
        summary = {**PINS[name], **summarize(output)}
        if name == "transformers":
            summary["generated_headers"] = generated_file_counts(
                checkout, output, scratch, environment
            )
        return name, summary

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        projects = dict(executor.map(scan_one, PINS))
    return {
        "scanner_commit": SCANNER_COMMIT,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "dependencies": {name: version(name) for name in ("click", "rich", "vulture")},
        "flags": SCAN_FLAGS,
        "pip_audit": False,
        "submodules_initialized": False,
        "projects": projects,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace", type=Path, required=True, help="Checkouts and full local JSON"
    )
    parser.add_argument("--output", type=Path, required=True, help="Aggregate JSON output")
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        result = run(workspace, Path(temp).resolve(), args.jobs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
