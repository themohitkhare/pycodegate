<h1 align="center">PyCodeGate</h1>
<p align="center">
  <strong>Trust, but verify. The quality gate for AI-generated Python code.</strong>
</p>
<p align="center">
  <a href="https://github.com/themohitkhare/pycodegate/actions/workflows/ci.yml"><img src="https://github.com/themohitkhare/pycodegate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/pycodegate/"><img src="https://img.shields.io/pypi/v/pycodegate" alt="PyPI"></a>
  <a href="https://pypi.org/project/pycodegate/"><img src="https://img.shields.io/pypi/pyversions/pycodegate" alt="Python"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

---

## Why PyCodeGate?

AI coding agents ship code fast — but fast doesn't mean safe. Every `eval()` an LLM drops in, every mutable default it forgets, every circular import it creates is a landmine waiting to go off. PyCodeGate is the trust layer between AI-generated code and your production codebase: one command, one score, zero ambiguity.

## How it works

PyCodeGate detects your project's context: framework (Django, FastAPI, Flask), Python version, package manager (uv, poetry, pip), and test framework. That context drives which rules are active — Django projects get SQL injection checks, FastAPI projects get async-correctness checks, and so on.

It then runs analysis passes **in parallel**: a lint pass across 9 categories (Security, Correctness, Complexity, Architecture, Performance, Structure, Imports, Dependencies, Dead Code), a dead-code pass powered by [Vulture](https://github.com/jendrikseipp/vulture) that finds unused functions, classes, imports, and variables, and an optional dependency-vulnerability pass via [pip-audit](https://github.com/pypa/pip-audit).

PyCodeGate is **precision-first**: it is meant to stay quiet on idiomatic, correct code so that a finding always means something. Test files only receive rules that make sense for tests (asserts, long fixtures, and long test functions are not flagged), and generated or non-source trees — `migrations`, `examples`, `docs`, and vendored directories — are skipped. The rule set is benchmarked against a corpus of respected PyPI packages (see [`benchmarks/`](benchmarks/)) to keep false positives down.

Findings are filtered through your configuration and scored using a **weighted category-budget system**. Each category has a maximum deduction budget proportional to its weight. Within a category the top 3 findings apply at full cost; additional findings apply diminishing returns (10% each), so fixing the worst issues always moves the needle. The final result is a **0–100 health score** with a label: Excellent (90+), Great (75–89), Needs work (50–74), or Critical (<50).

## Install

Run instantly with `uvx` — no install needed:

```bash
uvx pycodegate .
```

Install globally with pipx or uv:

```bash
pipx install pycodegate
# or
uv tool install pycodegate
# or
pip install pycodegate
```

## Quick Start

```bash
# Basic scan — score + summary
pycodegate .

# Show file paths and line numbers for every finding
pycodegate . --verbose

# Machine-readable output for AI agents and CI
pycodegate . --json

# Auto-fix ruff-fixable issues, then scan
pycodegate . --fix

# Output only the numeric score (useful in scripts)
pycodegate . --score

# Scan only files changed vs a base branch
pycodegate . --diff main
```

## JSON Output

Pass `--json` to get structured output that AI agents and CI pipelines can parse:

```bash
pycodegate . --json
```

```json
{
  "version": "0.3.0",
  "path": ".",
  "score": 87,
  "label": "Great",
  "errors": 1,
  "warnings": 4,
  "elapsed_ms": 212,
  "project": {
    "framework": "fastapi",
    "python_version": "3.12",
    "package_manager": "uv",
    "test_framework": "pytest"
  },
  "diagnostics": [
    {
      "rule": "no-mutable-default",
      "severity": "error",
      "category": "Correctness",
      "message": "Mutable default argument `[]` is shared across all calls",
      "file_path": "src/api/routes.py",
      "line": 34
    },
    {
      "rule": "high-complexity",
      "severity": "warning",
      "category": "Complexity",
      "message": "Function 'process_order' has cyclomatic complexity 17 (max 15)",
      "file_path": "src/api/orders.py",
      "line": 88
    }
  ]
}
```

## Agent Integration

PyCodeGate is designed to be used by AI coding agents. Add it to your agent's context so it runs after every Python change.

### Claude Code

Add the skill to your project:

```bash
mkdir -p .claude/skills
curl -fsSL https://raw.githubusercontent.com/themohitkhare/pycodegate/main/skills/pycodegate/SKILL.md \
  -o .claude/skills/pycodegate.md
```

Or copy `AGENTS.md` to your project root — Claude Code picks it up automatically.

### Cursor

Add to `.cursor/rules/pycodegate.mdc`:

```markdown
After modifying Python files, run `uvx pycodegate . --json` and fix all findings
with severity "error" before marking the task complete. Target score: 80+.
```

### Windsurf

Add to `.windsurfrules`:

```
After modifying Python files, run: uvx pycodegate . --json
Fix all "error" severity findings. Re-run to verify the score improved.
```

### Codex

Add to your system prompt:

```
After modifying Python files, run `uvx pycodegate . --json` to check code quality.
Fix errors first. Target score: 80+.
```

### Aider

```bash
aider --read AGENTS.md
```

## GitHub Actions

```yaml
name: Quality Gate

on: [push, pull_request]

jobs:
  pycodegate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for --diff

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Run PyCodeGate
        run: |
          pip install pycodegate
          pycodegate . --verbose --diff main --fail-on error
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `[DIRECTORY]` | `.` | Path to the Python project to scan |
| `--lint / --no-lint` | on | Enable or disable lint checks |
| `--dead-code / --no-dead-code` | on | Enable or disable dead code detection |
| `--verbose` | off | Show file path and line number per finding |
| `--score` | off | Print only the numeric score and exit |
| `--json` | off | Emit structured JSON (for agents and CI) |
| `--sarif` | off | Emit SARIF 2.1.0 (for GitHub Code Scanning) |
| `--fix` | off | Run `ruff --fix` before scanning |
| `--diff TEXT` | — | Scan only files changed vs this base branch |
| `--fail-on [error\|warning\|none]` | `none` | Exit code 1 when findings at this level exist |
| `--min-score INT` | — | Exit code 1 when the score is below this threshold |
| `--profile [cli\|web\|library\|script]` | auto | Override the auto-detected project profile |
| `--badge` | off | Print a shields.io badge markdown snippet |
| `--ci` | off | Print a ready-to-use GitHub Actions workflow |
| `--pre-commit` | off | Install a git pre-commit hook |
| `-v, --version` | — | Show version and exit |
| `-h, --help` | — | Show help and exit |

## What It Checks

| Category | Weight | What it catches |
|----------|--------|-----------------|
| Security | 5 | `eval`, `exec`, `pickle.load`, unsafe YAML, hardcoded secrets, weak hashes (excluding `usedforsecurity=False`), `os.system`, `shell=True`, `tempfile.mktemp` |
| Correctness | 4 | Mutable defaults, bare except, assert in production, bad `__init__` return |
| Complexity | 3 | Cyclomatic complexity > 15 (warning) or > 25 (error) |
| Architecture | 3 | Giant modules (>500 lines), deep nesting (>5), god functions (>50 lines), too many args (>7) |
| Performance | 2 | String concatenation in loops, star imports |
| Structure | 2 | Missing tests, README, LICENSE, linter/type-checker config, low type coverage |
| Imports | 1 | Circular imports between sibling modules |
| Dependencies | 1 | Known-vulnerable dependencies (via `pip-audit`, when installed) |
| Dead Code | 1 | Unused functions, classes, variables, and imports via Vulture |

Weights are normalized to a 100-point deduction budget. Framework- and library-specific rules (Django, FastAPI, Flask, Pydantic, SQLAlchemy, Celery, requests, logging, pandas, pytest, NumPy) are mapped into the Security or Correctness budget.

## Scoring

PyCodeGate uses a **weighted category-budget system**:

1. Each category has a weight (see table above). Weights are normalized to sum to 100 points of total deduction budget.
2. Within a category, findings are sorted by cost (errors cost more than warnings). The top 3 findings apply at full cost; every additional finding applies **diminishing returns** (10% of its cost).
3. A category's deduction is capped at its budget, so a single broken category can never zero out an otherwise healthy project.
4. Final score = `100 - sum(capped category deductions)`, floored at 0.

| Score | Label | Meaning |
|-------|-------|---------|
| 90–100 | Excellent | Production-ready |
| 75–89 | Great | Minor issues to address |
| 50–74 | Needs work | Significant issues present |
| 0–49 | Critical | Blocking issues, do not ship |

## Configuration

Create `pycodegate.toml` in your project root:

```toml
[options]
lint = true
dead_code = true
verbose = false
fail_on = "none"

[ignore]
rules = ["dead-code", "no-import-in-function"]
files = ["tests/fixtures/**", "migrations/**", "scripts/**"]

[per-file-ignores]
"src/legacy/*.py" = ["high-complexity", "no-god-function"]

[scoring]
max-deduction = { Security = 20, "Dead Code" = 0 }  # 0 disables a category's penalty
```

Or use `pyproject.toml`:

```toml
[tool.pycodegate]
lint = true
dead_code = true
fail_on = "error"

[tool.pycodegate.ignore]
rules = ["no-import-in-function"]
files = ["tests/fixtures/**"]

[tool.pycodegate.per-file-ignores]
"src/legacy/*.py" = ["high-complexity"]

[tool.pycodegate.scoring]
"max-deduction" = { Security = 20, "Dead Code" = 0 }
```

If both files exist, `pycodegate.toml` takes precedence. CLI flags always override config values.

## Profiles

PyCodeGate auto-detects a project profile and adjusts rule weights accordingly. You can also set a profile explicitly in config (`profile = "library"`).

| Profile | Auto-detected when | Adjustments |
|---------|--------------------|-------------|
| `cli` | `[project.scripts]` or a CLI dependency (click, typer, …) | Security budget relaxed; `subprocess`/`shell` rules suppressed |
| `web` | Django / FastAPI / Flask / Starlette / aiohttp / … detected | Framework rules active |
| `library` | Has a `[build-system]` and no scripts | Default budgets |
| `script` | No package `__init__.py` and ≤ 5 top-level `.py` files | Structure budget relaxed; `no-tests`/`no-license` suppressed |

## Pre-commit Hook

`--pre-commit` installs a git `pre-commit` hook (one-time) that scores the project on
every commit and blocks the commit when the score falls below the threshold:

```bash
pycodegate . --pre-commit --min-score 80
```

If you use the [pre-commit framework](https://pre-commit.com), add it to
`.pre-commit-config.yaml` instead:

```yaml
repos:
  - repo: local
    hooks:
      - id: pycodegate
        name: PyCodeGate quality check
        entry: pycodegate . --fail-on error
        language: system
        types: [python]
        pass_filenames: false
```

## Contributing

```bash
git clone https://github.com/themohitkhare/pycodegate
cd pycodegate
uv sync --all-extras
uv run pytest -q
uv run pycodegate . --verbose  # dogfood it
```

To add a new rule:

1. Create a file in `src/pycodegate/rules/` extending `BaseRules`
2. Implement `check(self, source: str, filename: str) -> list[Diagnostic]`
3. Register it in `src/pycodegate/rules/__init__.py`
4. Add tests in `tests/rules/`

## License

MIT
