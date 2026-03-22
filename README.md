<h1 align="center">Py Gate</h1>
<p align="center">
  <strong>One command. One score. Your Python quality gate.</strong>
</p>
<p align="center">
  <a href="https://github.com/themohitkhare/pycodegate/actions/workflows/ci.yml"><img src="https://github.com/themohitkhare/pycodegate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/py-gate/"><img src="https://img.shields.io/pypi/v/py-gate" alt="PyPI"></a>
  <a href="https://pypi.org/project/py-gate/"><img src="https://img.shields.io/pypi/pyversions/py-gate" alt="Python"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

---

## How it works

Py Gate starts by detecting your project's context: framework (Django, FastAPI, Flask), Python version, package manager (uv, poetry, pip), and test framework. That context drives which rules are active — Django projects get SQL injection checks, FastAPI projects get async-correctness checks, and so on.

It then runs two analysis passes **in parallel**: a lint pass that evaluates 40+ rules across 8 categories (Security, Correctness, Complexity, Architecture, Performance, Structure, Imports, Dead Code), and a dead-code pass powered by [Vulture](https://github.com/jendrikseipp/vulture) that finds unused functions, classes, imports, and variables.

Findings are filtered through your configuration and scored using a **weighted category-budget system**. Each category has a maximum deduction budget proportional to its weight. Within a category the top 3 findings apply at full cost; additional findings apply diminishing returns (10% each), so fixing the worst issues always moves the needle. The final result is a **0–100 health score** with a label: Excellent (90+), Great (75–89), Needs work (50–74), or Critical (<50).

## Install

Run instantly with `uvx` — no install needed:

```bash
uvx py-gate .
```

Install globally with pipx or uv:

```bash
pipx install py-gate
# or
uv tool install py-gate
# or
pip install py-gate
```

## Quick Start

```bash
# Basic scan — score + summary
py-gate .

# Show file paths and line numbers for every finding
py-gate . --verbose

# Machine-readable output for AI agents and CI
py-gate . --json

# Auto-fix ruff-fixable issues, then scan
py-gate . --fix

# Output only the numeric score (useful in scripts)
py-gate . --score

# Scan only files changed vs a base branch
py-gate . --diff main
```

## JSON Output

Pass `--json` to get structured output that AI agents and CI pipelines can parse:

```bash
py-gate . --json
```

```json
{
  "version": "0.1.0",
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

Py Gate is designed to be used by AI coding agents. Add it to your agent's context so it runs after every Python change.

### Claude Code

Add the skill to your project:

```bash
mkdir -p .claude/skills
curl -fsSL https://raw.githubusercontent.com/themohitkhare/pycodegate/main/skills/py-gate/SKILL.md \
  -o .claude/skills/py-gate.md
```

Or copy `AGENTS.md` to your project root — Claude Code picks it up automatically.

### Cursor

Add to `.cursor/rules/py-gate.mdc`:

```markdown
After modifying Python files, run `uvx py-gate . --json` and fix all findings
with severity "error" before marking the task complete. Target score: 80+.
```

### Windsurf

Add to `.windsurfrules`:

```
After modifying Python files, run: uvx py-gate . --json
Fix all "error" severity findings. Re-run to verify the score improved.
```

### Codex

Add to your system prompt:

```
After modifying Python files, run `uvx py-gate . --json` to check code quality.
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
  py-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for --diff

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Run Py Gate
        run: |
          pip install py-gate
          py-gate . --verbose --diff main --fail-on error
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
| `--fix` | off | Run `ruff --fix` before scanning |
| `--diff TEXT` | — | Scan only files changed vs this base branch |
| `--fail-on [error\|warning\|none]` | `none` | Exit code 1 when findings at this level exist |
| `-v, --version` | — | Show version and exit |
| `-h, --help` | — | Show help and exit |

## What It Checks

| Category | Weight | Max Deduction | What it catches |
|----------|--------|---------------|-----------------|
| Security | 5 | ~24 pts | `eval`, `exec`, `pickle.load`, unsafe YAML, hardcoded secrets, weak hashes |
| Correctness | 4 | ~19 pts | Mutable defaults, bare/broad except, assert in production, bad `__init__` return |
| Complexity | 3 | ~14 pts | Cyclomatic complexity > 15 (warning) or > 25 (error) |
| Architecture | 3 | ~14 pts | Giant modules (>500 lines), deep nesting (>5), god functions (>50 lines), too many args (>7) |
| Performance | 2 | ~10 pts | String concat in loops, imports inside functions, star imports |
| Structure | 2 | ~10 pts | Missing `__init__.py`, missing tests directory, no type hints |
| Imports | 1 | ~5 pts | Circular imports, wildcard imports, import order issues |
| Dead Code | 1 | ~5 pts | Unused functions, classes, variables, and imports via Vulture |

Framework-specific rules (Django, FastAPI, Flask) are mapped into the Security or Correctness budget.

## Scoring

Py Gate uses a **weighted category-budget system**:

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

Create `py-gate.toml` in your project root:

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
max-deduction.Security = 20
max-deduction.Dead Code = 0  # disable dead-code penalty entirely
```

Or use `pyproject.toml`:

```toml
[tool.py-gate]
lint = true
dead_code = true
fail_on = "error"

[tool.py-gate.ignore]
rules = ["no-import-in-function"]
files = ["tests/fixtures/**"]

[tool.py-gate.per-file-ignores]
"src/legacy/*.py" = ["high-complexity"]

[tool.py-gate.scoring]
"max-deduction" = { Security = 20, "Dead Code" = 0 }
```

If both files exist, `py-gate.toml` takes precedence. CLI flags always override config values.

## Profiles

Py Gate auto-detects a project profile and adjusts rule weights accordingly. You can also set a profile explicitly in config (`profile = "library"`).

| Profile | Auto-detected when | Adjustments |
|---------|--------------------|-------------|
| `cli` | `[project.scripts]` in pyproject.toml | Architecture rules weighted up; dead-code weighted down |
| `web` | Django / FastAPI / Flask detected | Security and correctness weighted up; framework rules active |
| `library` | No scripts, no framework, has `py.typed` | Public API checks active; dead-code weighted up |
| `script` | Single-file project or `scripts/` directory | Architecture rules relaxed; complexity thresholds raised |

## Pre-commit Hook

Use `--pre-commit` to run Py Gate as a pre-commit hook. It automatically scans only the staged files:

```bash
py-gate . --pre-commit --fail-on error
```

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: py-gate
        name: Py Gate quality check
        entry: py-gate . --pre-commit --fail-on error
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
uv run py-gate . --verbose  # dogfood it
```

To add a new rule:

1. Create a file in `src/python_doctor/rules/` extending `BaseRules`
2. Implement `check(self, source: str, filename: str) -> list[Diagnostic]`
3. Register it in `src/python_doctor/rules/__init__.py`
4. Add tests in `tests/rules/`

## License

MIT
