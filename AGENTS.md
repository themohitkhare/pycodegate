# AGENTS.md

## Overview

PyCodeGate is the quality gate for AI-generated Python code. It produces a 0–100 health score by detecting your framework, running parallel lint and dead-code analysis across 40+ rules, and reporting findings by severity — so you can trust what your AI agent just wrote.

## Quick Start

```bash
uvx pycodegate . --json
```

## For AI Agents

Run `pycodegate . --json` after modifying Python files. Fix findings with severity `"error"` first (security, correctness). Re-run to verify the score improved. Target: **80+**.

The JSON output includes the score, label, per-diagnostic severity and file location, and detected project context (framework, Python version, package manager).

## General Rules

- MUST: Use `uv` for all Python operations. `uv run` to execute, `uv sync` to install.
- MUST: Follow existing code patterns — AST-based rule checks extending `BaseRules`.
- MUST: Keep all types in `src/pycodegate/types.py`.
- MUST: Use dataclasses (frozen) for data containers.
- MUST: Never comment unless absolutely necessary.
  - If the code is a hack, prefix with `# HACK: reason`
- MUST: Use snake_case for files and variables.
- MUST: Use descriptive names (avoid shorthands or 1-2 character names).
- MUST: Do not use `type: ignore` unless absolutely necessary.
- MUST: Remove unused code and don't repeat yourself.
- MUST: Put all magic numbers in `constants.py` using `SCREAMING_SNAKE_CASE`.
- MUST: Put small, focused utility functions in `utils/` with one utility per file.
- MUST: Use early returns and guard clauses to reduce nesting depth below 5.
- MUST: Keep functions under 50 lines.

## Development

```bash
uv run pytest -q                              # run all tests
uv run ruff check . && uv run ruff format --check .  # lint + format check
uv run pycodegate . --verbose                   # dogfood on ourselves
```

## Adding Rules

1. Create a new file in `src/pycodegate/rules/` extending `BaseRules`
2. Implement `check(self, source: str, filename: str) -> list[Diagnostic]`
3. Register in `src/pycodegate/rules/__init__.py`
4. Add tests in `tests/rules/`

## Architecture

```
src/pycodegate/
  cli.py          — Click CLI entry point
  api.py          — Programmatic API (diagnose function)
  scan.py         — Orchestrator: parallel lint + dead code
  score.py        — Score calculation from diagnostics
  config.py       — Config loading (pycodegate.toml / pyproject.toml)
  discover.py     — Project detection (framework, package manager, etc.)
  output.py       — Rich terminal output
  types.py        — All data types (Diagnostic, Score, etc.)
  constants.py    — Magic numbers and thresholds
  rules/
    base.py       — Abstract BaseRules with AST parsing
    security.py   — eval, exec, pickle, yaml, secrets, hashes
    performance.py — string concat, imports in functions, star imports
    architecture.py — giant modules, nesting, god functions, too many args
    correctness.py — mutable defaults, bare except, assert, return in init
    django.py     — raw SQL, DEBUG, SECRET_KEY, N+1
    fastapi.py    — sync endpoints, missing response_model
    flask.py      — secret key, debug mode, SQL f-strings
    dead_code.py  — Vulture integration
  utils/
    file_discovery.py — Python file discovery (git + fallback)
    ast_helpers.py    — Common AST utilities
    diff.py           — Git diff file resolution
```
