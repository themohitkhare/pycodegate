## General Rules

- MUST: Use `uv` for all Python operations. `uv run` to execute, `uv sync` to install.
- MUST: Follow existing code patterns — AST-based rule checks extending `BaseRules`.
- MUST: Keep all types in `src/python_doctor/types.py`.
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

## Adding Rules

1. Create a new file in `src/python_doctor/rules/` extending `BaseRules`
2. Implement `check(self, source: str, filename: str) -> list[Diagnostic]`
3. Register in `src/python_doctor/rules/__init__.py`
4. Add tests in `tests/rules/`

## Testing

Run checks before committing:

```bash
uv run pytest                # runs all tests
uv run py-doctor . -v    # dogfood on ourselves
```

## Architecture

```
src/python_doctor/
  cli.py          — Click CLI entry point
  api.py          — Programmatic API (diagnose function)
  scan.py         — Orchestrator: parallel lint + dead code
  score.py        — Score calculation from diagnostics
  config.py       — Config loading (py-doctor.toml / pyproject.toml)
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
