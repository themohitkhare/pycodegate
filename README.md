# python-doctor

[![PyPI version](https://img.shields.io/pypi/v/python-doctor?style=flat&colorA=000000&colorB=000000)](https://pypi.org/project/python-doctor/)
[![Downloads](https://img.shields.io/pypi/dm/python-doctor?style=flat&colorA=000000&colorB=000000)](https://pypi.org/project/python-doctor/)

Diagnose your Python project's health. One command scans your codebase for security, performance, correctness, and architecture issues, then outputs a **0-100 score** with actionable diagnostics.

Inspired by [react-doctor](https://github.com/millionco/react-doctor).

## How it works

Python Doctor detects your framework (Django, FastAPI, Flask), Python version, package manager (uv, poetry, pip), and test framework, then runs two analysis passes **in parallel**:

1. **Lint**: Checks 30+ rules across security, performance, architecture, correctness, and framework-specific categories. Rules are toggled automatically based on your project setup.
2. **Dead code**: Detects unused functions, classes, imports, and variables via [Vulture](https://github.com/jendrikseipp/vulture).

Diagnostics are filtered through your config, then scored by severity (errors weigh more than warnings) to produce a **0-100 health score** (75+ Great, 50-74 Needs Work, <50 Critical).

## Install

Run instantly with uvx (no install needed):

```bash
uvx python-doctor .
```

Or install globally:

```bash
uv tool install python-doctor
# or
pip install python-doctor
```

Use `--verbose` to see affected files and line numbers:

```bash
python-doctor . --verbose
```

## Install for your coding agent

Add the skill to your Claude Code, Cursor, or other AI coding agent:

```bash
# Claude Code
cp skills/python-doctor/SKILL.md .claude/skills/python-doctor.md
```

Or reference the AGENTS.md in your project root — it's automatically picked up by Claude Code, Cursor, Windsurf, and others.

## GitHub Actions

```yaml
- uses: actions/checkout@v5
  with:
    fetch-depth: 0 # required for --diff
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- name: Run Python Doctor
  run: |
    pip install python-doctor
    python-doctor . --verbose --diff main --fail-on error
```

## Options

```
Usage: python-doctor [OPTIONS] [DIRECTORY]

Options:
  -v, --version                   Show the version and exit.
  --lint / --no-lint              Enable/disable lint checks.
  --dead-code / --no-dead-code    Enable/disable dead code detection.
  --verbose                       Show file details per rule.
  --score                         Output only the numeric score.
  --diff TEXT                     Scan only files changed vs base branch.
  --fail-on [error|warning|none]  Exit with code 1 on this severity level.
  -h, --help                      Show this message and exit.
```

## Configuration

Create a `python-doctor.toml` in your project root:

```toml
[options]
lint = true
dead_code = true
verbose = false
fail_on = "none"

[ignore]
rules = ["no-import-in-function", "dead-code"]
files = ["tests/fixtures/**", "migrations/**"]
```

Or use `pyproject.toml`:

```toml
[tool.python-doctor]
lint = true
dead_code = true

[tool.python-doctor.ignore]
rules = ["no-import-in-function"]
files = ["tests/fixtures/**"]
```

If both exist, `python-doctor.toml` takes precedence. CLI flags always override config values.

## Rules

### Security
| Rule | Severity | Description |
|------|----------|-------------|
| `no-eval` | Error | `eval()` executes arbitrary code |
| `no-exec` | Error | `exec()` executes arbitrary code |
| `no-pickle-load` | Error | `pickle.load()` can execute arbitrary code |
| `no-unsafe-yaml-load` | Error | `yaml.load()` without Loader is unsafe |
| `no-hardcoded-secret` | Error | Hardcoded secrets in source code |
| `no-weak-hash` | Warning | MD5/SHA1 are cryptographically weak |

### Performance
| Rule | Severity | Description |
|------|----------|-------------|
| `no-string-concat-in-loop` | Warning | O(n^2) string concatenation |
| `no-import-in-function` | Warning | Import re-executed on every call |
| `no-star-import` | Warning | Pollutes namespace |

### Architecture
| Rule | Severity | Description |
|------|----------|-------------|
| `no-giant-module` | Warning | Module exceeds 500 lines |
| `no-deep-nesting` | Warning | Nesting depth exceeds 5 |
| `no-god-function` | Warning | Function exceeds 50 lines |
| `no-too-many-args` | Warning | Function has more than 7 arguments |

### Correctness
| Rule | Severity | Description |
|------|----------|-------------|
| `no-mutable-default` | Error | Mutable default argument shared across calls |
| `no-bare-except` | Warning | Catches SystemExit and KeyboardInterrupt |
| `no-broad-except` | Warning | Catches overly broad Exception |
| `no-assert-in-production` | Warning | Assert statements stripped with -O |
| `no-return-in-init` | Warning | Return value in `__init__` |

### Django
| Rule | Severity | Description |
|------|----------|-------------|
| `no-raw-sql-injection` | Error | SQL built with string concatenation |
| `no-debug-true` | Error | DEBUG = True hardcoded in settings |
| `no-secret-key-in-source` | Error | SECRET_KEY hardcoded |
| `no-n-plus-one-query` | Warning | Related object access in loop |

### FastAPI
| Rule | Severity | Description |
|------|----------|-------------|
| `no-sync-endpoint` | Warning | Sync def blocks the event loop |
| `no-missing-response-model` | Warning | Endpoint missing response_model |

### Flask
| Rule | Severity | Description |
|------|----------|-------------|
| `no-flask-secret-in-source` | Error | Secret key hardcoded |
| `no-flask-debug-mode` | Error | Debug mode in production |
| `no-sql-string-format` | Error | SQL built with f-strings |

### Dead Code
| Rule | Severity | Description |
|------|----------|-------------|
| `dead-code` | Warning | Unused function, class, import, or variable |

## Python API

```python
from python_doctor.api import diagnose

result = diagnose("./path/to/your/project")

print(result.score)        # Score(value=82, label="Great")
print(result.diagnostics)  # List of Diagnostic objects
print(result.project)      # Detected framework, Python version, etc.
```

## Contributing

```bash
git clone https://github.com/themohitkhare/pythondoctor
cd pythondoctor
uv sync --all-extras
uv run pytest
uv run python-doctor .  # dogfood it
```

## License

MIT
