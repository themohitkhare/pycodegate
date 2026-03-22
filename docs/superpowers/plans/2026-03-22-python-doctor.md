# Python Doctor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a CLI diagnostic tool for Python projects that scans for security, performance, architecture, and framework-specific issues, producing a 0-100 health score with actionable diagnostics — a Python equivalent of react-doctor.

**Architecture:** AST-based analysis engine with pluggable rule categories. Two parallel analysis passes: lint checks (custom AST rules + ruff integration) and dead code detection (via vulture). Framework auto-detection (Django, FastAPI, Flask) enables framework-specific rule sets. Rich terminal output with score visualization.

**Tech Stack:** Python 3.10+, Click (CLI), Rich (terminal UI), ast module (analysis), vulture (dead code), ruff (baseline lint integration), pytest (testing), uv (package management)

---

## File Structure

```
python_doctor/
├── pyproject.toml                    # Project config, dependencies, entry point
├── src/
│   └── python_doctor/
│       ├── __init__.py               # Package init, version
│       ├── cli.py                    # Click CLI entry point, flags, output formatting
│       ├── api.py                    # Programmatic API: diagnose()
│       ├── scan.py                   # Orchestrates parallel lint + dead code passes
│       ├── types.py                  # Dataclasses: Diagnostic, ProjectInfo, ScanResult, Score
│       ├── constants.py              # Thresholds, score labels, penalties
│       ├── config.py                 # Load python-doctor.toml or pyproject.toml [tool.python-doctor]
│       ├── discover.py               # Auto-detect framework, Python version, package manager, test framework
│       ├── score.py                  # Calculate 0-100 score from diagnostics
│       ├── output.py                 # Rich-based terminal output: score bar, doctor face, framed summary
│       ├── rules/
│       │   ├── __init__.py           # Rule registry, category enum
│       │   ├── base.py              # Base Rule class + AST visitor mixin
│       │   ├── security.py          # eval/exec, pickle, yaml, secrets, SQL injection
│       │   ├── performance.py       # Global imports in functions, string concat in loops, star imports
│       │   ├── architecture.py      # Giant modules, god classes, circular imports, deep nesting
│       │   ├── correctness.py       # Mutable default args, bare except, broad exception, assert in prod, return in init
│       │   ├── django.py            # N+1, missing select_related, raw SQL, debug=True, missing migrations check
│       │   ├── fastapi.py           # Sync endpoints, missing response_model, untyped deps
│       │   ├── flask.py             # Secret key in source, debug mode, SQL injection via string format
│       │   └── dead_code.py         # Vulture integration wrapper
│       └── utils/
│           ├── __init__.py
│           ├── ast_helpers.py       # Common AST traversal utilities
│           ├── file_discovery.py    # Find Python files, respect gitignore
│           └── diff.py              # Git diff mode: only scan changed files
├── tests/
│   ├── conftest.py                  # Shared fixtures
│   ├── test_types.py                # Dataclass construction and validation
│   ├── test_score.py                # Score calculation
│   ├── test_config.py               # Config loading
│   ├── test_discover.py             # Framework detection
│   ├── test_output.py               # Output formatting
│   ├── test_scan.py                 # Scan orchestration
│   ├── test_cli.py                  # CLI integration tests
│   ├── rules/
│   │   ├── test_security.py
│   │   ├── test_performance.py
│   │   ├── test_architecture.py
│   │   ├── test_correctness.py
│   │   ├── test_django.py
│   │   ├── test_fastapi.py
│   │   ├── test_flask.py
│   │   └── test_dead_code.py
│   └── fixtures/
│       ├── clean_project/           # No issues baseline
│       ├── basic_python/            # Various issue types
│       └── (framework fixtures use inline source in tests)
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/python_doctor/__init__.py`
- Create: `src/python_doctor/types.py`
- Create: `tests/conftest.py`
- Create: `tests/test_types.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "python-doctor"
version = "0.1.0"
description = "Diagnose your Python project's health. Get a score, find issues, fix them."
readme = "README.md"
requires-python = ">=3.10"
license = "MIT"
authors = [{ name = "Mohit Khare" }]
dependencies = [
    "click>=8.1",
    "rich>=13.0",
    "vulture>=2.11",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "ruff>=0.4",
]

[project.scripts]
python-doctor = "python_doctor.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/python_doctor"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "UP", "B", "SIM", "TCH"]
```

- [ ] **Step 2: Create `src/python_doctor/__init__.py`**

```python
"""Python Doctor - Diagnose your Python project's health."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Write failing test for types**

Create `tests/test_types.py`:

```python
from python_doctor.types import Diagnostic, ProjectInfo, ScanResult, Score, Severity, Category


def test_diagnostic_creation():
    d = Diagnostic(
        file_path="app.py",
        rule="no-eval",
        severity=Severity.ERROR,
        category=Category.SECURITY,
        message="Avoid eval() with user input",
        help="Use ast.literal_eval() instead",
        line=10,
        column=4,
    )
    assert d.file_path == "app.py"
    assert d.severity == Severity.ERROR
    assert d.category == Category.SECURITY


def test_project_info_creation():
    p = ProjectInfo(
        path="/tmp/myproject",
        python_version="3.12",
        framework="django",
        package_manager="uv",
        test_framework="pytest",
        has_type_hints=True,
        source_file_count=42,
    )
    assert p.framework == "django"
    assert p.source_file_count == 42


def test_score_creation():
    s = Score(value=82, label="Great")
    assert s.value == 82
    assert s.label == "Great"


def test_scan_result_creation():
    result = ScanResult(
        score=Score(value=75, label="Great"),
        diagnostics=[],
        project=ProjectInfo(
            path="/tmp/p",
            python_version="3.11",
            framework=None,
            package_manager="pip",
            test_framework=None,
            has_type_hints=False,
            source_file_count=5,
        ),
        elapsed_ms=1200,
    )
    assert result.score.value == 75
    assert result.diagnostics == []
```

- [ ] **Step 4: Create conftest.py**

Create `tests/conftest.py`:

```python
"""Shared test fixtures for python-doctor."""
```

- [ ] **Step 5: Run test to verify it fails**

Run: `cd /Users/mkhare/Development/pythondoctor/.claude/worktrees/objective-meninsky && uv run pytest tests/test_types.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'python_doctor.types'`

- [ ] **Step 6: Create `src/python_doctor/types.py`**

```python
"""Core data types for python-doctor diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class Category(str, Enum):
    SECURITY = "Security"
    PERFORMANCE = "Performance"
    ARCHITECTURE = "Architecture"
    CORRECTNESS = "Correctness"
    DEAD_CODE = "Dead Code"
    DJANGO = "Django"
    FASTAPI = "FastAPI"
    FLASK = "Flask"


@dataclass(frozen=True)
class Diagnostic:
    file_path: str
    rule: str
    severity: Severity
    category: Category
    message: str
    help: str
    line: int
    column: int = 0


@dataclass(frozen=True)
class ProjectInfo:
    path: str
    python_version: str | None
    framework: str | None
    package_manager: str | None
    test_framework: str | None
    has_type_hints: bool
    source_file_count: int


@dataclass(frozen=True)
class Score:
    value: int
    label: str


@dataclass(frozen=True)
class ScanResult:
    score: Score
    diagnostics: list[Diagnostic]
    project: ProjectInfo
    elapsed_ms: int
```

- [ ] **Step 7: Run tests**

Run: `cd /Users/mkhare/Development/pythondoctor/.claude/worktrees/objective-meninsky && uv run pytest tests/test_types.py -v`
Expected: 4 PASSED

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml src/ tests/
git commit -m "feat: project scaffolding with core types"
```

---

### Task 2: Score Calculation

**Files:**
- Create: `src/python_doctor/constants.py`
- Create: `src/python_doctor/score.py`
- Create: `tests/test_score.py`

- [ ] **Step 1: Write failing test for score calculation**

Create `tests/test_score.py`:

```python
from python_doctor.score import calculate_score
from python_doctor.types import Diagnostic, Severity, Category


def _make_diag(rule: str, severity: Severity = Severity.ERROR) -> Diagnostic:
    return Diagnostic(
        file_path="app.py",
        rule=rule,
        severity=severity,
        category=Category.SECURITY,
        message="test",
        help="test",
        line=1,
    )


def test_perfect_score_no_diagnostics():
    score = calculate_score([])
    assert score.value == 100
    assert score.label == "Great"


def test_errors_reduce_score():
    diags = [_make_diag("rule-a"), _make_diag("rule-b")]
    score = calculate_score(diags)
    # 100 - 2 * 1.5 = 97
    assert score.value == 97


def test_warnings_reduce_score_less():
    diags = [_make_diag("rule-a", Severity.WARNING), _make_diag("rule-b", Severity.WARNING)]
    score = calculate_score(diags)
    # 100 - 2 * 0.75 = 98 (rounded)
    assert score.value == 98


def test_duplicate_rules_counted_once():
    diags = [_make_diag("rule-a"), _make_diag("rule-a"), _make_diag("rule-a")]
    score = calculate_score(diags)
    # 100 - 1 * 1.5 = 98 (rounded)
    assert score.value == 98


def test_score_floors_at_zero():
    diags = [_make_diag(f"rule-{i}") for i in range(100)]
    score = calculate_score(diags)
    assert score.value == 0
    assert score.label == "Critical"


def test_label_thresholds():
    assert calculate_score([]).label == "Great"
    # 50 unique error rules: 100 - 50*1.5 = 25
    diags_25 = [_make_diag(f"r-{i}") for i in range(50)]
    assert calculate_score(diags_25).label == "Critical"
    # 20 unique error rules: 100 - 20*1.5 = 70
    diags_70 = [_make_diag(f"r-{i}") for i in range(20)]
    assert calculate_score(diags_70).label == "Needs work"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_score.py -v`
Expected: FAIL

- [ ] **Step 3: Create constants.py**

```python
"""Constants and thresholds for python-doctor."""

# Score penalties per unique rule
ERROR_PENALTY = 1.5
WARNING_PENALTY = 0.75

# Score thresholds
SCORE_GREAT = 75
SCORE_NEEDS_WORK = 50

# Labels
LABEL_GREAT = "Great"
LABEL_NEEDS_WORK = "Needs work"
LABEL_CRITICAL = "Critical"
```

- [ ] **Step 4: Create score.py**

```python
"""Score calculation from diagnostics."""

from __future__ import annotations

from python_doctor.constants import (
    ERROR_PENALTY,
    LABEL_CRITICAL,
    LABEL_GREAT,
    LABEL_NEEDS_WORK,
    SCORE_GREAT,
    SCORE_NEEDS_WORK,
    WARNING_PENALTY,
)
from python_doctor.types import Diagnostic, Score, Severity


def calculate_score(diagnostics: list[Diagnostic]) -> Score:
    """Calculate a 0-100 health score from diagnostics.

    Only unique rules count — multiple violations of the same rule
    incur a single penalty.
    """
    error_rules: set[str] = set()
    warning_rules: set[str] = set()

    for d in diagnostics:
        if d.severity == Severity.ERROR:
            error_rules.add(d.rule)
        else:
            warning_rules.add(d.rule)

    penalty = len(error_rules) * ERROR_PENALTY + len(warning_rules) * WARNING_PENALTY
    value = max(0, round(100 - penalty))

    if value >= SCORE_GREAT:
        label = LABEL_GREAT
    elif value >= SCORE_NEEDS_WORK:
        label = LABEL_NEEDS_WORK
    else:
        label = LABEL_CRITICAL

    return Score(value=value, label=label)
```

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_score.py -v`
Expected: All PASSED

- [ ] **Step 6: Commit**

```bash
git add src/python_doctor/constants.py src/python_doctor/score.py tests/test_score.py
git commit -m "feat: score calculation with penalty system"
```

---

### Task 3: Configuration Loading

**Files:**
- Create: `src/python_doctor/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing test**

Create `tests/test_config.py`:

```python
from pathlib import Path

from python_doctor.config import load_config, Config


def test_default_config_when_no_file(tmp_path):
    cfg = load_config(str(tmp_path))
    assert cfg.lint is True
    assert cfg.dead_code is True
    assert cfg.verbose is False
    assert cfg.ignore_rules == []
    assert cfg.ignore_files == []


def test_load_from_python_doctor_toml(tmp_path):
    toml_content = """
[ignore]
rules = ["no-eval", "no-exec"]
files = ["migrations/*"]

[options]
lint = true
dead_code = false
verbose = true
fail_on = "error"
"""
    (tmp_path / "python-doctor.toml").write_text(toml_content)
    cfg = load_config(str(tmp_path))
    assert cfg.dead_code is False
    assert cfg.verbose is True
    assert cfg.ignore_rules == ["no-eval", "no-exec"]
    assert cfg.ignore_files == ["migrations/*"]
    assert cfg.fail_on == "error"


def test_load_from_pyproject_toml(tmp_path):
    toml_content = """
[tool.python-doctor]
lint = true
dead_code = true
verbose = false
fail_on = "none"

[tool.python-doctor.ignore]
rules = ["no-pickle"]
files = []
"""
    (tmp_path / "pyproject.toml").write_text(toml_content)
    cfg = load_config(str(tmp_path))
    assert cfg.ignore_rules == ["no-pickle"]
    assert cfg.fail_on == "none"


def test_python_doctor_toml_takes_precedence(tmp_path):
    (tmp_path / "python-doctor.toml").write_text("""
[options]
verbose = true
""")
    (tmp_path / "pyproject.toml").write_text("""
[tool.python-doctor]
verbose = false
""")
    cfg = load_config(str(tmp_path))
    assert cfg.verbose is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL

- [ ] **Step 3: Create config.py**

```python
"""Configuration loading for python-doctor."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    lint: bool = True
    dead_code: bool = True
    verbose: bool = False
    fail_on: str = "none"
    ignore_rules: list[str] = field(default_factory=list)
    ignore_files: list[str] = field(default_factory=list)


def load_config(project_path: str) -> Config:
    """Load config from python-doctor.toml or pyproject.toml [tool.python-doctor]."""
    root = Path(project_path)

    # python-doctor.toml takes precedence
    doctor_toml = root / "python-doctor.toml"
    if doctor_toml.exists():
        return _parse_doctor_toml(doctor_toml)

    # Fall back to pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        return _parse_pyproject_toml(pyproject)

    return Config()


def _parse_doctor_toml(path: Path) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    options = data.get("options", {})
    ignore = data.get("ignore", {})

    return Config(
        lint=options.get("lint", True),
        dead_code=options.get("dead_code", True),
        verbose=options.get("verbose", False),
        fail_on=options.get("fail_on", "none"),
        ignore_rules=ignore.get("rules", []),
        ignore_files=ignore.get("files", []),
    )


def _parse_pyproject_toml(path: Path) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    section = data.get("tool", {}).get("python-doctor", {})
    if not section:
        return Config()

    ignore = section.get("ignore", {})

    return Config(
        lint=section.get("lint", True),
        dead_code=section.get("dead_code", True),
        verbose=section.get("verbose", False),
        fail_on=section.get("fail_on", "none"),
        ignore_rules=ignore.get("rules", []),
        ignore_files=ignore.get("files", []),
    )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_config.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/config.py tests/test_config.py
git commit -m "feat: config loading from python-doctor.toml and pyproject.toml"
```

---

### Task 4: Project Discovery

**Files:**
- Create: `src/python_doctor/discover.py`
- Create: `src/python_doctor/utils/__init__.py`
- Create: `src/python_doctor/utils/file_discovery.py`
- Create: `tests/test_discover.py`
- Create: test fixtures

- [ ] **Step 1: Write failing tests**

Create `tests/test_discover.py`:

```python
from pathlib import Path
from python_doctor.discover import discover_project
from python_doctor.types import ProjectInfo


def _write_pyproject(tmp_path: Path, content: str):
    (tmp_path / "pyproject.toml").write_text(content)


def _write_requirements(tmp_path: Path, content: str):
    (tmp_path / "requirements.txt").write_text(content)


def test_detect_django_from_pyproject(tmp_path):
    _write_pyproject(tmp_path, """
[project]
dependencies = ["django>=4.2"]
""")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.framework == "django"


def test_detect_fastapi_from_requirements(tmp_path):
    _write_requirements(tmp_path, "fastapi>=0.100\nuvicorn\n")
    (tmp_path / "main.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.framework == "fastapi"


def test_detect_flask_from_pyproject(tmp_path):
    _write_pyproject(tmp_path, """
[project]
dependencies = ["flask>=3.0"]
""")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.framework == "flask"


def test_detect_no_framework(tmp_path):
    (tmp_path / "script.py").write_text("print('hello')")
    info = discover_project(str(tmp_path))
    assert info.framework is None


def test_detect_uv_package_manager(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.package_manager == "uv"


def test_detect_poetry_package_manager(tmp_path):
    (tmp_path / "poetry.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.package_manager == "poetry"


def test_detect_pytest(tmp_path):
    _write_pyproject(tmp_path, """
[project]
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0"]
""")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.test_framework == "pytest"


def test_source_file_count(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.py").write_text("x = 2")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "c.py").write_text("x = 3")
    info = discover_project(str(tmp_path))
    assert info.source_file_count == 3


def test_ignores_venv_and_node_modules(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "site.py").write_text("x = 1")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.source_file_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_discover.py -v`
Expected: FAIL

- [ ] **Step 3: Create utils/file_discovery.py**

```python
"""File discovery utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path

IGNORE_DIRS = {
    ".venv", "venv", "env", ".env", "node_modules", "__pycache__",
    ".git", ".hg", ".svn", "dist", "build", ".eggs", "*.egg-info",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "htmlcov", "site-packages",
}


def find_python_files(project_path: str) -> list[Path]:
    """Find all Python files in the project, respecting gitignore."""
    root = Path(project_path)

    # Try git ls-files first
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [root / f for f in result.stdout.strip().splitlines() if f.endswith(".py")]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Fallback: walk filesystem
    return _walk_for_python_files(root)


def _walk_for_python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if not any(part in IGNORE_DIRS or part.endswith(".egg-info") for part in path.relative_to(root).parts):
            files.append(path)
    return files
```

- [ ] **Step 4: Create utils/__init__.py**

```python
"""Utility modules for python-doctor."""
```

- [ ] **Step 5: Create discover.py**

```python
"""Project discovery: detect framework, Python version, package manager, etc."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from python_doctor.types import ProjectInfo
from python_doctor.utils.file_discovery import find_python_files


def discover_project(project_path: str) -> ProjectInfo:
    """Auto-detect project characteristics."""
    root = Path(project_path)
    deps = _collect_all_deps(root)

    return ProjectInfo(
        path=project_path,
        python_version=_detect_python_version(root),
        framework=_detect_framework(deps),
        package_manager=_detect_package_manager(root),
        test_framework=_detect_test_framework(deps),
        has_type_hints=_detect_type_hints(root),
        source_file_count=len(find_python_files(project_path)),
    )


def _collect_all_deps(root: Path) -> set[str]:
    """Collect dependency names from all sources."""
    deps: set[str] = set()

    # pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        project = data.get("project", {})
        for dep in project.get("dependencies", []):
            deps.add(_parse_dep_name(dep))
        for group_deps in project.get("optional-dependencies", {}).values():
            for dep in group_deps:
                deps.add(_parse_dep_name(dep))
        # Poetry format
        poetry = data.get("tool", {}).get("poetry", {})
        for dep in poetry.get("dependencies", {}):
            deps.add(dep.lower())
        for group in poetry.get("group", {}).values():
            for dep in group.get("dependencies", {}):
                deps.add(dep.lower())

    # requirements.txt
    for req_file in ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"]:
        req_path = root / req_file
        if req_path.exists():
            for line in req_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "-")):
                    deps.add(_parse_dep_name(line))

    return deps


def _parse_dep_name(dep_str: str) -> str:
    """Extract package name from a dependency specifier like 'django>=4.2'."""
    return re.split(r"[><=!~\[;@\s]", dep_str)[0].strip().lower()


def _detect_framework(deps: set[str]) -> str | None:
    # Order matters: check more specific first
    if "django" in deps or "django-rest-framework" in deps or "djangorestframework" in deps:
        return "django"
    if "fastapi" in deps:
        return "fastapi"
    if "flask" in deps:
        return "flask"
    return None


def _detect_package_manager(root: Path) -> str | None:
    if (root / "uv.lock").exists():
        return "uv"
    if (root / "poetry.lock").exists():
        return "poetry"
    if (root / "Pipfile.lock").exists():
        return "pipenv"
    if (root / "requirements.txt").exists():
        return "pip"
    if (root / "pyproject.toml").exists():
        return "pip"
    return None


def _detect_test_framework(deps: set[str]) -> str | None:
    if "pytest" in deps:
        return "pytest"
    if "unittest" in deps:
        return "unittest"
    return None


def _detect_python_version(root: Path) -> str | None:
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        requires = data.get("project", {}).get("requires-python", "")
        match = re.search(r"(\d+\.\d+)", requires)
        if match:
            return match.group(1)
    return None


def _detect_type_hints(root: Path) -> bool:
    return (root / "py.typed").exists() or (root / "mypy.ini").exists()
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/test_discover.py -v`
Expected: All PASSED

- [ ] **Step 7: Commit**

```bash
git add src/python_doctor/utils/ src/python_doctor/discover.py tests/test_discover.py
git commit -m "feat: project discovery with framework/package manager detection"
```

---

### Task 5: Rule Engine Base + Security Rules

**Files:**
- Create: `src/python_doctor/rules/__init__.py`
- Create: `src/python_doctor/rules/base.py`
- Create: `src/python_doctor/rules/security.py`
- Create: `tests/rules/test_security.py`

- [ ] **Step 1: Write failing tests for security rules**

Create `tests/rules/__init__.py`:

```python
```

Create `tests/rules/test_security.py`:

```python
import textwrap
from python_doctor.rules.security import SecurityRules
from python_doctor.types import Severity, Category


def _run(source: str, filename: str = "app.py") -> list:
    return SecurityRules().check(source, filename)


def test_no_eval_detected():
    diags = _run("result = eval(user_input)")
    assert len(diags) == 1
    assert diags[0].rule == "no-eval"
    assert diags[0].severity == Severity.ERROR


def test_no_exec_detected():
    diags = _run("exec(code_string)")
    assert len(diags) == 1
    assert diags[0].rule == "no-exec"


def test_no_pickle_load():
    diags = _run("import pickle\ndata = pickle.load(f)")
    assert any(d.rule == "no-pickle-load" for d in diags)


def test_no_yaml_unsafe_load():
    diags = _run("import yaml\ndata = yaml.load(f)")
    assert any(d.rule == "no-unsafe-yaml-load" for d in diags)


def test_yaml_safe_load_is_ok():
    diags = _run("import yaml\ndata = yaml.safe_load(f)")
    assert not any(d.rule == "no-unsafe-yaml-load" for d in diags)


def test_no_hardcoded_secrets():
    diags = _run('API_KEY = "sk-1234567890abcdef1234567890abcdef"')
    assert any(d.rule == "no-hardcoded-secret" for d in diags)


def test_no_hardcoded_password():
    diags = _run('PASSWORD = "hunter2"')
    assert any(d.rule == "no-hardcoded-secret" for d in diags)


def test_no_md5_usage():
    diags = _run("import hashlib\nhashlib.md5(data)")
    assert any(d.rule == "no-weak-hash" for d in diags)


def test_no_sha1_usage():
    diags = _run("import hashlib\nhashlib.sha1(data)")
    assert any(d.rule == "no-weak-hash" for d in diags)


def test_clean_code_no_issues():
    diags = _run("def greet(name: str) -> str:\n    return f'Hello, {name}'")
    assert diags == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_security.py -v`
Expected: FAIL

- [ ] **Step 3: Create rules/__init__.py**

```python
"""Rule registry for python-doctor."""

from __future__ import annotations

from python_doctor.rules.base import BaseRules


def get_all_rule_sets() -> list[BaseRules]:
    """Return all available rule sets."""
    from python_doctor.rules.security import SecurityRules
    from python_doctor.rules.performance import PerformanceRules
    from python_doctor.rules.architecture import ArchitectureRules
    from python_doctor.rules.correctness import CorrectnessRules

    return [SecurityRules(), PerformanceRules(), ArchitectureRules(), CorrectnessRules()]


def get_framework_rules(framework: str | None) -> list[BaseRules]:
    """Return framework-specific rule sets."""
    if framework == "django":
        from python_doctor.rules.django import DjangoRules
        return [DjangoRules()]
    if framework == "fastapi":
        from python_doctor.rules.fastapi import FastAPIRules
        return [FastAPIRules()]
    if framework == "flask":
        from python_doctor.rules.flask import FlaskRules
        return [FlaskRules()]
    return []
```

- [ ] **Step 4: Create rules/base.py**

```python
"""Base class for rule sets."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod

from python_doctor.types import Diagnostic


class BaseRules(ABC):
    """Base class that all rule sets inherit from."""

    @abstractmethod
    def check(self, source: str, filename: str) -> list[Diagnostic]:
        """Analyze source code and return diagnostics."""

    def _parse(self, source: str) -> ast.Module | None:
        """Safely parse Python source into AST."""
        try:
            return ast.parse(source)
        except SyntaxError:
            return None
```

- [ ] **Step 5: Create rules/security.py**

```python
"""Security rules: eval, exec, pickle, yaml, secrets, weak hashes."""

from __future__ import annotations

import ast
import re

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

# Patterns that suggest a hardcoded secret
_SECRET_VAR_PATTERNS = re.compile(
    r"(api_key|apikey|secret|password|passwd|token|auth_token|private_key|"
    r"access_key|secret_key|credentials)",
    re.IGNORECASE,
)

# Patterns that look like actual secret values (not empty/placeholder)
_SECRET_VALUE_MIN_LENGTH = 8


class SecurityRules(BaseRules):
    """Security-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_eval_exec(tree, filename))
        diags.extend(self._check_pickle(tree, filename))
        diags.extend(self._check_yaml(tree, filename))
        diags.extend(self._check_hardcoded_secrets(tree, filename))
        diags.extend(self._check_weak_hash(tree, filename))
        return diags

    def _check_eval_exec(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "eval":
                    diags.append(Diagnostic(
                        file_path=filename,
                        rule="no-eval",
                        severity=Severity.ERROR,
                        category=Category.SECURITY,
                        message="Avoid eval() — it executes arbitrary code",
                        help="Use ast.literal_eval() for safe parsing of literals",
                        line=node.lineno,
                        column=node.col_offset,
                    ))
                elif node.func.id == "exec":
                    diags.append(Diagnostic(
                        file_path=filename,
                        rule="no-exec",
                        severity=Severity.ERROR,
                        category=Category.SECURITY,
                        message="Avoid exec() — it executes arbitrary code",
                        help="Refactor to avoid dynamic code execution",
                        line=node.lineno,
                        column=node.col_offset,
                    ))
        return diags

    def _check_pickle(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("load", "loads") and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "pickle":
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-pickle-load",
                            severity=Severity.ERROR,
                            category=Category.SECURITY,
                            message="pickle.load() can execute arbitrary code on untrusted data",
                            help="Use JSON or a safe serialization format for untrusted data",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags

    def _check_yaml(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr == "load"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "yaml"
                ):
                    # Check if Loader kwarg is provided (safe_load equivalent)
                    has_loader = any(
                        kw.arg == "Loader" for kw in node.keywords
                    )
                    if not has_loader:
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-unsafe-yaml-load",
                            severity=Severity.ERROR,
                            category=Category.SECURITY,
                            message="yaml.load() without Loader is unsafe — can execute arbitrary code",
                            help="Use yaml.safe_load() or pass Loader=yaml.SafeLoader",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags

    def _check_hardcoded_secrets(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                        if (
                            isinstance(node.value.value, str)
                            and _SECRET_VAR_PATTERNS.search(target.id)
                            and len(node.value.value) >= _SECRET_VALUE_MIN_LENGTH
                        ):
                            diags.append(Diagnostic(
                                file_path=filename,
                                rule="no-hardcoded-secret",
                                severity=Severity.ERROR,
                                category=Category.SECURITY,
                                message=f"Hardcoded secret in '{target.id}' — use environment variables",
                                help="Use os.environ or a .env file via python-dotenv",
                                line=node.lineno,
                                column=node.col_offset,
                            ))
        return diags

    def _check_weak_hash(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr in ("md5", "sha1")
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "hashlib"
                ):
                    diags.append(Diagnostic(
                        file_path=filename,
                        rule="no-weak-hash",
                        severity=Severity.WARNING,
                        category=Category.SECURITY,
                        message=f"hashlib.{node.func.attr}() is cryptographically weak",
                        help="Use hashlib.sha256() or hashlib.sha3_256() instead",
                        line=node.lineno,
                        column=node.col_offset,
                    ))
        return diags
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/rules/test_security.py -v`
Expected: All PASSED

- [ ] **Step 7: Commit**

```bash
git add src/python_doctor/rules/ tests/rules/
git commit -m "feat: rule engine base + security rules (eval, exec, pickle, yaml, secrets, hashes)"
```

---

### Task 6: Performance Rules

**Files:**
- Create: `src/python_doctor/rules/performance.py`
- Create: `tests/rules/test_performance.py`

- [ ] **Step 1: Write failing tests**

Create `tests/rules/test_performance.py`:

```python
from python_doctor.rules.performance import PerformanceRules
from python_doctor.types import Severity


def _run(source: str) -> list:
    return PerformanceRules().check(source, "app.py")


def test_string_concat_in_loop():
    source = """
result = ""
for item in items:
    result += str(item)
"""
    diags = _run(source)
    assert any(d.rule == "no-string-concat-in-loop" for d in diags)


def test_global_import_in_function():
    source = """
def process():
    import json
    return json.dumps({})
"""
    diags = _run(source)
    assert any(d.rule == "no-import-in-function" for d in diags)


def test_top_level_import_is_ok():
    diags = _run("import json\njson.dumps({})")
    assert not any(d.rule == "no-import-in-function" for d in diags)


def test_star_import():
    diags = _run("from os.path import *")
    assert any(d.rule == "no-star-import" for d in diags)


def test_clean_code():
    source = """
import json

def process(items: list) -> str:
    parts = [str(item) for item in items]
    return json.dumps(parts)
"""
    diags = _run(source)
    assert diags == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_performance.py -v`
Expected: FAIL

- [ ] **Step 3: Create performance.py**

```python
"""Performance rules: string concat in loops, imports in functions, star imports."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity


class PerformanceRules(BaseRules):
    """Performance-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_string_concat_in_loop(tree, filename))
        diags.extend(self._check_import_in_function(tree, filename))
        diags.extend(self._check_star_imports(tree, filename))
        return diags

    def _check_string_concat_in_loop(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        # Collect variable names initialized to string literals
        string_vars = self._find_string_vars(tree)

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    if (
                        isinstance(child, ast.AugAssign)
                        and isinstance(child.op, ast.Add)
                        and isinstance(child.target, ast.Name)
                        and child.target.id in string_vars
                    ):
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-string-concat-in-loop",
                            severity=Severity.WARNING,
                            category=Category.PERFORMANCE,
                            message="String concatenation in a loop — O(n^2) memory",
                            help="Collect items in a list and use ''.join() at the end",
                            line=child.lineno,
                            column=child.col_offset,
                        ))
        return diags

    @staticmethod
    def _find_string_vars(tree: ast.Module) -> set[str]:
        """Find variable names assigned to string literals (e.g., x = '' or x = "hi")."""
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            names.add(target.id)
        return names

    def _check_import_in_function(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-import-in-function",
                            severity=Severity.WARNING,
                            category=Category.PERFORMANCE,
                            message="Import inside function body — re-imported on every call",
                            help="Move imports to the top of the module",
                            line=child.lineno,
                            column=child.col_offset,
                        ))
        return diags

    def _check_star_imports(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ):
                diags.append(Diagnostic(
                    file_path=filename,
                    rule="no-star-import",
                    severity=Severity.WARNING,
                    category=Category.PERFORMANCE,
                    message=f"Star import from {node.module} pollutes namespace and hides dependencies",
                    help="Import specific names instead",
                    line=node.lineno,
                    column=node.col_offset,
                ))
        return diags
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/rules/test_performance.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/rules/performance.py tests/rules/test_performance.py
git commit -m "feat: performance rules (mutable defaults, string concat, imports, star imports)"
```

---

### Task 7: Architecture Rules

**Files:**
- Create: `src/python_doctor/rules/architecture.py`
- Create: `tests/rules/test_architecture.py`

- [ ] **Step 1: Write failing tests**

Create `tests/rules/test_architecture.py`:

```python
from python_doctor.rules.architecture import ArchitectureRules


def _run(source: str) -> list:
    return ArchitectureRules().check(source, "app.py")


def test_giant_module():
    source = "\n".join([f"x_{i} = {i}" for i in range(501)])
    diags = _run(source)
    assert any(d.rule == "no-giant-module" for d in diags)


def test_small_module_ok():
    source = "\n".join([f"x_{i} = {i}" for i in range(50)])
    diags = _run(source)
    assert not any(d.rule == "no-giant-module" for d in diags)


def test_deep_nesting():
    source = """
def foo():
    if True:
        for x in range(10):
            if x > 5:
                while True:
                    if x > 7:
                        pass
"""
    diags = _run(source)
    assert any(d.rule == "no-deep-nesting" for d in diags)


def test_god_function():
    # Function with 51+ lines
    lines = ["def huge_function():"]
    for i in range(55):
        lines.append(f"    x_{i} = {i}")
    source = "\n".join(lines)
    diags = _run(source)
    assert any(d.rule == "no-god-function" for d in diags)


def test_too_many_args():
    source = "def foo(a, b, c, d, e, f, g, h):\n    pass"
    diags = _run(source)
    assert any(d.rule == "too-many-arguments" for d in diags)


def test_reasonable_args_ok():
    source = "def foo(a, b, c):\n    pass"
    diags = _run(source)
    assert not any(d.rule == "too-many-arguments" for d in diags)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_architecture.py -v`
Expected: FAIL

- [ ] **Step 3: Create architecture.py**

```python
"""Architecture rules: giant modules, deep nesting, god functions, too many args."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

MAX_MODULE_LINES = 500
MAX_FUNCTION_LINES = 50
MAX_NESTING_DEPTH = 5
MAX_ARGUMENTS = 7


class ArchitectureRules(BaseRules):
    """Architecture-level checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_giant_module(source, filename))
        diags.extend(self._check_deep_nesting(tree, filename))
        diags.extend(self._check_god_functions(tree, filename))
        diags.extend(self._check_too_many_args(tree, filename))
        return diags

    def _check_giant_module(self, source: str, filename: str) -> list[Diagnostic]:
        lines = source.count("\n") + 1
        if lines > MAX_MODULE_LINES:
            return [Diagnostic(
                file_path=filename,
                rule="no-giant-module",
                severity=Severity.WARNING,
                category=Category.ARCHITECTURE,
                message=f"Module has {lines} lines (max {MAX_MODULE_LINES}) — consider splitting",
                help="Extract related functions into separate modules",
                line=1,
            )]
        return []

    def _check_deep_nesting(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        self._walk_nesting(tree, 0, filename, diags)
        return diags

    def _walk_nesting(
        self, node: ast.AST, depth: int, filename: str, diags: list[Diagnostic]
    ) -> None:
        nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try)
        if isinstance(node, nesting_nodes):
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                diags.append(Diagnostic(
                    file_path=filename,
                    rule="no-deep-nesting",
                    severity=Severity.WARNING,
                    category=Category.ARCHITECTURE,
                    message=f"Nesting depth {depth} exceeds max {MAX_NESTING_DEPTH}",
                    help="Extract nested logic into helper functions or use early returns",
                    line=node.lineno,
                    column=node.col_offset,
                ))
        for child in ast.iter_child_nodes(node):
            self._walk_nesting(child, depth, filename, diags)

    def _check_god_functions(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", None)
                if end is not None:
                    length = end - node.lineno + 1
                    if length > MAX_FUNCTION_LINES:
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-god-function",
                            severity=Severity.WARNING,
                            category=Category.ARCHITECTURE,
                            message=f"Function '{node.name}' is {length} lines (max {MAX_FUNCTION_LINES})",
                            help="Break into smaller functions with single responsibilities",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags

    def _check_too_many_args(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                total = (
                    len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
                )
                # Subtract 'self'/'cls' for methods
                if total > 0 and args.args and args.args[0].arg in ("self", "cls"):
                    total -= 1
                if total > MAX_ARGUMENTS:
                    diags.append(Diagnostic(
                        file_path=filename,
                        rule="too-many-arguments",
                        severity=Severity.WARNING,
                        category=Category.ARCHITECTURE,
                        message=f"Function '{node.name}' has {total} arguments (max {MAX_ARGUMENTS})",
                        help="Group related arguments into a dataclass or TypedDict",
                        line=node.lineno,
                        column=node.col_offset,
                    ))
        return diags
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/rules/test_architecture.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/rules/architecture.py tests/rules/test_architecture.py
git commit -m "feat: architecture rules (giant modules, deep nesting, god functions, too many args)"
```

---

### Task 8: Correctness Rules

**Files:**
- Create: `src/python_doctor/rules/correctness.py`
- Create: `tests/rules/test_correctness.py`

- [ ] **Step 1: Write failing tests**

Create `tests/rules/test_correctness.py`:

```python
from python_doctor.rules.correctness import CorrectnessRules


def _run(source: str) -> list:
    return CorrectnessRules().check(source, "app.py")


def test_mutable_default_arg_list():
    diags = _run("def foo(items=[]):\n    pass")
    assert any(d.rule == "no-mutable-default" for d in diags)


def test_mutable_default_arg_dict():
    diags = _run("def foo(config={}):\n    pass")
    assert any(d.rule == "no-mutable-default" for d in diags)


def test_bare_except():
    diags = _run("try:\n    pass\nexcept:\n    pass")
    assert any(d.rule == "no-bare-except" for d in diags)


def test_broad_exception():
    diags = _run("try:\n    pass\nexcept Exception:\n    pass")
    assert any(d.rule == "no-broad-exception" for d in diags)


def test_specific_exception_ok():
    diags = _run("try:\n    pass\nexcept ValueError:\n    pass")
    assert not any(d.rule == "no-broad-exception" for d in diags)
    assert not any(d.rule == "no-bare-except" for d in diags)


def test_assert_in_non_test_file():
    diags = _run("assert user.is_admin, 'Must be admin'")
    assert any(d.rule == "no-assert-in-production" for d in diags)


def test_assert_in_test_file_ok():
    diags = CorrectnessRules().check("assert result == 42", "test_app.py")
    assert not any(d.rule == "no-assert-in-production" for d in diags)


def test_no_return_in_init():
    source = """
class Foo:
    def __init__(self):
        return 42
"""
    diags = _run(source)
    assert any(d.rule == "no-return-in-init" for d in diags)


def test_init_return_none_ok():
    source = """
class Foo:
    def __init__(self):
        return
"""
    diags = _run(source)
    assert not any(d.rule == "no-return-in-init" for d in diags)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_correctness.py -v`
Expected: FAIL

- [ ] **Step 3: Create correctness.py**

```python
"""Correctness rules: mutable defaults, bare except, broad exception, assert in prod, return in __init__."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity


class CorrectnessRules(BaseRules):
    """Correctness-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_mutable_defaults(tree, filename))
        diags.extend(self._check_bare_except(tree, filename))
        diags.extend(self._check_broad_exception(tree, filename))
        diags.extend(self._check_assert_in_production(tree, filename))
        diags.extend(self._check_return_in_init(tree, filename))
        return diags

    def _check_mutable_defaults(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-mutable-default",
                            severity=Severity.ERROR,
                            category=Category.CORRECTNESS,
                            message="Mutable default argument — shared across all calls",
                            help="Use None as default and create the mutable inside the function body",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags

    def _check_bare_except(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                diags.append(Diagnostic(
                    file_path=filename,
                    rule="no-bare-except",
                    severity=Severity.ERROR,
                    category=Category.CORRECTNESS,
                    message="Bare except catches all exceptions including SystemExit and KeyboardInterrupt",
                    help="Catch a specific exception type, or at minimum use 'except Exception'",
                    line=node.lineno,
                    column=node.col_offset,
                ))
        return diags

    def _check_broad_exception(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                if isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
                    diags.append(Diagnostic(
                        file_path=filename,
                        rule="no-broad-exception",
                        severity=Severity.WARNING,
                        category=Category.CORRECTNESS,
                        message=f"Catching '{node.type.id}' is too broad — masks real errors",
                        help="Catch specific exception types (ValueError, TypeError, etc.)",
                        line=node.lineno,
                        column=node.col_offset,
                    ))
        return diags

    def _check_assert_in_production(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        # Skip test files
        if filename.startswith("test_") or "/test_" in filename or filename.endswith("_test.py"):
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                diags.append(Diagnostic(
                    file_path=filename,
                    rule="no-assert-in-production",
                    severity=Severity.WARNING,
                    category=Category.CORRECTNESS,
                    message="assert statements are stripped with python -O flag",
                    help="Use explicit if/raise for production validation",
                    line=node.lineno,
                    column=node.col_offset,
                ))
        return diags

    def _check_return_in_init(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-return-in-init",
                            severity=Severity.ERROR,
                            category=Category.CORRECTNESS,
                            message="__init__ should not return a value",
                            help="Remove the return value — __init__ must return None",
                            line=child.lineno,
                            column=child.col_offset,
                        ))
        return diags
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/rules/test_correctness.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/rules/correctness.py tests/rules/test_correctness.py
git commit -m "feat: correctness rules (bare except, broad exception, assert in prod, return in init)"
```

---

### Task 9: Django Rules

**Files:**
- Create: `src/python_doctor/rules/django.py`
- Create: `tests/rules/test_django.py`

- [ ] **Step 1: Write failing tests**

Create `tests/rules/test_django.py`:

```python
from python_doctor.rules.django import DjangoRules


def _run(source: str, filename: str = "views.py") -> list:
    return DjangoRules().check(source, filename)


def test_raw_sql():
    source = """
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"""
    diags = _run(source)
    assert any(d.rule == "no-raw-sql-injection" for d in diags)


def test_debug_true_in_settings():
    diags = _run("DEBUG = True", filename="settings.py")
    assert any(d.rule == "no-debug-true" for d in diags)


def test_debug_in_non_settings_ok():
    diags = _run("DEBUG = True", filename="views.py")
    assert not any(d.rule == "no-debug-true" for d in diags)


def test_missing_select_related():
    source = """
for order in Order.objects.all():
    print(order.customer.name)
"""
    diags = _run(source)
    assert any(d.rule == "no-n-plus-one-query" for d in diags)


def test_secret_key_in_settings():
    diags = _run('SECRET_KEY = "django-insecure-abc123def456"', filename="settings.py")
    assert any(d.rule == "no-secret-key-in-source" for d in diags)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_django.py -v`
Expected: FAIL

- [ ] **Step 3: Create django.py**

```python
"""Django-specific rules: raw SQL, DEBUG=True, N+1 queries, secret key exposure."""

from __future__ import annotations

import ast
import re

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity


class DjangoRules(BaseRules):
    """Django framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_raw_sql(tree, filename))
        diags.extend(self._check_debug_true(tree, filename))
        diags.extend(self._check_n_plus_one(tree, source, filename))
        diags.extend(self._check_secret_key(tree, filename))
        return diags

    def _check_raw_sql(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "execute" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-raw-sql-injection",
                            severity=Severity.ERROR,
                            category=Category.DJANGO,
                            message="SQL query built with string concatenation — SQL injection risk",
                            help="Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', [user_id])",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags

    def _check_debug_true(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        if "settings" not in filename:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "DEBUG"
                        and isinstance(node.value, ast.Constant)
                        and node.value.value is True
                    ):
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-debug-true",
                            severity=Severity.ERROR,
                            category=Category.DJANGO,
                            message="DEBUG = True should not be hardcoded in settings",
                            help="Use environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags

    def _check_n_plus_one(self, tree: ast.Module, source: str, filename: str) -> list[Diagnostic]:
        """Detect potential N+1 query patterns: loop over queryset + attribute access."""
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.For):
                # Check if iterating over .objects.all() or .objects.filter()
                if self._is_queryset_iter(node.iter):
                    # Check if loop body accesses chained attributes (FK traversal)
                    loop_var = node.target
                    if isinstance(loop_var, ast.Name):
                        for child in ast.walk(node):
                            if (
                                isinstance(child, ast.Attribute)
                                and isinstance(child.value, ast.Attribute)
                                and isinstance(child.value.value, ast.Name)
                                and child.value.value.id == loop_var.id
                            ):
                                diags.append(Diagnostic(
                                    file_path=filename,
                                    rule="no-n-plus-one-query",
                                    severity=Severity.WARNING,
                                    category=Category.DJANGO,
                                    message="Potential N+1 query — accessing related object in a loop",
                                    help="Use select_related() or prefetch_related() on the queryset",
                                    line=child.lineno,
                                    column=child.col_offset,
                                ))
                                break  # One warning per loop
        return diags

    def _is_queryset_iter(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("all", "filter", "exclude", "values", "values_list"):
                return True
        return False

    def _check_secret_key(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        if "settings" not in filename:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "SECRET_KEY"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-secret-key-in-source",
                            severity=Severity.ERROR,
                            category=Category.DJANGO,
                            message="SECRET_KEY hardcoded in settings — use environment variable",
                            help="Use os.environ['SECRET_KEY'] or django-environ",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/rules/test_django.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/rules/django.py tests/rules/test_django.py
git commit -m "feat: Django rules (raw SQL, DEBUG, N+1 queries, secret key)"
```

---

### Task 10: FastAPI Rules

**Files:**
- Create: `src/python_doctor/rules/fastapi.py`
- Create: `tests/rules/test_fastapi.py`

- [ ] **Step 1: Write failing tests**

Create `tests/rules/test_fastapi.py`:

```python
from python_doctor.rules.fastapi import FastAPIRules


def _run(source: str) -> list:
    return FastAPIRules().check(source, "main.py")


def test_sync_endpoint():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
def get_users():
    return []
"""
    diags = _run(source)
    assert any(d.rule == "prefer-async-endpoint" for d in diags)


def test_async_endpoint_ok():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"""
    diags = _run(source)
    assert not any(d.rule == "prefer-async-endpoint" for d in diags)


def test_missing_response_model():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"""
    diags = _run(source)
    assert any(d.rule == "missing-response-model" for d in diags)


def test_response_model_present_ok():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users", response_model=list[dict])
async def get_users():
    return []
"""
    diags = _run(source)
    assert not any(d.rule == "missing-response-model" for d in diags)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_fastapi.py -v`
Expected: FAIL

- [ ] **Step 3: Create fastapi.py**

```python
"""FastAPI-specific rules: sync endpoints, missing response_model."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class FastAPIRules(BaseRules):
    """FastAPI framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route_decorator = self._get_route_decorator(node)
                if route_decorator is not None:
                    diags.extend(self._check_sync_endpoint(node, route_decorator, filename))
                    diags.extend(self._check_response_model(node, route_decorator, filename))
        return diags

    def _get_route_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call | None:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in _ROUTE_METHODS:
                    return dec
        return None

    def _check_sync_endpoint(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator: ast.Call,
        filename: str,
    ) -> list[Diagnostic]:
        if isinstance(node, ast.FunctionDef):  # Not async
            return [Diagnostic(
                file_path=filename,
                rule="prefer-async-endpoint",
                severity=Severity.WARNING,
                category=Category.FASTAPI,
                message=f"Endpoint '{node.name}' is synchronous — blocks the event loop",
                help="Use 'async def' for I/O-bound endpoints",
                line=node.lineno,
                column=node.col_offset,
            )]
        return []

    def _check_response_model(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator: ast.Call,
        filename: str,
    ) -> list[Diagnostic]:
        has_response_model = any(
            kw.arg == "response_model" for kw in decorator.keywords
        )
        if not has_response_model:
            return [Diagnostic(
                file_path=filename,
                rule="missing-response-model",
                severity=Severity.WARNING,
                category=Category.FASTAPI,
                message=f"Endpoint '{node.name}' missing response_model — no response validation",
                help="Add response_model parameter to the route decorator",
                line=node.lineno,
                column=node.col_offset,
            )]
        return []
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/rules/test_fastapi.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/rules/fastapi.py tests/rules/test_fastapi.py
git commit -m "feat: FastAPI rules (sync endpoints, missing response_model)"
```

---

### Task 11: Flask Rules

**Files:**
- Create: `src/python_doctor/rules/flask.py`
- Create: `tests/rules/test_flask.py`

- [ ] **Step 1: Write failing tests**

Create `tests/rules/test_flask.py`:

```python
from python_doctor.rules.flask import FlaskRules


def _run(source: str, filename: str = "app.py") -> list:
    return FlaskRules().check(source, filename)


def test_secret_key_hardcoded():
    source = """
from flask import Flask
app = Flask(__name__)
app.secret_key = "super-secret-key-value"
"""
    diags = _run(source)
    assert any(d.rule == "no-flask-secret-in-source" for d in diags)


def test_debug_mode():
    source = """
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
"""
    diags = _run(source)
    assert any(d.rule == "no-flask-debug-mode" for d in diags)


def test_sql_string_format():
    source = """
@app.route("/user/<user_id>")
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    db.execute(query)
"""
    diags = _run(source)
    assert any(d.rule == "no-sql-string-format" for d in diags)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_flask.py -v`
Expected: FAIL

- [ ] **Step 3: Create flask.py**

```python
"""Flask-specific rules: secret key in source, debug mode, SQL via string format."""

from __future__ import annotations

import ast
import re

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

_SQL_PATTERN = re.compile(
    r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+",
    re.IGNORECASE,
)


class FlaskRules(BaseRules):
    """Flask framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_secret_key(tree, filename))
        diags.extend(self._check_debug_mode(tree, filename))
        diags.extend(self._check_sql_string_format(tree, filename))
        return diags

    def _check_secret_key(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "secret_key"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        diags.append(Diagnostic(
                            file_path=filename,
                            rule="no-flask-secret-in-source",
                            severity=Severity.ERROR,
                            category=Category.FLASK,
                            message="Flask secret_key hardcoded in source",
                            help="Use os.environ['SECRET_KEY'] or a config file",
                            line=node.lineno,
                            column=node.col_offset,
                        ))
        return diags

    def _check_debug_mode(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "run":
                    for kw in node.keywords:
                        if (
                            kw.arg == "debug"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                        ):
                            diags.append(Diagnostic(
                                file_path=filename,
                                rule="no-flask-debug-mode",
                                severity=Severity.ERROR,
                                category=Category.FLASK,
                                message="Debug mode enabled — exposes debugger and reloader in production",
                                help="Use environment variable: app.run(debug=os.environ.get('FLASK_DEBUG'))",
                                line=node.lineno,
                                column=node.col_offset,
                            ))
        return diags

    def _check_sql_string_format(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.JoinedStr):  # f-string
                    # Check if it looks like SQL
                    for val in node.value.values:
                        if isinstance(val, ast.Constant) and isinstance(val.value, str):
                            if _SQL_PATTERN.search(val.value):
                                diags.append(Diagnostic(
                                    file_path=filename,
                                    rule="no-sql-string-format",
                                    severity=Severity.ERROR,
                                    category=Category.FLASK,
                                    message="SQL query built with f-string — SQL injection risk",
                                    help="Use parameterized queries with placeholders",
                                    line=node.lineno,
                                    column=node.col_offset,
                                ))
                                break
        return diags
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/rules/test_flask.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/rules/flask.py tests/rules/test_flask.py
git commit -m "feat: Flask rules (secret key, debug mode, SQL injection)"
```

---

### Task 12: Dead Code Detection (Vulture Integration)

**Files:**
- Create: `src/python_doctor/rules/dead_code.py`
- Create: `tests/rules/test_dead_code.py`

- [ ] **Step 1: Write failing tests**

Create `tests/rules/test_dead_code.py`:

```python
from pathlib import Path
from python_doctor.rules.dead_code import DeadCodeRules
from python_doctor.types import Category


def test_detects_unused_function(tmp_path):
    (tmp_path / "app.py").write_text("""
def used_function():
    return 42

def unused_function():
    return 99

result = used_function()
""")
    rules = DeadCodeRules()
    diags = rules.check_project(str(tmp_path))
    assert any(d.rule == "dead-code" and "unused_function" in d.message for d in diags)
    assert all(d.category == Category.DEAD_CODE for d in diags)


def test_no_dead_code_in_clean_project(tmp_path):
    (tmp_path / "app.py").write_text("""
def greet(name):
    return f"Hello, {name}"

print(greet("world"))
""")
    rules = DeadCodeRules()
    diags = rules.check_project(str(tmp_path))
    # Vulture may still find some things, but greet should not be flagged
    assert not any("greet" in d.message for d in diags)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/rules/test_dead_code.py -v`
Expected: FAIL

- [ ] **Step 3: Create dead_code.py**

```python
"""Dead code detection via vulture."""

from __future__ import annotations

import io
import contextlib
from pathlib import Path

from python_doctor.types import Category, Diagnostic, Severity


class DeadCodeRules:
    """Detect unused code using vulture."""

    def check_project(self, project_path: str) -> list[Diagnostic]:
        """Run vulture on the entire project and return diagnostics."""
        try:
            import vulture  # noqa: F811
        except ImportError:
            return []

        v = vulture.Vulture()

        py_files = list(Path(project_path).rglob("*.py"))
        # Filter out common non-source directories
        ignore = {".venv", "venv", "node_modules", "__pycache__", ".git", "dist", "build"}
        py_files = [
            f for f in py_files
            if not any(part in ignore for part in f.relative_to(project_path).parts)
        ]

        if not py_files:
            return []

        v.scan([str(f) for f in py_files])

        diags: list[Diagnostic] = []
        for item in v.get_unused_code():
            diags.append(Diagnostic(
                file_path=str(item.filename),
                rule="dead-code",
                severity=Severity.WARNING,
                category=Category.DEAD_CODE,
                message=f"Unused {item.typ}: '{item.name}' ({item.confidence}% confidence)",
                help="Remove this dead code or add it to a vulture whitelist",
                line=item.first_lineno,
            ))
        return diags
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/rules/test_dead_code.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/rules/dead_code.py tests/rules/test_dead_code.py
git commit -m "feat: dead code detection via vulture integration"
```

---

### Task 13: Scan Orchestration

**Files:**
- Create: `src/python_doctor/scan.py`
- Create: `src/python_doctor/utils/ast_helpers.py`
- Create: `src/python_doctor/utils/diff.py`
- Create: `tests/test_scan.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_scan.py`:

```python
from pathlib import Path
from python_doctor.scan import scan_project
from python_doctor.config import Config


def test_scan_clean_project(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "clean"\ndependencies = []\n')
    (tmp_path / "app.py").write_text("""
def greet(name: str) -> str:
    return f"Hello, {name}"

print(greet("world"))
""")
    result = scan_project(str(tmp_path), Config())
    assert result.score.value >= 75
    assert result.project.path == str(tmp_path)
    assert result.elapsed_ms >= 0


def test_scan_project_with_issues(tmp_path):
    (tmp_path / "app.py").write_text("""
result = eval(user_input)
exec(code)
API_KEY = "sk-1234567890abcdef1234567890abcdef"
""")
    result = scan_project(str(tmp_path), Config())
    assert result.score.value < 100
    assert len(result.diagnostics) > 0


def test_scan_respects_ignore_rules(tmp_path):
    (tmp_path / "app.py").write_text('result = eval("1+1")')
    config = Config(ignore_rules=["no-eval"])
    result = scan_project(str(tmp_path), config)
    assert not any(d.rule == "no-eval" for d in result.diagnostics)


def test_scan_lint_disabled(tmp_path):
    (tmp_path / "app.py").write_text('result = eval("1+1")')
    config = Config(lint=False, dead_code=False)
    result = scan_project(str(tmp_path), config)
    assert result.diagnostics == []


def test_scan_dead_code_disabled(tmp_path):
    (tmp_path / "app.py").write_text("""
def unused():
    pass
""")
    config = Config(dead_code=False)
    result = scan_project(str(tmp_path), config)
    assert not any(d.rule == "dead-code" for d in result.diagnostics)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_scan.py -v`
Expected: FAIL

- [ ] **Step 3: Create utils/ast_helpers.py**

```python
"""Common AST traversal utilities."""

from __future__ import annotations

import ast
from pathlib import Path


def parse_file(file_path: Path) -> tuple[str, ast.Module | None]:
    """Read and parse a Python file. Returns (source, tree) or (source, None) on error."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
        return source, tree
    except (SyntaxError, UnicodeDecodeError):
        return "", None
```

- [ ] **Step 4: Create utils/diff.py**

```python
"""Git diff utilities for scanning only changed files."""

from __future__ import annotations

import subprocess
from pathlib import Path


def get_changed_files(project_path: str, base: str = "main") -> list[Path] | None:
    """Get Python files changed compared to a base branch. Returns None if git fails."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", base, "--", "*.py"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        root = Path(project_path)
        return [root / f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
```

- [ ] **Step 5: Create scan.py**

```python
"""Scan orchestration: runs lint + dead code in parallel, produces ScanResult."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from python_doctor.config import Config
from python_doctor.discover import discover_project
from python_doctor.rules import get_all_rule_sets, get_framework_rules
from python_doctor.rules.dead_code import DeadCodeRules
from python_doctor.score import calculate_score
from python_doctor.types import Diagnostic, ScanResult
from python_doctor.utils.file_discovery import find_python_files


def scan_project(
    project_path: str,
    config: Config,
    diff_base: str | None = None,
) -> ScanResult:
    """Run full scan and return results."""
    start = time.monotonic()

    project = discover_project(project_path)

    # Determine files to scan
    if diff_base:
        from python_doctor.utils.diff import get_changed_files
        files = get_changed_files(project_path, diff_base)
        if files is None:
            files = find_python_files(project_path)
    else:
        files = find_python_files(project_path)

    # Run lint + dead code in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        lint_future = executor.submit(
            _run_lint, files, project.framework, config
        ) if config.lint else None
        dead_code_future = executor.submit(
            _run_dead_code, project_path, config
        ) if config.dead_code else None

        lint_diags = lint_future.result() if lint_future else []
        dead_code_diags = dead_code_future.result() if dead_code_future else []

    all_diags = lint_diags + dead_code_diags

    # Apply ignore rules
    if config.ignore_rules:
        all_diags = [d for d in all_diags if d.rule not in config.ignore_rules]

    # Apply ignore files
    if config.ignore_files:
        import fnmatch
        all_diags = [
            d for d in all_diags
            if not any(fnmatch.fnmatch(d.file_path, pat) for pat in config.ignore_files)
        ]

    score = calculate_score(all_diags)
    elapsed = int((time.monotonic() - start) * 1000)

    return ScanResult(
        score=score,
        diagnostics=all_diags,
        project=project,
        elapsed_ms=elapsed,
    )


def _run_lint(
    files: list[Path],
    framework: str | None,
    config: Config,
) -> list[Diagnostic]:
    """Run all rule sets against all files."""
    rule_sets = get_all_rule_sets() + get_framework_rules(framework)
    diags: list[Diagnostic] = []

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        for rules in rule_sets:
            diags.extend(rules.check(source, str(file_path)))

    return diags


def _run_dead_code(project_path: str, config: Config) -> list[Diagnostic]:
    """Run dead code detection."""
    return DeadCodeRules().check_project(project_path)
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/test_scan.py -v`
Expected: All PASSED

- [ ] **Step 7: Commit**

```bash
git add src/python_doctor/scan.py src/python_doctor/utils/ast_helpers.py src/python_doctor/utils/diff.py tests/test_scan.py
git commit -m "feat: scan orchestration with parallel lint + dead code detection"
```

---

### Task 14: Rich Terminal Output

**Files:**
- Create: `src/python_doctor/output.py`
- Create: `tests/test_output.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_output.py`:

```python
from io import StringIO
from python_doctor.output import format_score_bar, format_doctor_face, format_summary
from python_doctor.types import Score, ScanResult, ProjectInfo, Diagnostic, Severity, Category


def test_score_bar_full():
    bar = format_score_bar(100)
    assert "100" in bar


def test_score_bar_empty():
    bar = format_score_bar(0)
    assert "0" in bar


def test_doctor_face_happy():
    face = format_doctor_face(90)
    assert face  # Non-empty string


def test_doctor_face_sad():
    face = format_doctor_face(30)
    assert face


def test_format_summary():
    result = ScanResult(
        score=Score(value=85, label="Great"),
        diagnostics=[
            Diagnostic(
                file_path="app.py",
                rule="no-eval",
                severity=Severity.ERROR,
                category=Category.SECURITY,
                message="Avoid eval()",
                help="Use ast.literal_eval()",
                line=1,
            )
        ],
        project=ProjectInfo(
            path="/tmp/proj",
            python_version="3.12",
            framework="fastapi",
            package_manager="uv",
            test_framework="pytest",
            has_type_hints=True,
            source_file_count=42,
        ),
        elapsed_ms=1234,
    )
    text = format_summary(result)
    assert "85" in text
    assert "Great" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_output.py -v`
Expected: FAIL

- [ ] **Step 3: Create output.py**

```python
"""Rich terminal output: score bar, doctor face, framed summary, diagnostic groups."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from python_doctor.types import Diagnostic, ScanResult, Severity

BAR_WIDTH = 50

# Doctor ASCII faces
_HAPPY = r"""
  ┌─────┐
  │ ◕ ◕ │
  │  ◡  │
  └─────┘
"""

_NEUTRAL = r"""
  ┌─────┐
  │ ◑ ◑ │
  │  ━  │
  └─────┘
"""

_SAD = r"""
  ┌─────┐
  │ ◔ ◔ │
  │  ◠  │
  └─────┘
"""


def format_score_bar(score: int) -> str:
    """Return a text-based score bar."""
    filled = round(score / 100 * BAR_WIDTH)
    empty = BAR_WIDTH - filled
    bar = "█" * filled + "░" * empty
    return f"  {bar} {score}/100"


def format_doctor_face(score: int) -> str:
    """Return doctor ASCII art based on score."""
    if score >= 75:
        return _HAPPY
    elif score >= 50:
        return _NEUTRAL
    else:
        return _SAD


def _score_color(score: int) -> str:
    if score >= 75:
        return "green"
    elif score >= 50:
        return "yellow"
    return "red"


def format_summary(result: ScanResult) -> str:
    """Format the full scan summary as a string (for testing)."""
    lines: list[str] = []
    lines.append(format_doctor_face(result.score.value))
    lines.append(f"  Score: {result.score.value}/100 — {result.score.label}")
    lines.append(format_score_bar(result.score.value))
    lines.append("")

    errors = sum(1 for d in result.diagnostics if d.severity == Severity.ERROR)
    warnings = sum(1 for d in result.diagnostics if d.severity == Severity.WARNING)
    files = len({d.file_path for d in result.diagnostics})

    lines.append(f"  {errors} errors, {warnings} warnings across {files} files")
    lines.append(f"  Completed in {result.elapsed_ms}ms")
    return "\n".join(lines)


def print_scan_result(result: ScanResult, verbose: bool = False) -> None:
    """Print the full scan result to terminal using Rich."""
    console = Console()

    # Project info
    p = result.project
    console.print()
    console.print(f"  [bold]Python Doctor[/bold] — v0.1.0")
    console.print()
    console.print(f"  [dim]Path:[/dim]            {p.path}")
    if p.framework:
        console.print(f"  [dim]Framework:[/dim]       {p.framework}")
    if p.python_version:
        console.print(f"  [dim]Python:[/dim]          {p.python_version}")
    if p.package_manager:
        console.print(f"  [dim]Package manager:[/dim] {p.package_manager}")
    if p.test_framework:
        console.print(f"  [dim]Test framework:[/dim]  {p.test_framework}")
    console.print(f"  [dim]Source files:[/dim]    {p.source_file_count}")
    console.print()

    # Diagnostics grouped by rule
    if result.diagnostics:
        _print_diagnostics(console, result.diagnostics, verbose)

    # Summary panel
    color = _score_color(result.score.value)
    face = format_doctor_face(result.score.value).strip()

    errors = sum(1 for d in result.diagnostics if d.severity == Severity.ERROR)
    warnings = sum(1 for d in result.diagnostics if d.severity == Severity.WARNING)
    files = len({d.file_path for d in result.diagnostics})

    summary = Text()
    summary.append(f"\n{face}\n\n", style="bold")
    summary.append(f"  Score: ", style="dim")
    summary.append(f"{result.score.value}/100", style=f"bold {color}")
    summary.append(f" — {result.score.label}\n", style=color)
    summary.append(f"{format_score_bar(result.score.value)}\n\n")
    summary.append(f"  {errors} errors, {warnings} warnings across {files} files\n", style="dim")
    summary.append(f"  Completed in {result.elapsed_ms}ms\n", style="dim")

    console.print(Panel(summary, title="[bold]Results[/bold]", border_style=color))
    console.print()


def _print_diagnostics(
    console: Console, diagnostics: list[Diagnostic], verbose: bool
) -> None:
    """Print diagnostics grouped by rule, sorted by severity."""
    # Group by rule
    groups: dict[str, list[Diagnostic]] = {}
    for d in diagnostics:
        groups.setdefault(d.rule, []).append(d)

    # Sort: errors first
    sorted_rules = sorted(
        groups.keys(),
        key=lambda r: (0 if groups[r][0].severity == Severity.ERROR else 1, r),
    )

    for rule in sorted_rules:
        diags = groups[rule]
        first = diags[0]
        icon = "[red]✗[/red]" if first.severity == Severity.ERROR else "[yellow]⚠[/yellow]"
        count = len(diags)

        console.print(f"  {icon} [bold]{first.message}[/bold]  [dim]({rule} × {count})[/dim]")
        if first.help:
            console.print(f"    [dim]{first.help}[/dim]")

        if verbose:
            for d in diags[:10]:
                console.print(f"    [dim]{d.file_path}:{d.line}[/dim]")
            if count > 10:
                console.print(f"    [dim]... and {count - 10} more[/dim]")

        console.print()
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_output.py -v`
Expected: All PASSED

- [ ] **Step 5: Commit**

```bash
git add src/python_doctor/output.py tests/test_output.py
git commit -m "feat: Rich terminal output with score bar, doctor face, diagnostic groups"
```

---

### Task 15: CLI Entry Point

**Files:**
- Create: `src/python_doctor/cli.py`
- Create: `src/python_doctor/api.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_cli.py`:

```python
from click.testing import CliRunner
from python_doctor.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Python Doctor" in result.output or "python-doctor" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_scan_clean_project(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path)])
    assert result.exit_code == 0


def test_cli_score_only(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--score"])
    assert result.exit_code == 0
    # Should output just the number
    score_line = result.output.strip()
    assert score_line.isdigit()


def test_cli_no_lint(tmp_path):
    (tmp_path / "app.py").write_text('eval("1+1")')
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--no-lint", "--score"])
    assert result.exit_code == 0


def test_cli_fail_on_error(tmp_path):
    (tmp_path / "app.py").write_text('eval("1+1")')
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--fail-on", "error"])
    assert result.exit_code == 1


def test_cli_fail_on_none(tmp_path):
    (tmp_path / "app.py").write_text('eval("1+1")')
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--fail-on", "none"])
    assert result.exit_code == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL

- [ ] **Step 3: Create api.py**

```python
"""Programmatic API for python-doctor."""

from __future__ import annotations

from python_doctor.config import Config, load_config
from python_doctor.scan import scan_project
from python_doctor.types import ScanResult


def diagnose(
    project_path: str = ".",
    *,
    lint: bool = True,
    dead_code: bool = True,
    diff_base: str | None = None,
) -> ScanResult:
    """Run python-doctor analysis programmatically.

    Args:
        project_path: Path to the Python project.
        lint: Enable lint checks.
        dead_code: Enable dead code detection.
        diff_base: Only scan files changed vs this branch.

    Returns:
        ScanResult with score, diagnostics, and project info.
    """
    config = load_config(project_path)
    config.lint = lint
    config.dead_code = dead_code

    return scan_project(project_path, config, diff_base=diff_base)
```

- [ ] **Step 4: Create cli.py**

```python
"""CLI entry point for python-doctor."""

from __future__ import annotations

import sys

import click

from python_doctor import __version__
from python_doctor.config import Config, load_config
from python_doctor.output import print_scan_result
from python_doctor.scan import scan_project
from python_doctor.types import Severity


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-v", "--version", prog_name="Python Doctor")
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option("--lint/--no-lint", default=True, help="Enable/disable lint checks.")
@click.option("--dead-code/--no-dead-code", default=True, help="Enable/disable dead code detection.")
@click.option("--verbose", is_flag=True, help="Show file details per rule.")
@click.option("--score", "score_only", is_flag=True, help="Output only the numeric score.")
@click.option(
    "--diff",
    "diff_base",
    default=None,
    type=str,
    help="Scan only files changed vs base branch.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["error", "warning", "none"]),
    default="none",
    help="Exit with code 1 on this severity level.",
)
def main(
    directory: str,
    lint: bool,
    dead_code: bool,
    verbose: bool,
    score_only: bool,
    diff_base: str | None,
    fail_on: str,
) -> None:
    """Python Doctor — Diagnose your Python project's health."""
    config = load_config(directory)
    config.lint = lint
    config.dead_code = dead_code
    config.verbose = verbose
    config.fail_on = fail_on

    result = scan_project(directory, config, diff_base=diff_base)

    if score_only:
        click.echo(str(result.score.value))
    else:
        print_scan_result(result, verbose=verbose)

    # Exit code based on --fail-on
    if fail_on == "error" and any(d.severity == Severity.ERROR for d in result.diagnostics):
        sys.exit(1)
    elif fail_on == "warning" and result.diagnostics:
        sys.exit(1)
```

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All PASSED

- [ ] **Step 6: Commit**

```bash
git add src/python_doctor/cli.py src/python_doctor/api.py tests/test_cli.py
git commit -m "feat: CLI entry point with Click + programmatic API"
```

---

### Task 16: Full Integration Test + Final Polish

**Files:**
- Create: test fixture projects
- Create: `tests/test_integration.py`
- Modify: `src/python_doctor/rules/__init__.py` (ensure all imports work)

- [ ] **Step 1: Create test fixtures**

Create `tests/fixtures/basic_python/app.py`:

```python
import pickle
import yaml
from os.path import *

API_KEY = "sk-1234567890abcdef1234567890abcdef"
PASSWORD = "supersecretpassword123"

def process_data(items=[]):
    result = ""
    for item in items:
        result += str(item)
    return result

def dangerous(user_input):
    return eval(user_input)

data = yaml.load(open("config.yaml"))
obj = pickle.load(open("data.pkl", "rb"))

try:
    risky()
except:
    pass
```

Create `tests/fixtures/clean_project/app.py`:

```python
"""A clean Python module."""

import json
from typing import Optional


def greet(name: str, greeting: Optional[str] = None) -> str:
    """Greet someone by name."""
    if greeting is None:
        greeting = "Hello"
    return f"{greeting}, {name}!"


def process_items(items: list[str]) -> str:
    """Join items into a comma-separated string."""
    return ", ".join(items)


if __name__ == "__main__":
    print(greet("World"))
    print(process_items(["a", "b", "c"]))
```

- [ ] **Step 2: Write integration tests**

Create `tests/test_integration.py`:

```python
from pathlib import Path
from python_doctor.scan import scan_project
from python_doctor.config import Config


FIXTURES = Path(__file__).parent / "fixtures"


def test_basic_python_has_issues():
    result = scan_project(str(FIXTURES / "basic_python"), Config(dead_code=False))
    assert result.score.value < 100
    rules_found = {d.rule for d in result.diagnostics}
    assert "no-eval" in rules_found
    assert "no-hardcoded-secret" in rules_found
    assert "no-bare-except" in rules_found
    assert "no-star-import" in rules_found


def test_clean_project_scores_high():
    result = scan_project(str(FIXTURES / "clean_project"), Config(dead_code=False))
    assert result.score.value >= 90


def test_scan_nonexistent_returns_empty():
    """Scanning a dir with no Python files should still work."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        result = scan_project(tmp, Config())
        assert result.score.value == 100
        assert result.diagnostics == []
```

- [ ] **Step 3: Run all tests**

Run: `uv run pytest -v`
Expected: All PASSED

- [ ] **Step 4: Run ruff on the codebase**

Run: `uv run ruff check src/ tests/ --fix`
Expected: Clean or minor fixes applied

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/ tests/test_integration.py
git commit -m "feat: integration tests with fixture projects"
```

- [ ] **Step 6: Run full test suite one final time**

Run: `uv run pytest -v --tb=short`
Expected: All tests pass

- [ ] **Step 7: Final commit with any remaining fixes**

```bash
git add -A
git commit -m "chore: final polish and lint fixes"
```
