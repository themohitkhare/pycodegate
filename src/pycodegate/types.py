"""Core data types for pycodegate diagnostics."""

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
    COMPLEXITY = "Complexity"
    DEAD_CODE = "Dead Code"
    DJANGO = "Django"
    FASTAPI = "FastAPI"
    FLASK = "Flask"
    PYDANTIC = "Pydantic"
    SQLALCHEMY = "SQLAlchemy"
    CELERY = "Celery"
    REQUESTS = "Requests"
    LOGGING = "Logging"
    PANDAS = "Pandas"
    PYTEST = "Pytest"
    NUMPY = "NumPy"
    STRUCTURE = "Structure"
    IMPORTS = "Imports"
    DEPENDENCIES = "Dependencies"


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
    cost: float = field(default=1.0)


@dataclass(frozen=True)
class ProjectInfo:
    path: str
    python_version: str | None
    framework: str | None
    package_manager: str | None
    test_framework: str | None
    has_type_hints: bool
    source_file_count: int
    frameworks: list[str] = field(default_factory=list)


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
    profile: str | None = None
    category_scores: dict[Category, tuple[int, int]] = field(default_factory=dict)
