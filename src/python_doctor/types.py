"""Core data types for python-doctor diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
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
