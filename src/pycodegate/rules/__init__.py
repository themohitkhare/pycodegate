"""Rule registry for pycodegate."""

from __future__ import annotations

from pycodegate.rules.architecture import ArchitectureRules
from pycodegate.rules.base import BaseRules
from pycodegate.rules.celery import CeleryRules
from pycodegate.rules.complexity import ComplexityRules
from pycodegate.rules.correctness import CorrectnessRules
from pycodegate.rules.dependencies import DependencyRules as DependencyRules
from pycodegate.rules.django import DjangoRules
from pycodegate.rules.fastapi import FastAPIRules
from pycodegate.rules.flask import FlaskRules
from pycodegate.rules.imports import ImportsRules as ImportsRules
from pycodegate.rules.logging_rules import LoggingRules
from pycodegate.rules.numpy_rules import NumpyRules
from pycodegate.rules.pandas_rules import PandasRules
from pycodegate.rules.performance import PerformanceRules
from pycodegate.rules.pydantic import PydanticRules
from pycodegate.rules.pytest_rules import PytestRules
from pycodegate.rules.requests_rules import RequestsRules
from pycodegate.rules.security import SecurityRules
from pycodegate.rules.sqlalchemy import SQLAlchemyRules
from pycodegate.rules.structure import StructureRules as StructureRules


def get_all_rule_sets() -> list[BaseRules]:
    """Return the core rule sets that run on every Python file."""
    return [
        SecurityRules(),
        PerformanceRules(),
        ArchitectureRules(),
        CorrectnessRules(),
        ComplexityRules(),
    ]


def get_import_gated_rules() -> list[tuple[BaseRules, str]]:
    """Return (rule_set, trigger_module) pairs.

    Each library rule set runs only on files that actually import its module, so a
    pandas rule never fires on a file that does not touch pandas — activation is
    per-file and import-based rather than project-wide from the dependency manifest.
    """
    return [
        (DjangoRules(), "django"),
        (FastAPIRules(), "fastapi"),
        (FlaskRules(), "flask"),
        (PydanticRules(), "pydantic"),
        (SQLAlchemyRules(), "sqlalchemy"),
        (CeleryRules(), "celery"),
        (RequestsRules(), "requests"),
        (LoggingRules(), "logging"),
        (PandasRules(), "pandas"),
        (NumpyRules(), "numpy"),
        (PytestRules(), "pytest"),
    ]
