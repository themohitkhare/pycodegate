"""Rule registry for python-doctor."""

from __future__ import annotations

from python_doctor.rules.architecture import ArchitectureRules
from python_doctor.rules.base import BaseRules
from python_doctor.rules.complexity import ComplexityRules
from python_doctor.rules.correctness import CorrectnessRules
from python_doctor.rules.django import DjangoRules
from python_doctor.rules.fastapi import FastAPIRules
from python_doctor.rules.flask import FlaskRules
from python_doctor.rules.performance import PerformanceRules
from python_doctor.rules.security import SecurityRules


def get_all_rule_sets() -> list[BaseRules]:
    """Return all available rule sets."""
    return [
        SecurityRules(),
        PerformanceRules(),
        ArchitectureRules(),
        CorrectnessRules(),
        ComplexityRules(),
    ]


def get_framework_rules(framework: str | None) -> list[BaseRules]:
    """Return framework-specific rule sets."""
    _framework_map: dict[str, type[BaseRules]] = {
        "django": DjangoRules,
        "fastapi": FastAPIRules,
        "flask": FlaskRules,
    }
    cls = _framework_map.get(framework or "")
    return [cls()] if cls else []
