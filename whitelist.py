"""Vulture whitelist — these symbols are used but vulture can't detect it."""

# Public API
from python_doctor.api import diagnose  # noqa: F401

# Dataclass fields accessed dynamically or in templates
from python_doctor.types import ProjectInfo, Score  # noqa: F401

ProjectInfo.has_type_hints  # type: ignore[truthy-function]
ProjectInfo.source_file_count  # type: ignore[truthy-function]
Score.label  # type: ignore[truthy-function]

# AST helper used by rules
from python_doctor.utils.ast_helpers import parse_file  # noqa: F401
