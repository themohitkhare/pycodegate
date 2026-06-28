"""Detect whether a file path belongs to a project's test suite."""

from __future__ import annotations

from pathlib import Path


def is_test_file(file_path: str) -> bool:
    """Return True if *file_path* looks like test code or test fixtures.

    Matches the common conventions: a ``test_*.py`` / ``*_test.py`` module,
    ``conftest.py``, or any file living under a ``tests`` / ``test`` directory
    (which also covers fixture trees like ``tests/data/cases``).
    """
    path = Path(file_path)
    name = path.name
    if name == "conftest.py":
        return True
    stem = path.stem
    if stem.startswith("test_") or stem.endswith("_test"):
        return True
    return any(part in ("tests", "test") for part in path.parts)
