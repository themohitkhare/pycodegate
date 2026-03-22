"""Tests for run_ruff_fix utility."""

from __future__ import annotations

import tempfile
from pathlib import Path

from python_doctor.utils.fixer import run_ruff_fix


def test_run_ruff_fix_returns_int_on_temp_dir():
    """run_ruff_fix should return an int and not crash on an empty temp directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        result = run_ruff_fix(tmpdir)
    assert isinstance(result, int)


def test_run_ruff_fix_returns_int_on_python_file():
    """run_ruff_fix should return an int and not crash when there are Python files present."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a simple Python file
        py_file = Path(tmpdir) / "sample.py"
        py_file.write_text("x = 1\n")
        result = run_ruff_fix(tmpdir)
    assert isinstance(result, int)


def test_run_ruff_fix_nonnegative_or_minus_one():
    """run_ruff_fix returns -1 when ruff is not found, otherwise >= 0."""
    with tempfile.TemporaryDirectory() as tmpdir:
        result = run_ruff_fix(tmpdir)
    # -1 means ruff not installed; >= 0 means it ran successfully
    assert result >= -1
