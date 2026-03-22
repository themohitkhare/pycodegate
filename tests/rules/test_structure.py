"""Tests for StructureRules project-level health checks."""

from __future__ import annotations

from python_doctor.rules.structure import StructureRules
from python_doctor.types import Category


def test_large_file(tmp_path):
    """File over 1000 lines should trigger structure/large-file."""
    big = tmp_path / "big_module.py"
    big.write_text("\n".join(["x = 1"] * 1001))
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(big)])
    assert any(d.rule == "structure/large-file" for d in diags)
    assert all(d.category == Category.STRUCTURE for d in diags if d.rule == "structure/large-file")


def test_normal_file(tmp_path):
    """File under 1000 lines should not trigger structure/large-file."""
    small = tmp_path / "small_module.py"
    small.write_text("\n".join(["x = 1"] * 100))
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(small)])
    assert not any(d.rule == "structure/large-file" for d in diags)


def test_no_tests(tmp_path):
    """Project with no test files should trigger structure/no-tests."""
    src = tmp_path / "app.py"
    src.write_text("def hello(): pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src)])
    assert any(d.rule == "structure/no-tests" for d in diags)


def test_with_tests(tmp_path):
    """Project with test files should not trigger structure/no-tests."""
    src = tmp_path / "app.py"
    src.write_text("def hello(): pass\n")
    test_file = tmp_path / "test_app.py"
    test_file.write_text("def test_hello(): pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src), str(test_file)])
    assert not any(d.rule == "structure/no-tests" for d in diags)


def test_low_test_ratio(tmp_path):
    """Very few test lines vs many source lines should trigger structure/low-test-ratio."""
    src = tmp_path / "app.py"
    # 200 source lines
    src.write_text("\n".join(["x = 1"] * 200))
    test_file = tmp_path / "test_app.py"
    # 5 test lines — ratio ~0.025, well below 0.1
    test_file.write_text("\n".join(["x = 1"] * 5))
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src), str(test_file)])
    assert any(d.rule == "structure/low-test-ratio" for d in diags)


def test_no_readme(tmp_path):
    """Missing README should trigger structure/no-readme."""
    src = tmp_path / "app.py"
    src.write_text("pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src)])
    assert any(d.rule == "structure/no-readme" for d in diags)


def test_has_readme(tmp_path):
    """Presence of README.md should suppress structure/no-readme."""
    (tmp_path / "README.md").write_text("# My Project\n")
    src = tmp_path / "app.py"
    src.write_text("pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src)])
    assert not any(d.rule == "structure/no-readme" for d in diags)


def test_no_license(tmp_path):
    """Missing LICENSE file should trigger structure/no-license."""
    src = tmp_path / "app.py"
    src.write_text("pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src)])
    assert any(d.rule == "structure/no-license" for d in diags)


def test_no_gitignore(tmp_path):
    """Missing .gitignore should trigger structure/no-gitignore."""
    src = tmp_path / "app.py"
    src.write_text("pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src)])
    assert any(d.rule == "structure/no-gitignore" for d in diags)


def test_no_linter_config(tmp_path):
    """Project without any linter config should trigger structure/no-linter-config."""
    src = tmp_path / "app.py"
    src.write_text("pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src)])
    assert any(d.rule == "structure/no-linter-config" for d in diags)


def test_has_ruff_in_pyproject(tmp_path):
    """pyproject.toml with [tool.ruff] should suppress structure/no-linter-config."""
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 88\n")
    src = tmp_path / "app.py"
    src.write_text("pass\n")
    rules = StructureRules()
    diags = rules.check_project(str(tmp_path), [str(src)])
    assert not any(d.rule == "structure/no-linter-config" for d in diags)
