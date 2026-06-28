"""Regression tests for false-positive fixes and scoring/version consistency."""

from __future__ import annotations

from pycodegate import __version__
from pycodegate.config import Config
from pycodegate.constants import CATEGORY_WEIGHTS, RULES_SUPPRESSED_IN_TESTS
from pycodegate.rules.security import SecurityRules
from pycodegate.scan import scan_project
from pycodegate.types import Category
from pycodegate.utils.is_test_file import is_test_file


def _security(source: str, filename: str = "app.py") -> list:
    return SecurityRules().check(source, filename)


def test_is_test_file():
    assert is_test_file("tests/test_thing.py")
    assert is_test_file("pkg/foo_test.py")
    assert is_test_file("conftest.py")
    assert is_test_file("tests/data/cases/weird.py")
    assert not is_test_file("pkg/module.py")
    assert not is_test_file("src/app.py")


def test_weak_hash_flagged():
    diags = _security("import hashlib\nh = hashlib.md5(b'x')\n")
    assert any(d.rule == "no-weak-hash" for d in diags)


def test_weak_hash_usedforsecurity_false_ok():
    src = "import hashlib\nh = hashlib.md5(b'x', usedforsecurity=False)\n"
    assert not any(d.rule == "no-weak-hash" for d in _security(src))


def test_hardcoded_secret_flagged():
    src = 'API_KEY = "sk-1234567890abcdef1234567890"\n'
    assert any(d.rule == "no-hardcoded-secret" for d in _security(src))


def test_hardcoded_secret_placeholder_ok():
    for value in ("your-secret-here", "changeme", "example-token-value", "xxxxxxxx"):
        src = f'API_KEY = "{value}"\n'
        assert not any(d.rule == "no-hardcoded-secret" for d in _security(src)), value


def test_dependencies_category_is_budgeted():
    assert Category.DEPENDENCIES in CATEGORY_WEIGHTS


def test_version_is_resolved():
    # Single source of truth via package metadata, not a hard-coded drift.
    assert __version__ != "0.0.0+unknown"
    assert __version__[0].isdigit()


def test_asserts_suppressed_in_test_files(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "app.py").write_text("assert something\n")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("def test_x():\n    assert result == 1\n")

    result = scan_project(str(tmp_path), Config(dead_code=False))
    asserts = [d for d in result.diagnostics if d.rule == "no-assert-in-production"]
    # The production assert is reported; the test-file assert is suppressed.
    assert any(d.file_path.endswith("pkg/app.py") for d in asserts)
    assert all(not d.file_path.endswith("test_app.py") for d in asserts)


def test_suppressed_rules_constant_nonempty():
    assert "no-assert-in-production" in RULES_SUPPRESSED_IN_TESTS
    assert "no-god-function" in RULES_SUPPRESSED_IN_TESTS
