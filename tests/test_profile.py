"""Tests for project profile detection."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from pycodegate.profile import PROFILES, Profile, detect_profile


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    return tmp_path


def _write_pyproject(tmp_path: Path, content: str) -> None:
    (tmp_path / "pyproject.toml").write_text(textwrap.dedent(content))


def _write_requirements(tmp_path: Path, deps: list[str]) -> None:
    (tmp_path / "requirements.txt").write_text("\n".join(deps) + "\n")


class TestDetectWebProfile:
    def test_detect_web_profile_flask(self, tmp_project: Path) -> None:
        _write_requirements(tmp_project, ["flask>=2.0", "gunicorn"])
        profile = detect_profile(str(tmp_project))
        assert profile.name == "web"

    def test_detect_web_profile_django(self, tmp_project: Path) -> None:
        _write_pyproject(
            tmp_project,
            """\
            [project]
            dependencies = ["django>=4.0"]
            """,
        )
        profile = detect_profile(str(tmp_project))
        assert profile.name == "web"

    def test_detect_web_profile_fastapi(self, tmp_project: Path) -> None:
        _write_requirements(tmp_project, ["fastapi", "uvicorn"])
        profile = detect_profile(str(tmp_project))
        assert profile.name == "web"


class TestDetectCliProfile:
    def test_detect_cli_profile_click(self, tmp_project: Path) -> None:
        _write_requirements(tmp_project, ["click>=8.0"])
        profile = detect_profile(str(tmp_project))
        assert profile.name == "cli"

    def test_detect_cli_profile_typer(self, tmp_project: Path) -> None:
        _write_pyproject(
            tmp_project,
            """\
            [project]
            dependencies = ["typer"]
            """,
        )
        profile = detect_profile(str(tmp_project))
        assert profile.name == "cli"

    def test_detect_cli_profile_with_scripts(self, tmp_project: Path) -> None:
        _write_pyproject(
            tmp_project,
            """\
            [project]
            dependencies = []

            [project.scripts]
            my-tool = "mypackage.cli:main"

            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"
            """,
        )
        profile = detect_profile(str(tmp_project))
        assert profile.name == "cli"


class TestDetectLibraryProfile:
    def test_detect_library_profile(self, tmp_project: Path) -> None:
        _write_pyproject(
            tmp_project,
            """\
            [project]
            dependencies = ["requests"]

            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"
            """,
        )
        profile = detect_profile(str(tmp_project))
        assert profile.name == "library"

    def test_detect_library_profile_no_scripts(self, tmp_project: Path) -> None:
        _write_pyproject(
            tmp_project,
            """\
            [project]
            dependencies = []

            [build-system]
            requires = ["setuptools"]
            build-backend = "setuptools.build_meta"
            """,
        )
        profile = detect_profile(str(tmp_project))
        assert profile.name == "library"


class TestDetectScriptProfile:
    def test_detect_script_profile(self, tmp_project: Path) -> None:
        # No __init__.py, a few .py files at root level
        for i in range(3):
            (tmp_project / f"script{i}.py").write_text("# script\n")
        profile = detect_profile(str(tmp_project))
        assert profile.name == "script"

    def test_detect_script_profile_at_limit(self, tmp_project: Path) -> None:
        for i in range(5):
            (tmp_project / f"script{i}.py").write_text("# script\n")
        profile = detect_profile(str(tmp_project))
        assert profile.name == "script"

    def test_not_script_profile_too_many_files(self, tmp_project: Path) -> None:
        for i in range(6):
            (tmp_project / f"script{i}.py").write_text("# script\n")
        # With no pyproject/requirements and no __init__.py but >5 files → library
        profile = detect_profile(str(tmp_project))
        assert profile.name == "library"


class TestProfileAttributes:
    def test_cli_profile_suppressed_rules(self) -> None:
        cli = PROFILES["cli"]
        # These must be the IDs the rules actually emit, or suppression does nothing.
        assert "no-os-system" in cli.suppressed_rules
        assert "no-subprocess-shell" in cli.suppressed_rules

    def test_script_profile_max_deduction(self) -> None:
        script = PROFILES["script"]
        assert "Structure" in script.max_deduction_overrides
        assert script.max_deduction_overrides["Structure"] == 5

    def test_cli_profile_max_deduction(self) -> None:
        cli = PROFILES["cli"]
        assert "Security" in cli.max_deduction_overrides
        assert cli.max_deduction_overrides["Security"] == 15

    def test_web_profile_no_suppressions(self) -> None:
        web = PROFILES["web"]
        assert len(web.suppressed_rules) == 0

    def test_library_profile_no_suppressions(self) -> None:
        library = PROFILES["library"]
        assert len(library.suppressed_rules) == 0

    def test_profiles_are_frozen(self) -> None:
        profile = PROFILES["cli"]
        assert isinstance(profile, Profile)
        with pytest.raises((AttributeError, TypeError)):
            profile.name = "other"  # type: ignore[misc]
