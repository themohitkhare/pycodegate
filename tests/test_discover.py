from pathlib import Path

from python_doctor.discover import discover_project


def _write_pyproject(tmp_path: Path, content: str):
    (tmp_path / "pyproject.toml").write_text(content)


def _write_requirements(tmp_path: Path, content: str):
    (tmp_path / "requirements.txt").write_text(content)


def test_detect_django_from_pyproject(tmp_path):
    _write_pyproject(tmp_path, """
[project]
dependencies = ["django>=4.2"]
""")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.framework == "django"


def test_detect_fastapi_from_requirements(tmp_path):
    _write_requirements(tmp_path, "fastapi>=0.100\nuvicorn\n")
    (tmp_path / "main.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.framework == "fastapi"


def test_detect_flask_from_pyproject(tmp_path):
    _write_pyproject(tmp_path, """
[project]
dependencies = ["flask>=3.0"]
""")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.framework == "flask"


def test_detect_no_framework(tmp_path):
    (tmp_path / "script.py").write_text("print('hello')")
    info = discover_project(str(tmp_path))
    assert info.framework is None


def test_detect_uv_package_manager(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.package_manager == "uv"


def test_detect_poetry_package_manager(tmp_path):
    (tmp_path / "poetry.lock").write_text("")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.package_manager == "poetry"


def test_detect_pytest(tmp_path):
    _write_pyproject(tmp_path, """
[project]
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0"]
""")
    (tmp_path / "app.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.test_framework == "pytest"


def test_source_file_count(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.py").write_text("x = 2")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "c.py").write_text("x = 3")
    info = discover_project(str(tmp_path))
    assert info.source_file_count == 3


def test_ignores_venv_and_node_modules(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "site.py").write_text("x = 1")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.py").write_text("x = 1")
    info = discover_project(str(tmp_path))
    assert info.source_file_count == 1
