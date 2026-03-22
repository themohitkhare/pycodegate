
from python_doctor.config import load_config


def test_default_config_when_no_file(tmp_path):
    cfg = load_config(str(tmp_path))
    assert cfg.lint is True
    assert cfg.dead_code is True
    assert cfg.verbose is False
    assert cfg.ignore_rules == []
    assert cfg.ignore_files == []


def test_load_from_python_doctor_toml(tmp_path):
    toml_content = """
[ignore]
rules = ["no-eval", "no-exec"]
files = ["migrations/*"]

[options]
lint = true
dead_code = false
verbose = true
fail_on = "error"
"""
    (tmp_path / "python-doctor.toml").write_text(toml_content)
    cfg = load_config(str(tmp_path))
    assert cfg.dead_code is False
    assert cfg.verbose is True
    assert cfg.ignore_rules == ["no-eval", "no-exec"]
    assert cfg.ignore_files == ["migrations/*"]
    assert cfg.fail_on == "error"


def test_load_from_pyproject_toml(tmp_path):
    toml_content = """
[tool.python-doctor]
lint = true
dead_code = true
verbose = false
fail_on = "none"

[tool.python-doctor.ignore]
rules = ["no-pickle"]
files = []
"""
    (tmp_path / "pyproject.toml").write_text(toml_content)
    cfg = load_config(str(tmp_path))
    assert cfg.ignore_rules == ["no-pickle"]
    assert cfg.fail_on == "none"


def test_python_doctor_toml_takes_precedence(tmp_path):
    (tmp_path / "python-doctor.toml").write_text("""
[options]
verbose = true
""")
    (tmp_path / "pyproject.toml").write_text("""
[tool.python-doctor]
verbose = false
""")
    cfg = load_config(str(tmp_path))
    assert cfg.verbose is True
