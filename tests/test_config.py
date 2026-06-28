from pycodegate.config import load_config


def test_default_config_when_no_file(tmp_path):
    cfg = load_config(str(tmp_path))
    assert cfg.lint is True
    assert cfg.dead_code is True
    assert cfg.verbose is False
    assert cfg.ignore_rules == []
    assert cfg.ignore_files == []


def test_load_from_pycodegate_toml(tmp_path):
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
    (tmp_path / "pycodegate.toml").write_text(toml_content)
    cfg = load_config(str(tmp_path))
    assert cfg.dead_code is False
    assert cfg.verbose is True
    assert cfg.ignore_rules == ["no-eval", "no-exec"]
    assert cfg.ignore_files == ["migrations/*"]
    assert cfg.fail_on == "error"


def test_load_from_pyproject_toml(tmp_path):
    toml_content = """
[tool.pycodegate]
lint = true
dead_code = true
verbose = false
fail_on = "none"

[tool.pycodegate.ignore]
rules = ["no-pickle"]
files = []
"""
    (tmp_path / "pyproject.toml").write_text(toml_content)
    cfg = load_config(str(tmp_path))
    assert cfg.ignore_rules == ["no-pickle"]
    assert cfg.fail_on == "none"


def test_pycodegate_toml_takes_precedence(tmp_path):
    (tmp_path / "pycodegate.toml").write_text("""
[options]
verbose = true
""")
    (tmp_path / "pyproject.toml").write_text("""
[tool.pycodegate]
verbose = false
""")
    cfg = load_config(str(tmp_path))
    assert cfg.verbose is True


def test_per_file_suppress_from_toml(tmp_path):
    toml_content = """[options]
lint = true

[per-file-suppress]
"tests/*" = ["no-bare-except"]
"""
    (tmp_path / "pycodegate.toml").write_text(toml_content)
    config = load_config(str(tmp_path))
    assert config.per_file_suppress == {"tests/*": ["no-bare-except"]}


def test_max_deduction_from_toml(tmp_path):
    toml_content = """[options]
lint = true

[max-deduction]
security = 15
structure = 5
"""
    (tmp_path / "pycodegate.toml").write_text(toml_content)
    config = load_config(str(tmp_path))
    assert config.max_deduction == {"security": 15, "structure": 5}


def test_max_deduction_from_scoring_section(tmp_path):
    # The documented location is the [scoring] table.
    toml_content = """[scoring]
max-deduction.Security = 20
max-deduction.Structure = 0
"""
    (tmp_path / "pycodegate.toml").write_text(toml_content)
    config = load_config(str(tmp_path))
    assert config.max_deduction == {"Security": 20, "Structure": 0}


def test_max_deduction_from_scoring_section_pyproject(tmp_path):
    pyproject = """[tool.pycodegate.scoring]
"max-deduction" = { Security = 20, "Dead Code" = 0 }
"""
    (tmp_path / "pyproject.toml").write_text(pyproject)
    config = load_config(str(tmp_path))
    assert config.max_deduction == {"Security": 20, "Dead Code": 0}


def test_per_file_suppress_from_pyproject(tmp_path):
    pyproject = """[tool.pycodegate.per-file-suppress]
"tests/*" = ["no-bare-except"]

[tool.pycodegate.max-deduction]
security = 10
"""
    (tmp_path / "pyproject.toml").write_text(pyproject)
    config = load_config(str(tmp_path))
    assert config.per_file_suppress == {"tests/*": ["no-bare-except"]}
    assert config.max_deduction == {"security": 10}
