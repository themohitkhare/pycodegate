import json

from click.testing import CliRunner

from pycodegate import __version__
from pycodegate.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "PyCodeGate" in result.output or "pycodegate" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_scan_clean_project(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path)])
    assert result.exit_code == 0


def test_cli_score_only(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--score"])
    assert result.exit_code == 0
    score_line = result.output.strip()
    assert score_line.isdigit()


def test_cli_no_lint(tmp_path):
    (tmp_path / "app.py").write_text('eval("1+1")')
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--no-lint", "--score"])
    assert result.exit_code == 0


def test_cli_fail_on_error(tmp_path):
    (tmp_path / "app.py").write_text('eval("1+1")')
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--fail-on", "error"])
    assert result.exit_code == 1


def test_cli_fail_on_none(tmp_path):
    (tmp_path / "app.py").write_text('eval("1+1")')
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--fail-on", "none"])
    assert result.exit_code == 0


def test_cli_json_output(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    expected_keys = (
        "version",
        "path",
        "score",
        "label",
        "errors",
        "warnings",
        "elapsed_ms",
        "project",
        "diagnostics",
    )
    for key in expected_keys:
        assert key in data, f"Missing key: {key}"
    project = data["project"]
    project_keys = (
        "framework",
        "python_version",
        "package_manager",
        "test_framework",
        "source_file_count",
    )
    for key in project_keys:
        assert key in project, f"Missing project key: {key}"
    assert isinstance(data["diagnostics"], list)
    assert isinstance(data["score"], int)
    assert isinstance(data["errors"], int)
    assert isinstance(data["warnings"], int)


def test_badge_output(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--badge"])
    assert result.exit_code == 0
    assert "https://img.shields.io/badge/pycodegate-" in result.output
    assert "%2F100" in result.output  # the slash must be URL-encoded
    assert "/100-" not in result.output  # ...and never left bare


def test_min_score_pass(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    # A clean file should score high enough to pass a very low threshold
    result = runner.invoke(main, [str(tmp_path), "--min-score", "1"])
    assert result.exit_code == 0


def test_min_score_fail(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    # Require a score of 101 (impossible), so it must fail
    result = runner.invoke(main, [str(tmp_path), "--min-score", "101"])
    assert result.exit_code == 1


def test_ci_workflow(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--ci"])
    assert result.exit_code == 0
    assert "name: Py Gate Score" in result.output
    assert "pycodegate" in result.output


def test_cli_sarif_output(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--sarif"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert data["runs"][0]["tool"]["driver"]["name"] == "PyCodeGate"
