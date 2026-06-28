"""Regression tests for the audit-driven fixes (0.4.1)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from pycodegate.cli import main
from pycodegate.config import Config, load_config
from pycodegate.rules.architecture import ArchitectureRules
from pycodegate.rules.complexity import ComplexityRules
from pycodegate.rules.django import DjangoRules
from pycodegate.rules.fastapi import FastAPIRules
from pycodegate.rules.flask import FlaskRules
from pycodegate.rules.logging_rules import LoggingRules
from pycodegate.rules.sqlalchemy import SQLAlchemyRules
from pycodegate.scan import scan_project
from pycodegate.score import calculate_score
from pycodegate.types import Category, Diagnostic, Severity


# --- complexity: match/case counts ---
def test_complexity_counts_match_case():
    arms = "\n".join(f"        case {i}: x = {i}" for i in range(20))
    src = f"def f(v):\n    match v:\n{arms}\n        case _: x = -1\n"
    diags = ComplexityRules().check(src, "a.py")
    assert any(d.rule in ("high-complexity", "critical-complexity") for d in diags)


# --- architecture: elif chains are not deeper nesting ---
def test_elif_chain_not_deep_nesting():
    branches = "".join(f"    elif x == {i}:\n        pass\n" for i in range(8))
    src = f"def f(x):\n    if x == 0:\n        pass\n{branches}"
    diags = ArchitectureRules().check(src, "a.py")
    assert not any(d.rule == "no-deep-nesting" for d in diags)


def test_genuine_deep_nesting_still_flagged():
    src = (
        "def f(x):\n"
        "    for a in x:\n"
        "        for b in a:\n"
        "            with open('p') as fh:\n"
        "                while b:\n"
        "                    if b:\n"
        "                        b = 0\n"
    )
    diags = ArchitectureRules().check(src, "a.py")
    assert any(d.rule == "no-deep-nesting" for d in diags)


# --- fastapi ---
def test_fastapi_return_annotation_satisfies_response_model():
    src = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/x')\n"
        "async def h() -> dict:\n"
        "    return {}\n"
    )
    diags = FastAPIRules().check(src, "api.py")
    assert not any(d.rule == "missing-response-model" for d in diags)


def test_fastapi_ignores_non_router_decorator():
    src = "@cache.get('/x')\nasync def h():\n    return 1\n"
    diags = FastAPIRules().check(src, "api.py")
    assert diags == []


# --- django ---
def test_django_n_plus_one_suppressed_with_select_related():
    src = (
        "def v():\n"
        "    for o in Order.objects.select_related('customer').all():\n"
        "        print(o.customer.name)\n"
    )
    diags = DjangoRules().check(src, "views.py")
    assert not any(d.rule == "no-n-plus-one-query" for d in diags)


def test_django_raw_sql_requires_sql_keyword():
    src = "def f(name):\n    runner.execute('task_' + name)\n"
    diags = DjangoRules().check(src, "views.py")
    assert not any(d.rule == "no-raw-sql-injection" for d in diags)
    src2 = "def f(uid):\n    cursor.execute('SELECT * FROM u WHERE id=' + uid)\n"
    diags2 = DjangoRules().check(src2, "views.py")
    assert any(d.rule == "no-raw-sql-injection" for d in diags2)


# --- flask / sqlalchemy: f-string SQL ---
def test_flask_fstring_passed_to_execute_flagged():
    src = "def q(uid):\n    cur.execute(f'SELECT * FROM u WHERE id={uid}')\n"
    diags = FlaskRules().check(src, "app.py")
    assert any(d.rule == "no-sql-string-format" for d in diags)


def test_sqla_placeholder_free_fstring_not_flagged():
    src = "def q():\n    conn.execute(f'SELECT 1')\n"
    diags = SQLAlchemyRules().check(src, "db.py")
    assert not any(d.rule == "sqla-sql-injection" for d in diags)


# --- logging receiver narrowing + exc_info ---
def test_logging_fstring_only_on_loggers():
    bad = "def f(resp, uid):\n    resp.info(f'x {uid}')\n"
    assert not any(d.rule == "logging-fstring" for d in LoggingRules().check(bad, "a.py"))
    good = "logger = logging.getLogger(__name__)\ndef f(uid):\n    logger.info(f'x {uid}')\n"
    assert any(d.rule == "logging-fstring" for d in LoggingRules().check(good, "a.py"))


def test_logging_exc_info_variable_accepted():
    src = (
        "logger = logging.getLogger(__name__)\n"
        "def f(exc):\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        logger.error('boom', exc_info=e)\n"
    )
    assert not any(d.rule == "logging-error-no-exc-info" for d in LoggingRules().check(src, "a.py"))


# --- scoring: clamp + negative override ---
def test_negative_override_does_not_exceed_100():
    diags = [Diagnostic("a.py", "x", Severity.WARNING, Category.SECURITY, "m", "h", 1, cost=1.0)]
    score = calculate_score(diags, max_deduction_overrides={"Security": -50})
    assert score.value <= 100


# --- import gating ---
def test_library_rules_gated_by_import(tmp_path):
    # pandas-style chained indexing in a file that does NOT import pandas -> no pandas rule.
    (tmp_path / "a.py").write_text("df = make()\ndf['x']['y'] = 1\n")
    result = scan_project(str(tmp_path), Config(dead_code=False))
    assert not any(d.category == Category.PANDAS for d in result.diagnostics)


# --- robustness: non-UTF-8 file must not crash the scan ---
def test_non_utf8_file_does_not_crash(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "weird.py").write_bytes(b"x = '\xff\xfe invalid utf8'\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_bytes(b"# \xff\xfe\nassert True\n")
    result = scan_project(str(tmp_path), Config(dead_code=False))
    assert result.score.value >= 0  # completed without raising


# --- config: documented per-file-ignores alias works ---
def test_per_file_ignores_alias(tmp_path):
    (tmp_path / "pycodegate.toml").write_text(
        '[per-file-ignores]\n"legacy/*.py" = ["high-complexity"]\n'
    )
    cfg = load_config(str(tmp_path))
    assert cfg.per_file_suppress == {"legacy/*.py": ["high-complexity"]}


# --- JSON output exposes profile ---
def test_json_output_includes_profile(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="0.1.0"\n[project.scripts]\nx="x:main"\n'
    )
    (tmp_path / "app.py").write_text("x = 1\n")
    runner = CliRunner()
    result = runner.invoke(main, [str(tmp_path), "--json", "--no-dead-code"])
    payload = json.loads(result.output)
    assert "profile" in payload and payload["profile"] is not None


# --- cli profile actually filters subprocess-shell ---
def test_cli_profile_filters_subprocess_shell(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\nversion="0.1.0"\n'
        'dependencies=["click"]\n[project.scripts]\nx="x:main"\n'
    )
    (tmp_path / "app.py").write_text("import subprocess\nsubprocess.run('ls', shell=True)\n")
    result = scan_project(str(tmp_path), Config(dead_code=False))
    assert result.profile == "cli"
    assert not any(d.rule == "no-subprocess-shell" for d in result.diagnostics)
