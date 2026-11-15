import pytest
from click.testing import CliRunner

from pycodegate.cli import main
from pycodegate.config import Config, load_config
from pycodegate.rules.import_boundaries import ImportBoundaryRules
from pycodegate.scan import scan_project
from pycodegate.types import ImportBoundary, Severity


@pytest.mark.parametrize(
    "source",
    [
        "import app.infrastructure.database as database",
        "from app.infrastructure import database",
        "from app import infrastructure",
        "from ..infrastructure import database",
        "from .. import infrastructure",
        "def load():\n    import app.infrastructure.database",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import app.infrastructure",
    ],
)
@pytest.mark.parametrize("source_root", ["", "src/"])
def test_forbidden_imports(tmp_path, source, source_root):
    filename = tmp_path / f"{source_root}app/domain/service.py"
    rules = ImportBoundaryRules(
        str(tmp_path),
        [ImportBoundary(("**/domain/*.py",), ("app.infrastructure",), "Use a domain port")],
    )
    diagnostics = rules.check(source, str(filename))
    assert len(diagnostics) == 1
    assert diagnostics[0].rule == "imports/boundary"
    assert diagnostics[0].severity == Severity.ERROR
    assert diagnostics[0].help == "Use a domain port"


@pytest.mark.parametrize(
    "source,filename",
    [
        ("import app.infrastructure_extra", "app/domain/service.py"),
        ("from app import domain", "app/domain/service.py"),
        ("from . import infrastructure", "app/domain/service.py"),
        ("import app.infrastructure", "app/api/service.py"),
        ("text = 'import app.infrastructure'", "app/domain/service.py"),
        ("broken syntax!", "app/domain/service.py"),
    ],
)
def test_allowed_code(tmp_path, source, filename):
    rules = ImportBoundaryRules(
        str(tmp_path),
        [ImportBoundary(("app/domain/*.py",), ("app.infrastructure",), "Use a port")],
    )
    assert rules.check(source, str(tmp_path / filename)) == []


@pytest.mark.parametrize("config_file", ["pycodegate.toml", "pyproject.toml"])
@pytest.mark.parametrize("output_flag", ["--json", "--sarif"])
def test_configured_boundary_blocks_cli_and_can_be_suppressed(tmp_path, config_file, output_flag):
    prefix = "tool.pycodegate." if config_file == "pyproject.toml" else ""
    (tmp_path / config_file).write_text(
        f'[[{prefix}import-boundaries]]\nfiles = ["*.py"]\n'
        'forbidden = ["requests"]\nmessage = "Use the shared HTTP client"\n'
    )
    (tmp_path / "service.py").write_text("import requests\n")
    config = load_config(str(tmp_path))
    assert config.import_boundaries == [
        ImportBoundary(("*.py",), ("requests",), "Use the shared HTTP client")
    ]
    result = CliRunner().invoke(main, [str(tmp_path), output_flag, "--fail-on", "error"])
    assert result.exit_code == 1
    assert "imports/boundary" in result.output
    config.per_file_suppress = {"service.py": ["imports/boundary"]}
    assert not any(
        diagnostic.rule == "imports/boundary"
        for diagnostic in scan_project(str(tmp_path), config).diagnostics
    )


def test_boundaries_are_opt_in_and_follow_lint_setting(tmp_path):
    (tmp_path / "service.py").write_text("import requests\n")
    for config in [
        Config(),
        Config(lint=False, import_boundaries=[ImportBoundary(("*.py",), ("requests",), "No")]),
    ]:
        assert not any(
            diagnostic.rule == "imports/boundary"
            for diagnostic in scan_project(str(tmp_path), config).diagnostics
        )


@pytest.mark.parametrize(
    "setting",
    [
        'files = "*.py"\nforbidden = ["requests"]',
        'files = ["*.py"]\nforbidden = []',
        'files = ["*.py"]\nforbidden = [42]',
        'files = ["*.py"]\nforbidden = ["requests.*"]',
        'files = ["*.py"]\nforbidden = ["requests"]\nmessage = ""',
    ],
)
def test_invalid_boundary_is_rejected(tmp_path, setting):
    (tmp_path / "pycodegate.toml").write_text(f"[[import-boundaries]]\n{setting}\n")
    with pytest.raises(ValueError, match="Import boundary"):
        load_config(str(tmp_path))
    result = CliRunner().invoke(main, [str(tmp_path)])
    assert result.exit_code == 1
    assert result.output.startswith("Error: Import boundary")


def test_nested_import_location_and_package_init(tmp_path):
    rules = ImportBoundaryRules(
        str(tmp_path),
        [ImportBoundary(("src/app/domain/*.py",), ("app.infrastructure",), "Use a port")],
    )
    diagnostics = rules.check(
        "def load():\n    from ..infrastructure import database\n",
        str(tmp_path / "src/app/domain/__init__.py"),
    )
    assert diagnostics[0].line == 2
    assert diagnostics[0].column == 4


def test_outside_root_and_invalid_relative_import_are_ignored(tmp_path):
    rules = ImportBoundaryRules(
        str(tmp_path), [ImportBoundary(("*.py",), ("requests",), "Use a client")]
    )
    assert rules.check("import requests", str(tmp_path.parent / "outside.py")) == []
    assert rules.check("from .. import requests", str(tmp_path / "module.py")) == []


@pytest.mark.parametrize("contents", ['import-boundaries = "invalid"', "import-boundaries = [42]"])
def test_invalid_boundary_table_is_rejected(tmp_path, contents):
    (tmp_path / "pycodegate.toml").write_text(contents)
    with pytest.raises(ValueError, match="[Ii]mport[- ]boundar"):
        load_config(str(tmp_path))
