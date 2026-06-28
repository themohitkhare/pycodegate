"""Structure rules: project-level health checks."""

from __future__ import annotations

import ast
from pathlib import Path

from pycodegate.types import Category, Diagnostic, Severity


def _has_annotated_param(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if any parameter (of any kind, excluding self/cls) carries an annotation."""
    args = node.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg:
        params.append(args.vararg)
    if args.kwarg:
        params.append(args.kwarg)
    return any(p.annotation for p in params if p.arg not in ("self", "cls"))


class StructureRules:
    """Project-level structure health checks."""

    def check_project(self, project_path: str, source_files: list[str]) -> list[Diagnostic]:
        """Run all structure checks on the project."""
        path = Path(project_path)
        diags: list[Diagnostic] = []

        diags.extend(self._check_large_files(source_files))
        diags.extend(self._check_tests(path, source_files))
        diags.extend(self._check_readme(path))
        diags.extend(self._check_license(path))
        diags.extend(self._check_gitignore(path))
        diags.extend(self._check_linter_config(path))
        diags.extend(self._check_type_checker(path))
        diags.extend(self._check_type_coverage(source_files))

        return diags

    def _check_large_files(self, files: list[str]) -> list[Diagnostic]:
        diags = []
        for f in files:
            try:
                line_count = len(Path(f).read_text().splitlines())
                if line_count > 1000:
                    diags.append(
                        Diagnostic(
                            file_path=f,
                            rule="structure/large-file",
                            severity=Severity.WARNING,
                            category=Category.STRUCTURE,
                            message=f"File is {line_count} lines (max 1000)",
                            help="Split into smaller, focused modules",
                            line=1,
                            cost=1.0,
                        )
                    )
            except (OSError, UnicodeDecodeError):
                pass
        return diags

    @staticmethod
    def _count_lines(files: list[str]) -> int:
        """Return total line count across *files*, ignoring unreadable/non-UTF-8 files."""
        return sum(
            len(Path(f).read_text(encoding="utf-8", errors="ignore").splitlines())
            for f in files
            if Path(f).exists()
        )

    def _check_test_ratio(
        self, path: Path, test_files: list[str], src_files: list[str]
    ) -> list[Diagnostic]:
        """Return a diagnostic if the test-to-source line ratio is too low."""
        test_lines = self._count_lines(test_files)
        src_lines = self._count_lines(src_files)
        if src_lines == 0:
            return []
        ratio = test_lines / src_lines
        if ratio < 0.1:
            cost = 2.0
        elif ratio < 0.3:
            cost = 1.0
        else:
            return []
        return [
            Diagnostic(
                file_path=str(path),
                rule="structure/low-test-ratio",
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                message=f"Test:source ratio is {ratio:.1f} (< 0.3)",
                help="Add more tests to improve coverage",
                line=0,
                cost=cost,
            )
        ]

    def _check_tests(self, path: Path, source_files: list[str]) -> list[Diagnostic]:
        test_files = [
            f
            for f in source_files
            if Path(f).stem.startswith("test_") or Path(f).stem.endswith("_test") or "/tests/" in f
        ]
        src_files = [f for f in source_files if f not in test_files]

        if not test_files:
            return [
                Diagnostic(
                    file_path=str(path),
                    rule="structure/no-tests",
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    message="No test files found",
                    help="Add tests to improve code reliability",
                    line=0,
                    cost=3.0,
                )
            ]

        return self._check_test_ratio(path, test_files, src_files)

    def _check_readme(self, path: Path) -> list[Diagnostic]:
        for name in ["README.md", "README.rst", "README", "readme.md"]:
            if (path / name).exists():
                return []
        return [
            Diagnostic(
                file_path=str(path),
                rule="structure/no-readme",
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                message="No README file found",
                help="Add a README.md describing your project",
                line=0,
                cost=1.0,
            )
        ]

    def _check_license(self, path: Path) -> list[Diagnostic]:
        for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"]:
            if (path / name).exists():
                return []
        return [
            Diagnostic(
                file_path=str(path),
                rule="structure/no-license",
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                message="No LICENSE file found",
                help="Add a LICENSE file to clarify usage terms",
                line=0,
                cost=0.5,
            )
        ]

    def _check_gitignore(self, path: Path) -> list[Diagnostic]:
        if (path / ".gitignore").exists():
            return []
        return [
            Diagnostic(
                file_path=str(path),
                rule="structure/no-gitignore",
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                message="No .gitignore file found",
                help="Add a .gitignore to exclude build artifacts and secrets",
                line=0,
                cost=0.5,
            )
        ]

    def _check_linter_config(self, path: Path) -> list[Diagnostic]:
        # Check for ruff, flake8, pylint configs
        if (path / "ruff.toml").exists() or (path / ".flake8").exists():
            return []
        pyproject = path / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text()
            if "[tool.ruff]" in content or "[tool.flake8]" in content or "[tool.pylint]" in content:
                return []
        return [
            Diagnostic(
                file_path=str(path),
                rule="structure/no-linter-config",
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                message="No linter configuration found",
                help="Add ruff or flake8 config to enforce code style",
                line=0,
                cost=0.5,
            )
        ]

    def _check_type_checker(self, path: Path) -> list[Diagnostic]:
        if (
            (path / "mypy.ini").exists()
            or (path / "pyrightconfig.json").exists()
            or (path / ".mypy.ini").exists()
        ):
            return []
        pyproject = path / "pyproject.toml"
        if pyproject.exists():
            content = pyproject.read_text()
            if "[tool.mypy]" in content or "[tool.pyright]" in content:
                return []
        return [
            Diagnostic(
                file_path=str(path),
                rule="structure/no-type-checker",
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                message="No type checker configuration found",
                help="Add mypy or pyright config for type safety",
                line=0,
                cost=0.5,
            )
        ]

    def _check_type_coverage(self, source_files: list[str]) -> list[Diagnostic]:
        """Check what fraction of functions have type annotations."""
        total_funcs = 0
        annotated_funcs = 0
        for f in source_files:
            # Skip test files
            if Path(f).stem.startswith("test_") or Path(f).stem.endswith("_test") or "/tests/" in f:
                continue
            try:
                tree = ast.parse(Path(f).read_text())
            except (SyntaxError, OSError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    total_funcs += 1
                    if node.returns or _has_annotated_param(node):
                        annotated_funcs += 1

        if total_funcs > 0:
            coverage = annotated_funcs / total_funcs
            if coverage < 0.5:
                return [
                    Diagnostic(
                        file_path="project",
                        rule="structure/low-type-coverage",
                        severity=Severity.WARNING,
                        category=Category.STRUCTURE,
                        message=f"Only {coverage:.0%} of functions have type annotations (< 50%)",
                        help="Add return type and parameter annotations to functions",
                        line=0,
                        cost=1.0,
                    )
                ]
        return []
