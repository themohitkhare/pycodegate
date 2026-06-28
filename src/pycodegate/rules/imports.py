"""Import rules: circular dependency detection."""

from __future__ import annotations

import ast
import os
from collections import defaultdict
from pathlib import Path

from pycodegate.types import Category, Diagnostic, Severity


class ImportsRules:
    """Project-level import analysis."""

    def check_project(self, project_path: str, source_files: list[str]) -> list[Diagnostic]:
        """Detect circular imports across the project."""
        return self._check_circular_imports(project_path, source_files)

    def _collect_imports_for_module(
        self, filepath: str, root: str, graph: dict[str, set[str]], file_map: dict[str, str]
    ) -> None:
        """Parse *filepath* and populate *graph* and *file_map* in-place."""
        try:
            source = Path(filepath).read_text()
            tree = ast.parse(source)
        except (SyntaxError, OSError, UnicodeDecodeError):
            return

        module_name = self._file_to_module(filepath, root)
        if not module_name:
            return
        file_map[module_name] = filepath

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    graph[module_name].add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                graph[module_name].add(node.module)

    def _detect_cycles(
        self,
        graph: dict[str, set[str]],
        file_map: dict[str, str],
    ) -> list[Diagnostic]:
        """Return diagnostics for every direct A↔B cycle in *graph*."""
        diags: list[Diagnostic] = []
        seen_pairs: set[tuple[str, str]] = set()

        for mod_a, imports in graph.items():
            for mod_b in imports:
                if mod_b not in graph or mod_a not in graph[mod_b]:
                    continue
                if self._is_parent_child(mod_a, mod_b):
                    continue
                pair = tuple(sorted([mod_a, mod_b]))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                diags.append(
                    Diagnostic(
                        file_path=file_map.get(mod_a, mod_a),
                        rule="imports/circular",
                        severity=Severity.ERROR,
                        category=Category.IMPORTS,
                        message=f"Circular import between '{mod_a}' and '{mod_b}'",
                        help="Break the cycle by moving shared code to a third module",
                        line=1,
                        cost=3.0,
                    )
                )

        return diags

    @staticmethod
    def _is_parent_child(mod_a: str, mod_b: str) -> bool:
        """True if one module is a parent package of the other.

        A package ``__init__`` importing from its own submodule (and that submodule
        importing back from the package) is the standard facade pattern, which Python
        resolves fine — not a real circular-import bug.
        """
        return mod_a.startswith(f"{mod_b}.") or mod_b.startswith(f"{mod_a}.")

    def _check_circular_imports(
        self, project_path: str, source_files: list[str]
    ) -> list[Diagnostic]:
        # Build import graph: module_name -> set of imported module_names
        graph: dict[str, set[str]] = defaultdict(set)
        file_map: dict[str, str] = {}  # module_name -> file_path

        root = str(Path(project_path).resolve())

        for filepath in source_files:
            self._collect_imports_for_module(filepath, root, graph, file_map)

        return self._detect_cycles(graph, file_map)

    def _file_to_module(self, filepath: str, root: str) -> str | None:
        """Convert a file path to a dotted module name."""
        try:
            rel = os.path.relpath(filepath, root)
        except ValueError:
            return None

        # Remove .py extension
        if rel.endswith(".py"):
            rel = rel[:-3]
        else:
            return None

        # Remove __init__ suffix
        if rel.endswith("__init__"):
            rel = rel[:-9].rstrip(os.sep)

        if not rel:
            return None

        # Convert path separators to dots
        return rel.replace(os.sep, ".").replace("/", ".")
