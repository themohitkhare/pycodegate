"""Auto-fix utilities using ruff."""

from __future__ import annotations

import re
import subprocess


def run_ruff_fix(project_path: str) -> int:
    """Run ``ruff check --fix`` on *project_path* and return the number of fixes applied.

    Returns 0 if ruff is not installed or if no fixes were made.
    Raises no exceptions — all subprocess errors are caught gracefully.
    """
    try:
        result = subprocess.run(
            ["ruff", "check", "--fix", project_path],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        # ruff is not installed
        return -1
    except Exception:
        return 0

    # ruff prints something like "Fixed 3 errors." to stdout or stderr
    output = result.stdout + result.stderr
    match = re.search(r"Fixed (\d+)", output)
    if match:
        return int(match.group(1))
    return 0
