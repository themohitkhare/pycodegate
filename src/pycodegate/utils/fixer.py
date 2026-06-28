"""Auto-fix utilities using ruff."""

from __future__ import annotations

import re
import subprocess


def run_ruff_fix(project_path: str) -> int:
    """Run ``ruff check --fix`` on *project_path* and return the number of fixes applied.

    Returns the number of fixes applied, 0 if no fixes were made (or on a
    subprocess/OS error), or -1 if ruff is not installed.
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
    except (OSError, subprocess.SubprocessError):
        return 0

    # Modern ruff prints "Fixed 3 errors." or "3 fixed, …"; accept both.
    output = result.stdout + result.stderr
    match = re.search(r"(\d+) fixed", output) or re.search(r"Fixed (\d+)", output)
    if match:
        return int(match.group(1))
    return 0
