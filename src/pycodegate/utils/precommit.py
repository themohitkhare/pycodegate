"""Pre-commit hook installer."""

from __future__ import annotations

from pathlib import Path


def install_precommit_hook(project_path: str, min_score: int = 50) -> str:
    """Install a git pre-commit hook that runs pycodegate."""
    hooks_dir = Path(project_path) / ".git" / "hooks"
    if not hooks_dir.exists():
        return "Error: not a git repository"

    hook_path = hooks_dir / "pre-commit"
    hook_content = f"""#!/bin/sh
# pycodegate pre-commit hook
SCORE=$(pycodegate . --score 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "pycodegate not found. Install with: uvx pycodegate"
    exit 0
fi
if [ "$SCORE" -lt {min_score} ]; then
    echo "pycodegate: score $SCORE is below minimum {min_score}. Fix issues before committing."
    pycodegate . 2>/dev/null
    exit 1
fi
echo "pycodegate: score $SCORE/{min_score} — passed"
"""

    # Only manage a hook we own. Never modify a foreign hook: appending our block
    # after another hook's `exit` makes it dead code, and rewriting it destroys it.
    if hook_path.exists():
        existing = hook_path.read_text()
        if "pycodegate" not in existing:
            return (
                f"A pre-commit hook already exists at {hook_path}. Leaving it untouched — "
                "add `pycodegate . --score` to it manually, or use the pre-commit framework."
            )
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)
        return f"Updated pre-commit hook at {hook_path} (min-score: {min_score})"

    hook_path.write_text(hook_content)
    hook_path.chmod(0o755)
    return f"Installed pre-commit hook at {hook_path} (min-score: {min_score})"
