"""Badge and CI workflow generation."""

from __future__ import annotations

import urllib.parse


def generate_badge(score: int, label: str) -> str:
    """Generate shields.io badge markdown."""
    if score >= 90:
        color = "brightgreen"
    elif score >= 75:
        color = "green"
    elif score >= 50:
        color = "yellow"
    else:
        color = "red"

    score_text = urllib.parse.quote(f"{score}/100", safe="")
    return f"![pycodegate score](https://img.shields.io/badge/pycodegate-{score_text}-{color})"


def generate_ci_workflow() -> str:
    """Generate GitHub Actions workflow YAML for auto-updating badge."""
    return """name: Py Gate Score
on:
  push:
    branches: [main]

permissions:
  contents: write

jobs:
  score:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv tool install pycodegate
      - name: Run pycodegate
        run: |
          SCORE=$(pycodegate . --score)
          BADGE=$(pycodegate . --badge)
          # Update badge in README
          sed -i "s|!\\[pycodegate score\\](.*)|${BADGE}|" README.md
      - name: Commit badge update
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git diff --quiet README.md || (git add README.md && git commit -m "chore: update pycodegate score badge" && git push)
"""
