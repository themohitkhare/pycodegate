---
name: py-doctor
description: Run after making Python changes to catch issues early. Use when reviewing code, finishing a feature, or fixing bugs in a Python project.
version: 1.0.0
---

# Py Doctor

Scans your Python codebase for security, performance, correctness, and architecture issues. Outputs a 0-100 score with actionable diagnostics. Auto-detects Django, FastAPI, and Flask.

## Usage

```bash
uvx py-doctor . --verbose --diff
```

## Workflow

Run after making changes to catch issues early. Fix errors first (security, correctness), then warnings (performance, architecture). Re-run to verify the score improved.

## When to use

- After completing a feature or bug fix
- Before creating a pull request
- During code review
- When refactoring to verify nothing degraded
