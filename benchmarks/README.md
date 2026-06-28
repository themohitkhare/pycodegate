# Precision benchmark

A quality gate is only useful if it stays quiet on good code. This benchmark runs
PyCodeGate against the source of widely used, idiomatic PyPI packages and reports
the findings per rule. A rule that fires heavily here is a false-positive suspect.

```bash
python benchmarks/run_corpus.py                 # default corpus, lint only
python benchmarks/run_corpus.py --with-dead-code
python benchmarks/run_corpus.py flask django    # a custom package list
```

Source distributions are fetched from PyPI into `benchmarks/.corpus/` (git-ignored)
and cached between runs. No GitHub access is required.

## How to read the output

The per-package table shows the score and finding count; the tail aggregates
findings by rule across the whole corpus. When triaging a rule with a high count,
open a few of the flagged files — if the pattern is idiomatic and correct, the rule
needs to be narrowed, suppressed in the relevant context (e.g. test files), or
removed. Genuine issues (a 100-branch function, `verify=False`) should remain.

The precision fixes derived from this benchmark are locked in by
`tests/test_precision.py` and the per-rule unit tests under `tests/rules/`.
