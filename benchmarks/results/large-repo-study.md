# Is PyCodeGate useful on large Python repositories?

**Use it to focus a pull-request review. Be selective about which rules can block a merge.** PyCodeGate v0.5.0 found concrete improvements in established codebases, including shared mutable defaults in Transformers test fixtures and duplicated formatting logic in scikit-learn. It also recommended changes that would defeat intentional pandas tests. A blanket `--fail-on error` gate would have rejected all five release checkouts.

## What the scans found

On November 19, 2026, we scanned five tagged Git repositories spanning web development, scientific computing and machine learning. PyCodeGate discovered **10,113 Python files** and emitted **19,487 findings**, including **1,001 errors**. “Error” is the scanner's severity. A maintainer still needs to decide what to change.

| Upstream release | Discovered Python files | Errors | Warnings | Score / 100 |
| --- | ---: | ---: | ---: | ---: |
| [Django 6.1.3](https://github.com/django/django/tree/f16e25dcb9fe55734ba4ea2b00ac34405b7df74a) | 2,603 | 83 | 905 | 32 |
| [pandas 3.1.1](https://github.com/pandas-dev/pandas/tree/3dcc6fbbbebc5e85dd3e83fe49b382ca7735cae1) | 1,544 | 298 | 2,947 | 20 |
| [NumPy 2.5.5](https://github.com/numpy/numpy/tree/afcbc6d21a88a7b59c5bfe115198e24ed51b3dae) | 492 | 118 | 1,218 | 27 |
| [scikit-learn 1.9.1](https://github.com/scikit-learn/scikit-learn/tree/866c0f51e7560ef0303cbcc5f159df5382ea9e3f) | 752 | 62 | 1,905 | 26 |
| [Transformers 5.23.0](https://github.com/huggingface/transformers/tree/52b080b6416a7897e2af90febeb4dfad22b84d19) | 4,722 | 440 | 11,511 | 19 |

Architecture and complexity checks produced **14,219 findings (73.0%)**. One rule, `no-god-function`, flagged **7,747** functions by length. Transformers accounted for 61.3% of all findings, so its coding conventions carry considerable weight in the totals. The score caps deductions per category and does not normalize by file count. A score threshold offers little guidance on which of thousands of findings to fix first. [Counts by project, severity, category and rule](large-repo-scan.json)

## What was worth acting on?

We reviewed five errors and five warnings per project against the source at the scanned commit. **18 of the 50** suggested a concrete change, **20** gave misleading guidance, and **12** needed maintainer judgment.

| Source review | Errors reviewed | Warnings reviewed | Total |
| --- | ---: | ---: | ---: |
| Actionable change identified | 13 | 5 | 18 |
| False alarm or clearly inapplicable advice | 11 | 9 | 20 |
| Depends on project context | 1 | 11 | 12 |
| **Total reviewed** | **25** | **25** | **50** |

- **A concrete improvement.** A Transformers test fixture stores its default configuration dictionaries on the instance. Multiple instances constructed with omitted arguments therefore share state. Creating fresh dictionaries per instance would isolate the fixtures. This is a preventive fix. [Fixture constructor](https://github.com/huggingface/transformers/blob/52b080b6416a7897e2af90febeb4dfad22b84d19/tests/models/cohere2_vision/test_modeling_cohere2_vision.py#L53)
- **A useful refactor lead.** In scikit-learn, the flagged pretty-printer handles recursion and depth and accumulates readability flags in two similar branches. A reviewer can assess a specific extraction that removes duplicated logic. [Formatting branches](https://github.com/scikit-learn/scikit-learn/blob/866c0f51e7560ef0303cbcc5f159df5382ea9e3f/sklearn/utils/_pprint.py#L356)
- **A rule that should be narrowed.** All five sampled pandas errors flagged tests that deliberately inspect the return value of an inplace operation. Three check for `None`. Two check that `replace(inplace=True)` returns the original object in this release. Discarding the return as the diagnostic advises would lose test coverage. [Example identity assertion](https://github.com/pandas-dev/pandas/blob/3dcc6fbbbebc5e85dd3e83fe49b382ca7735cae1/pandas/tests/series/methods/test_replace.py#L733)
- **A misleading size threshold.** NumPy's `vdot` dispatch wrapper triggered a 60-line function warning. It has one executable return statement. The public API docstring accounts for nearly the whole span. [NumPy wrapper](https://github.com/numpy/numpy/blob/afcbc6d21a88a7b59c5bfe115198e24ed51b3dae/numpy/_core/multiarray.py#L847)

Generated code offers a practical way to reduce review volume. In Transformers, **1,215 of 4,722** discovered files carried the project's generation marker in the first 1,200 bytes. Those files produced **4,825 findings (40.4%)**, including 2,184 star-import warnings. A warning on an emitted file may belong at the generator. In one sampled case the file header explicitly says that regeneration overwrites manual edits. [Generated module header](https://github.com/huggingface/transformers/blob/52b080b6416a7897e2af90febeb4dfad22b84d19/src/transformers/models/afmoe/modeling_afmoe.py#L1)

## How to use these results

For an existing repository, start by reviewing findings on changed files and choose blocking rules for which the team agrees on the fix. Two separate controls using the released CLI illustrate the difference a clear policy makes. A changed function with a shared list default exited 1 under `--fail-on error` and exited 0 after switching to a fresh list per call. A configured domain-layer import boundary likewise exited 1 for a forbidden dependency and 0 for an allowed import. The `--diff` option selects changed **files**, so older findings in those files can also appear.

For PyCodeGate development, the strongest leads here are to account for method-specific inplace semantics, measure executable function bodies separately from docstrings, and surface generated-file findings separately from their source templates. The sample provides regression cases for testing those changes.

## Method and reproduction

We ran the released scanner at `edcf65b` on CPython 3.12.16 with `--json --no-dead-code` and the optional dependency auditor disabled. The runner checks out and verifies each Git commit, leaves submodules uninitialized, and analyzes source without importing or running upstream code. File counts reflect PyCodeGate's normal discovery and exclusions. They measure the Python portion of these projects. [Repository pins](../large_repo_pins.json) · [Runner](../run_large_repos.py)

Within each project and severity, we selected the five diagnostics with the lowest SHA-256 hashes of their normalized JSON. Codex reviewed the selected source locations. An actionable label requires a specific preventive fix or refactoring opportunity. A false-positive label requires an inaccurate diagnosis or clearly inapplicable advice. A context-dependent label means the pattern exists and the benefit of changing it depends on project policy or algorithm design. The judgments are ours and have no upstream maintainer endorsement. [All 50 judgments and source references](large-repo-review.json)

Each project and severity contributed equally to the review, although their finding counts differed greatly. The sample supports the examples above. Estimating overall precision, missed defects, or performance specifically on AI-generated changes would require a different study.

```bash
uv run --frozen --python 3.12.16 python benchmarks/run_large_repos.py \
  --workspace /tmp/pycodegate-upstream-study --output /tmp/pycodegate-upstream-summary.json
uv run --frozen --python 3.12.16 python benchmarks/check_large_repo_review.py \
  /tmp/pycodegate-upstream-study/scans
```
