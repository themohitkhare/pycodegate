"""Constants and thresholds for pycodegate."""

from pycodegate.types import Category

# Score thresholds
SCORE_GREAT = 75
SCORE_NEEDS_WORK = 50

# Labels
LABEL_EXCELLENT = "Excellent"
LABEL_GREAT = "Great"
LABEL_NEEDS_WORK = "Needs work"
LABEL_CRITICAL = "Critical"

# Category weights for budget-based scoring
CATEGORY_WEIGHTS: dict = {
    Category.SECURITY: 5,
    Category.CORRECTNESS: 4,
    Category.COMPLEXITY: 3,
    Category.ARCHITECTURE: 3,
    Category.PERFORMANCE: 2,
    Category.STRUCTURE: 2,
    Category.IMPORTS: 1,
    Category.DEPENDENCIES: 1,
    Category.DEAD_CODE: 1,
}

# Rules suppressed in test files: idiomatic in tests, noise as findings.
# Asserts are the pytest idiom; tests are long, deeply nested, take many fixtures,
# and legitimately contain fixture "secrets", weak hashes, and pickle round-trips.
RULES_SUPPRESSED_IN_TESTS: frozenset[str] = frozenset(
    {
        "no-assert-in-production",
        "no-god-function",
        "no-giant-module",
        "no-deep-nesting",
        "too-many-arguments",
        "high-complexity",
        "critical-complexity",
        "structure/large-file",
        "no-hardcoded-secret",
        "no-weak-hash",
        "no-pickle-load",
        "no-string-concat-in-loop",
    }
)

# Framework categories map to their parent category for scoring
FRAMEWORK_CATEGORY_MAP: dict = {
    Category.DJANGO: Category.SECURITY,
    Category.FASTAPI: Category.CORRECTNESS,
    Category.FLASK: Category.SECURITY,
    Category.PYDANTIC: Category.CORRECTNESS,
    Category.SQLALCHEMY: Category.SECURITY,
    Category.CELERY: Category.CORRECTNESS,
    Category.REQUESTS: Category.SECURITY,
    Category.LOGGING: Category.CORRECTNESS,
    Category.PANDAS: Category.CORRECTNESS,
    Category.PYTEST: Category.CORRECTNESS,
    Category.NUMPY: Category.CORRECTNESS,
}
