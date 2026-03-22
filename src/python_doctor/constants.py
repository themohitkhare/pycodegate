"""Constants and thresholds for python-doctor."""

from python_doctor.types import Category

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
    Category.DEAD_CODE: 1,
}

# Framework categories map to their parent category for scoring
FRAMEWORK_CATEGORY_MAP: dict = {
    Category.DJANGO: Category.SECURITY,
    Category.FASTAPI: Category.CORRECTNESS,
    Category.FLASK: Category.SECURITY,
}
