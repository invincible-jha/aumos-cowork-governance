"""PII pattern collections by jurisdiction."""
from __future__ import annotations

from aumos_cowork_governance.detection.patterns.common import COMMON_PATTERNS
from aumos_cowork_governance.detection.patterns.eu import EU_PATTERNS
from aumos_cowork_governance.detection.patterns.india import INDIA_PATTERNS
from aumos_cowork_governance.detection.patterns.us import US_PATTERNS

__all__ = [
    "COMMON_PATTERNS",
    "EU_PATTERNS",
    "INDIA_PATTERNS",
    "US_PATTERNS",
]
