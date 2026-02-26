"""PII detection, file classification, compliance checking, and redaction package.

Provides regex-based PII detection across multiple jurisdictions,
file sensitivity classification, compliance rule evaluation, and PII
redaction utilities.
"""
from __future__ import annotations

from aumos_cowork_governance.detection.classifier import FileClassifier, SensitivityLevel
from aumos_cowork_governance.detection.compliance_checker import (
    ComplianceChecker,
    ComplianceResult,
    ComplianceViolation,
)
from aumos_cowork_governance.detection.pii_detector import PiiDetector, PiiMatch
from aumos_cowork_governance.detection.redactor import PiiRedactor

__all__ = [
    "ComplianceChecker",
    "ComplianceResult",
    "ComplianceViolation",
    "FileClassifier",
    "PiiDetector",
    "PiiMatch",
    "PiiRedactor",
    "SensitivityLevel",
]
