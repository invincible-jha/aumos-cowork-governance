"""Policy template library for aumos-cowork-governance.

Provides seven built-in YAML governance policy templates covering PII
protection, file access control, cost limits, data classification, and
basic HIPAA, GDPR, and SOC 2 compliance starting points.
"""
from __future__ import annotations

from aumos_cowork_governance.templates.policy_templates import (
    TEMPLATES,
    get_template,
    list_templates,
    write_template,
)

__all__ = [
    "TEMPLATES",
    "get_template",
    "list_templates",
    "write_template",
]
