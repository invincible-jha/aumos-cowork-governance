"""Compliance rule checker for governance policy enforcement.

Evaluates data-handling operations against configurable compliance rules
covering classification, retention, and consent requirements.  Rules are
modelled as callable predicates so that enterprise teams can inject domain-
specific logic without forking the library.

Example
-------
>>> checker = ComplianceChecker()
>>> result = checker.check_data_handling("SELECT * FROM users", "restricted")
>>> result.compliant
False
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class ComplianceViolation:
    """A single compliance rule violation.

    Attributes
    ----------
    rule_id:
        Unique identifier for the rule that was violated.
    description:
        Human-readable description of what the rule checks.
    severity:
        One of ``"low"``, ``"medium"``, ``"high"``, or ``"critical"``.
    evidence:
        Excerpt or explanation of why the rule was triggered.
    """

    rule_id: str
    description: str
    severity: str
    evidence: str


@dataclass
class ComplianceResult:
    """Aggregate result of running compliance rules against an operation.

    Attributes
    ----------
    compliant:
        ``True`` when no violations were found.
    violations:
        List of individual rule violations detected.
    checked_rules:
        Total number of rules evaluated (including those that passed).
    """

    compliant: bool
    violations: list[ComplianceViolation]
    checked_rules: int


# ---------------------------------------------------------------------------
# Internal rule descriptor
# ---------------------------------------------------------------------------

@dataclass
class _RuleDescriptor:
    rule_id: str
    description: str
    severity: str
    check_fn: Callable[..., str | None]


# ---------------------------------------------------------------------------
# Built-in rule check functions
# ---------------------------------------------------------------------------

def _check_restricted_in_public(data: str, classification: str) -> str | None:
    """Detect restricted data being treated as public."""
    if classification.lower() == "public" and len(data) > 0:
        sensitive_indicators = [
            "ssn", "social security", "credit card", "password", "secret",
            "private key", "bearer ", "api_key", "apikey",
        ]
        lower_data = data.lower()
        for indicator in sensitive_indicators:
            if indicator in lower_data:
                return (
                    f"Data appears to contain sensitive content ({indicator!r}) "
                    f"but is classified as 'public'."
                )
    return None


def _check_unencrypted_restricted(data: str, classification: str) -> str | None:
    """Detect restricted data stored without encryption markers."""
    if classification.lower() in ("restricted", "confidential"):
        encryption_markers = [
            "encrypted", "cipher", "aes-", "rsa-", "-----begin",
            "enc=", "encrypted=true",
        ]
        lower_data = data.lower()
        has_encryption_marker = any(m in lower_data for m in encryption_markers)
        if not has_encryption_marker and len(data) > 50:
            return (
                f"Data classified as {classification!r} does not appear to be "
                "encrypted. Ensure at-rest encryption before processing."
            )
    return None


def _check_pii_in_logs(data: str, classification: str) -> str | None:
    """Detect PII-like patterns that should not appear in log output."""
    import re
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
    ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    if email_pattern.search(data) or ssn_pattern.search(data):
        if classification.lower() not in ("restricted", "confidential"):
            return (
                "Data contains PII patterns (email or SSN) but is not classified "
                "as 'confidential' or 'restricted'."
            )
    return None


def _check_sql_injection_risk(data: str, classification: str) -> str | None:
    """Flag data that contains SQL-injection-risk patterns."""
    import re
    sqli_pattern = re.compile(
        r"(?i)(\bUNION\b.+\bSELECT\b|\bDROP\s+TABLE\b|\bINSERT\s+INTO\b"
        r"|\bDELETE\s+FROM\b|\b--\s*$|;\s*--|\bEXEC\b\s*\()",
        re.MULTILINE,
    )
    match = sqli_pattern.search(data)
    if match:
        return (
            f"Data contains SQL injection risk pattern: {match.group()!r}. "
            "Only parameterised queries are permitted."
        )
    return None


def _check_data_minimisation(data: str, classification: str) -> str | None:
    """Flag excessively large payloads that may violate data minimisation."""
    max_bytes = 1_048_576  # 1 MiB
    if len(data.encode("utf-8", errors="replace")) > max_bytes:
        return (
            f"Data payload exceeds the 1 MiB data-minimisation limit "
            f"({len(data)} characters). Split into smaller chunks."
        )
    return None


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class ComplianceChecker:
    """Checks operations against a configurable set of compliance rules.

    Default rules cover common GDPR / SOC 2 / HIPAA-adjacent concerns:
    - Restricted data in public classification
    - Unencrypted restricted data
    - PII in incorrectly classified payloads
    - SQL injection risk patterns
    - Data minimisation limits

    Custom rules can be added via :meth:`add_rule`.

    Example
    -------
    >>> checker = ComplianceChecker()
    >>> result = checker.check_data_handling("user@example.com", "public")
    >>> result.compliant
    False
    """

    def __init__(self) -> None:
        self._rules: list[_RuleDescriptor] = [
            _RuleDescriptor(
                rule_id="DH-001",
                description="Restricted/sensitive data must not be classified as public.",
                severity="high",
                check_fn=lambda data, cls: _check_restricted_in_public(data, cls),
            ),
            _RuleDescriptor(
                rule_id="DH-002",
                description="Restricted or confidential data must have encryption markers.",
                severity="high",
                check_fn=lambda data, cls: _check_unencrypted_restricted(data, cls),
            ),
            _RuleDescriptor(
                rule_id="DH-003",
                description="PII must be classified as confidential or restricted.",
                severity="medium",
                check_fn=lambda data, cls: _check_pii_in_logs(data, cls),
            ),
            _RuleDescriptor(
                rule_id="DH-004",
                description="Data must not contain SQL injection risk patterns.",
                severity="critical",
                check_fn=lambda data, cls: _check_sql_injection_risk(data, cls),
            ),
            _RuleDescriptor(
                rule_id="DH-005",
                description="Data payloads must comply with the 1 MiB data-minimisation limit.",
                severity="low",
                check_fn=lambda data, cls: _check_data_minimisation(data, cls),
            ),
        ]

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_rule(
        self,
        rule_id: str,
        check_fn: Callable[..., str | None],
        description: str,
        severity: str = "medium",
    ) -> None:
        """Register a custom compliance rule.

        Parameters
        ----------
        rule_id:
            Unique identifier for the rule (e.g. ``"CUSTOM-001"``).
        check_fn:
            Callable with the same signature as built-in check functions.
            Receives the data string and classification string; returns a
            non-empty evidence string when the rule is violated, or
            ``None`` when compliant.
        description:
            Human-readable explanation of what the rule enforces.
        severity:
            One of ``"low"``, ``"medium"``, ``"high"``, or ``"critical"``.
        """
        self._rules.append(
            _RuleDescriptor(
                rule_id=rule_id,
                description=description,
                severity=severity,
                check_fn=check_fn,
            )
        )
        logger.debug("Registered compliance rule %r (%s)", rule_id, severity)

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def check_data_handling(
        self,
        data: str,
        classification: str = "internal",
    ) -> ComplianceResult:
        """Evaluate data against all registered data-handling rules.

        Parameters
        ----------
        data:
            The string content to evaluate (payload, query, log entry, etc.).
        classification:
            Data sensitivity label: ``"public"``, ``"internal"``,
            ``"confidential"``, or ``"restricted"``.

        Returns
        -------
        ComplianceResult
            Aggregate result including all violations found.
        """
        violations: list[ComplianceViolation] = []

        for rule in self._rules:
            try:
                evidence = rule.check_fn(data, classification)
            except Exception:
                logger.exception(
                    "Compliance rule %r raised an unexpected exception; skipping.",
                    rule.rule_id,
                )
                continue

            if evidence:
                violations.append(
                    ComplianceViolation(
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=rule.severity,
                        evidence=evidence,
                    )
                )

        return ComplianceResult(
            compliant=len(violations) == 0,
            violations=violations,
            checked_rules=len(self._rules),
        )

    def check_retention(
        self,
        created_at: datetime,
        retention_days: int,
    ) -> ComplianceResult:
        """Verify that a data item has not exceeded its retention period.

        Parameters
        ----------
        created_at:
            UTC datetime when the data record was created.
        retention_days:
            Maximum number of days the record is allowed to be retained.

        Returns
        -------
        ComplianceResult
            Compliant when the record is within its retention window.
        """
        now = datetime.now(tz=timezone.utc)
        created_utc = created_at.astimezone(timezone.utc) if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
        age_days = (now - created_utc).days

        violations: list[ComplianceViolation] = []

        if age_days > retention_days:
            violations.append(
                ComplianceViolation(
                    rule_id="RET-001",
                    description="Data must not be retained beyond its configured retention period.",
                    severity="high",
                    evidence=(
                        f"Record is {age_days} days old but the retention limit is "
                        f"{retention_days} days. It must be deleted or anonymised."
                    ),
                )
            )

        return ComplianceResult(
            compliant=len(violations) == 0,
            violations=violations,
            checked_rules=1,
        )

    def check_consent(
        self,
        operation: str,
        consents: set[str],
    ) -> ComplianceResult:
        """Verify that required consents have been granted for an operation.

        Parameters
        ----------
        operation:
            The operation being attempted.  Known operations:
            ``"marketing_email"``, ``"data_sharing"``, ``"profiling"``,
            ``"analytics"``, ``"third_party_transfer"``.
        consents:
            Set of consent labels already granted by the data subject.

        Returns
        -------
        ComplianceResult
            Compliant when all required consents for the operation are present.
        """
        _REQUIRED_CONSENTS: dict[str, set[str]] = {
            "marketing_email": {"marketing", "email_communications"},
            "data_sharing": {"data_sharing"},
            "profiling": {"profiling", "automated_decision_making"},
            "analytics": {"analytics"},
            "third_party_transfer": {"data_sharing", "third_party_transfer"},
        }

        required = _REQUIRED_CONSENTS.get(operation, set())
        missing = required - consents
        violations: list[ComplianceViolation] = []

        if missing:
            violations.append(
                ComplianceViolation(
                    rule_id="CON-001",
                    description="All required consents must be granted before performing the operation.",
                    severity="critical",
                    evidence=(
                        f"Operation {operation!r} requires consents {sorted(required)!r} "
                        f"but the following are missing: {sorted(missing)!r}."
                    ),
                )
            )

        return ComplianceResult(
            compliant=len(violations) == 0,
            violations=violations,
            checked_rules=1,
        )
