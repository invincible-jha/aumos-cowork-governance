"""Tests for FileClassifier and ComplianceChecker."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aumos_cowork_governance.detection.classifier import (
    FileClassifier,
    SensitivityLevel,
)
from aumos_cowork_governance.detection.compliance_checker import (
    ComplianceChecker,
    ComplianceResult,
    ComplianceViolation,
    _check_restricted_in_public,
    _check_unencrypted_restricted,
    _check_pii_in_logs,
    _check_sql_injection_risk,
    _check_data_minimisation,
)


# ---------------------------------------------------------------------------
# SensitivityLevel ordering
# ---------------------------------------------------------------------------


class TestSensitivityLevelOrdering:
    def test_public_is_less_than_internal(self) -> None:
        assert SensitivityLevel.PUBLIC < SensitivityLevel.INTERNAL

    def test_internal_is_less_than_confidential(self) -> None:
        assert SensitivityLevel.INTERNAL < SensitivityLevel.CONFIDENTIAL

    def test_confidential_is_less_than_restricted(self) -> None:
        assert SensitivityLevel.CONFIDENTIAL < SensitivityLevel.RESTRICTED

    def test_restricted_is_greatest(self) -> None:
        assert SensitivityLevel.RESTRICTED >= SensitivityLevel.PUBLIC
        assert SensitivityLevel.RESTRICTED >= SensitivityLevel.INTERNAL
        assert SensitivityLevel.RESTRICTED >= SensitivityLevel.CONFIDENTIAL
        assert SensitivityLevel.RESTRICTED >= SensitivityLevel.RESTRICTED

    def test_equal_levels(self) -> None:
        assert SensitivityLevel.PUBLIC <= SensitivityLevel.PUBLIC
        assert SensitivityLevel.CONFIDENTIAL >= SensitivityLevel.CONFIDENTIAL

    def test_greater_than(self) -> None:
        assert SensitivityLevel.RESTRICTED > SensitivityLevel.INTERNAL
        assert not (SensitivityLevel.PUBLIC > SensitivityLevel.INTERNAL)


# ---------------------------------------------------------------------------
# FileClassifier — classify_path
# ---------------------------------------------------------------------------


class TestClassifyPath:
    def setup_method(self) -> None:
        self.classifier = FileClassifier()

    def test_secret_path_is_restricted(self) -> None:
        assert self.classifier.classify_path(Path("/vault/master.key")) == SensitivityLevel.RESTRICTED

    def test_pem_file_is_restricted(self) -> None:
        assert self.classifier.classify_path(Path("/certs/server.pem")) == SensitivityLevel.RESTRICTED

    def test_private_key_is_restricted(self) -> None:
        assert self.classifier.classify_path(Path("/home/user/.ssh/id_rsa")) == SensitivityLevel.RESTRICTED

    def test_credentials_path_is_restricted(self) -> None:
        assert self.classifier.classify_path(Path("/app/credentials/db.json")) == SensitivityLevel.RESTRICTED

    def test_confidential_path_is_confidential(self) -> None:
        assert self.classifier.classify_path(Path("/data/confidential/report.csv")) == SensitivityLevel.CONFIDENTIAL

    def test_hipaa_path_is_confidential(self) -> None:
        assert self.classifier.classify_path(Path("/data/hipaa/patient_records.csv")) == SensitivityLevel.CONFIDENTIAL

    def test_pii_path_is_confidential(self) -> None:
        assert self.classifier.classify_path(Path("/storage/pii/users.csv")) == SensitivityLevel.CONFIDENTIAL

    def test_internal_path_is_internal(self) -> None:
        assert self.classifier.classify_path(Path("/corp/internal/reports/q1.pdf")) == SensitivityLevel.INTERNAL

    def test_hr_path_is_internal(self) -> None:
        assert self.classifier.classify_path(Path("/data/hr/employees.csv")) == SensitivityLevel.INTERNAL

    def test_public_path_is_public(self) -> None:
        assert self.classifier.classify_path(Path("/public/website/index.html")) == SensitivityLevel.PUBLIC

    def test_random_file_is_public(self) -> None:
        assert self.classifier.classify_path(Path("/tmp/output.txt")) == SensitivityLevel.PUBLIC


# ---------------------------------------------------------------------------
# FileClassifier — classify_content
# ---------------------------------------------------------------------------


class TestClassifyContent:
    def setup_method(self) -> None:
        self.classifier = FileClassifier()

    def test_top_secret_is_restricted(self) -> None:
        assert self.classifier.classify_content("TOP SECRET classification report") == SensitivityLevel.RESTRICTED

    def test_trade_secret_is_restricted(self) -> None:
        assert self.classifier.classify_content("This document contains a trade secret.") == SensitivityLevel.RESTRICTED

    def test_confidential_keyword_is_confidential(self) -> None:
        assert self.classifier.classify_content("CONFIDENTIAL — do not share") == SensitivityLevel.CONFIDENTIAL

    def test_proprietary_keyword_is_confidential(self) -> None:
        assert self.classifier.classify_content("Proprietary algorithm description") == SensitivityLevel.CONFIDENTIAL

    def test_internal_use_only_is_internal(self) -> None:
        assert self.classifier.classify_content("Internal use only — not for external distribution") == SensitivityLevel.INTERNAL

    def test_pii_content_is_confidential(self) -> None:
        # Email address should trigger PII detection → CONFIDENTIAL
        result = self.classifier.classify_content("User email: user@example.com")
        assert result >= SensitivityLevel.CONFIDENTIAL

    def test_plain_text_is_public(self) -> None:
        assert self.classifier.classify_content("Hello, world! This is a public message.") == SensitivityLevel.PUBLIC

    def test_case_insensitive(self) -> None:
        assert self.classifier.classify_content("CONFIDENTIAL data here") == SensitivityLevel.CONFIDENTIAL


# ---------------------------------------------------------------------------
# FileClassifier — classify (combined)
# ---------------------------------------------------------------------------


class TestClassify:
    def setup_method(self) -> None:
        self.classifier = FileClassifier()

    def test_classify_with_both_signals_takes_max(self) -> None:
        # Path says INTERNAL, content says RESTRICTED → RESTRICTED wins
        path = Path("/corp/internal/notes.txt")
        content = "This document is top secret and eyes only."
        result = self.classifier.classify(path=path, content=content)
        assert result == SensitivityLevel.RESTRICTED

    def test_classify_path_only(self) -> None:
        result = self.classifier.classify(path=Path("/vault/key.pem"))
        assert result == SensitivityLevel.RESTRICTED

    def test_classify_content_only(self) -> None:
        result = self.classifier.classify(content="Confidential — do not share")
        assert result == SensitivityLevel.CONFIDENTIAL

    def test_classify_no_signals_returns_internal(self) -> None:
        result = self.classifier.classify()
        assert result == SensitivityLevel.INTERNAL

    def test_public_path_with_restricted_content(self) -> None:
        result = self.classifier.classify(
            path=Path("/tmp/report.txt"),
            content="restricted — trade secret",
        )
        assert result == SensitivityLevel.RESTRICTED


# ---------------------------------------------------------------------------
# Standalone rule functions
# ---------------------------------------------------------------------------


class TestBuiltinRuleFunctions:
    def test_restricted_in_public_triggers(self) -> None:
        # Use data containing only the "api_key" indicator (not "secret") so
        # that the first matched indicator is deterministically "api_key".
        result = _check_restricted_in_public("my api_key=abc123", "public")
        assert result is not None
        assert "api_key" in result

    def test_restricted_in_public_not_public_classification(self) -> None:
        result = _check_restricted_in_public("my api_key=secret123", "internal")
        assert result is None

    def test_restricted_in_public_empty_data(self) -> None:
        result = _check_restricted_in_public("", "public")
        assert result is None

    def test_unencrypted_restricted_triggers_for_large_data(self) -> None:
        # Data must be > 50 chars and must NOT contain any encryption markers
        # (including substrings like "encrypted" inside "unencrypted").
        data = "This is plain-text restricted data that has no protection. " * 5
        result = _check_unencrypted_restricted(data, "restricted")
        assert result is not None

    def test_unencrypted_restricted_ignores_encrypted_marker(self) -> None:
        result = _check_unencrypted_restricted("-----BEGIN ENCRYPTED-----", "restricted")
        assert result is None

    def test_unencrypted_restricted_ignores_internal_classification(self) -> None:
        result = _check_unencrypted_restricted("plain text data for internal use", "internal")
        assert result is None

    def test_pii_in_logs_email_in_public(self) -> None:
        result = _check_pii_in_logs("User email: user@example.com", "internal")
        assert result is not None

    def test_pii_in_logs_email_in_restricted_no_trigger(self) -> None:
        result = _check_pii_in_logs("User email: user@example.com", "confidential")
        assert result is None

    def test_pii_in_logs_ssn(self) -> None:
        result = _check_pii_in_logs("SSN: 123-45-6789", "internal")
        assert result is not None

    def test_sql_injection_union_select(self) -> None:
        result = _check_sql_injection_risk("SELECT * UNION SELECT password FROM users", "public")
        assert result is not None

    def test_sql_injection_drop_table(self) -> None:
        result = _check_sql_injection_risk("DROP TABLE users", "public")
        assert result is not None

    def test_sql_injection_clean_data(self) -> None:
        result = _check_sql_injection_risk("Get all users from the database", "public")
        assert result is None

    def test_data_minimisation_large_payload(self) -> None:
        large = "x" * (1_048_577)  # Exceeds 1 MiB
        result = _check_data_minimisation(large, "internal")
        assert result is not None

    def test_data_minimisation_small_payload(self) -> None:
        result = _check_data_minimisation("Hello, world!", "internal")
        assert result is None


# ---------------------------------------------------------------------------
# ComplianceChecker — check_data_handling
# ---------------------------------------------------------------------------


class TestComplianceCheckerDataHandling:
    def setup_method(self) -> None:
        self.checker = ComplianceChecker()

    def test_clean_internal_data_is_compliant(self) -> None:
        result = self.checker.check_data_handling("Hello, this is internal data.", "internal")
        assert result.compliant is True
        assert result.violations == []

    def test_sensitive_in_public_not_compliant(self) -> None:
        result = self.checker.check_data_handling("password=secret123", "public")
        assert result.compliant is False
        assert any(v.rule_id == "DH-001" for v in result.violations)

    def test_sql_injection_not_compliant(self) -> None:
        result = self.checker.check_data_handling("SELECT * UNION SELECT password FROM users", "internal")
        assert result.compliant is False
        assert any(v.rule_id == "DH-004" for v in result.violations)

    def test_email_in_public_not_compliant(self) -> None:
        result = self.checker.check_data_handling("Contact us at user@example.com", "public")
        # DH-001 or DH-003 may trigger
        assert result.compliant is False

    def test_checked_rules_count_correct(self) -> None:
        result = self.checker.check_data_handling("clean data", "internal")
        assert result.checked_rules == 5  # 5 built-in rules

    def test_compliance_violation_fields(self) -> None:
        result = self.checker.check_data_handling("SELECT * UNION SELECT 1 FROM users", "internal")
        violation = next((v for v in result.violations if v.rule_id == "DH-004"), None)
        assert violation is not None
        assert violation.severity == "critical"
        assert isinstance(violation.description, str)
        assert isinstance(violation.evidence, str)

    def test_add_custom_rule(self) -> None:
        self.checker.add_rule(
            rule_id="CUSTOM-001",
            check_fn=lambda data, cls: "blocked" if "forbidden" in data else None,
            description="Block forbidden keyword",
            severity="high",
        )
        result = self.checker.check_data_handling("This is forbidden content", "public")
        assert any(v.rule_id == "CUSTOM-001" for v in result.violations)

    def test_custom_rule_that_passes(self) -> None:
        self.checker.add_rule(
            rule_id="CUSTOM-002",
            check_fn=lambda data, cls: None,  # Never triggers
            description="Always passes",
        )
        result = self.checker.check_data_handling("anything", "internal")
        # Only check that custom rule is counted
        assert result.checked_rules == 6

    def test_rule_that_raises_exception_is_skipped(self) -> None:
        self.checker.add_rule(
            rule_id="BUGGY-001",
            check_fn=lambda data, cls: (_ for _ in ()).throw(RuntimeError("bug")),  # type: ignore[arg-type]
            description="Buggy rule",
        )
        # Should not raise — buggy rule is skipped
        result = self.checker.check_data_handling("data", "internal")
        assert isinstance(result, ComplianceResult)


# ---------------------------------------------------------------------------
# ComplianceChecker — check_retention
# ---------------------------------------------------------------------------


class TestComplianceCheckerRetention:
    def setup_method(self) -> None:
        self.checker = ComplianceChecker()

    def test_within_retention_is_compliant(self) -> None:
        created_at = datetime.now(tz=timezone.utc) - timedelta(days=30)
        result = self.checker.check_retention(created_at, retention_days=365)
        assert result.compliant is True

    def test_exceeded_retention_not_compliant(self) -> None:
        created_at = datetime.now(tz=timezone.utc) - timedelta(days=400)
        result = self.checker.check_retention(created_at, retention_days=365)
        assert result.compliant is False
        assert any(v.rule_id == "RET-001" for v in result.violations)

    def test_retention_violation_mentions_days(self) -> None:
        created_at = datetime.now(tz=timezone.utc) - timedelta(days=400)
        result = self.checker.check_retention(created_at, retention_days=365)
        evidence = result.violations[0].evidence
        assert "365" in evidence

    def test_retention_checked_rules_is_1(self) -> None:
        created_at = datetime.now(tz=timezone.utc)
        result = self.checker.check_retention(created_at, retention_days=30)
        assert result.checked_rules == 1

    def test_naive_datetime_treated_as_utc(self) -> None:
        created_at = datetime.now() - timedelta(days=10)  # No tzinfo
        result = self.checker.check_retention(created_at, retention_days=30)
        assert result.compliant is True


# ---------------------------------------------------------------------------
# ComplianceChecker — check_consent
# ---------------------------------------------------------------------------


class TestComplianceCheckerConsent:
    def setup_method(self) -> None:
        self.checker = ComplianceChecker()

    def test_marketing_email_with_consent_compliant(self) -> None:
        consents = {"marketing", "email_communications"}
        result = self.checker.check_consent("marketing_email", consents)
        assert result.compliant is True

    def test_marketing_email_missing_consent_not_compliant(self) -> None:
        consents = {"marketing"}  # Missing email_communications
        result = self.checker.check_consent("marketing_email", consents)
        assert result.compliant is False
        assert any(v.rule_id == "CON-001" for v in result.violations)

    def test_profiling_with_both_consents(self) -> None:
        consents = {"profiling", "automated_decision_making"}
        result = self.checker.check_consent("profiling", consents)
        assert result.compliant is True

    def test_third_party_transfer_requires_two_consents(self) -> None:
        consents = {"data_sharing"}  # Missing third_party_transfer
        result = self.checker.check_consent("third_party_transfer", consents)
        assert result.compliant is False

    def test_unknown_operation_always_compliant(self) -> None:
        result = self.checker.check_consent("unknown_operation", set())
        assert result.compliant is True

    def test_violation_mentions_missing_consents(self) -> None:
        result = self.checker.check_consent("data_sharing", set())
        evidence = result.violations[0].evidence
        assert "data_sharing" in evidence

    def test_analytics_with_consent(self) -> None:
        result = self.checker.check_consent("analytics", {"analytics"})
        assert result.compliant is True

    def test_consent_checked_rules_is_1(self) -> None:
        result = self.checker.check_consent("analytics", {"analytics"})
        assert result.checked_rules == 1
