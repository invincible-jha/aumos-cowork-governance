#!/usr/bin/env python3
"""Example: PII Detection and Redaction

Demonstrates detecting PII in agent outputs, classifying file
sensitivity, and redacting sensitive content.

Usage:
    python examples/03_pii_detection.py

Requirements:
    pip install aumos-cowork-governance
"""
from __future__ import annotations

import aumos_cowork_governance as gov
from aumos_cowork_governance import (
    ComplianceChecker,
    FileClassifier,
    PiiDetector,
    PiiRedactor,
    SensitivityLevel,
)


def main() -> None:
    print(f"aumos-cowork-governance version: {gov.__version__}")

    # Step 1: PII detection
    detector = PiiDetector()
    texts = [
        "Please contact John Smith at john.smith@example.com for details.",
        "The patient's SSN is 123-45-6789 and DOB is 01/15/1980.",
        "Revenue increased by 18% in Q3 with no personal data involved.",
        "Card number 4111-1111-1111-1111 was declined at checkout.",
    ]

    print("PII Detection:")
    for text in texts:
        matches = detector.detect(text)
        if matches:
            types = [m.pii_type for m in matches]
            print(f"  FOUND {types}: '{text[:55]}'")
        else:
            print(f"  CLEAN: '{text[:55]}'")

    # Step 2: PII redaction
    redactor = PiiRedactor()
    sensitive_text = ("Contact Alice Brown at alice@company.com "
                      "or call +1-555-234-5678 for support.")
    redacted = redactor.redact(sensitive_text)
    print(f"\nOriginal: {sensitive_text}")
    print(f"Redacted: {redacted}")

    # Step 3: File sensitivity classification
    classifier = FileClassifier()
    files = [
        {"name": "quarterly_report.pdf", "content_sample": "Q3 revenue grew 18%"},
        {"name": "patient_records.csv", "content_sample": "patient_id,ssn,diagnosis"},
        {"name": "deployment_keys.env", "content_sample": "API_KEY=sk-live-xyz123"},
        {"name": "meeting_notes.txt", "content_sample": "Discussed roadmap priorities"},
    ]

    print("\nFile sensitivity classification:")
    for file_info in files:
        level: SensitivityLevel = classifier.classify(
            filename=str(file_info["name"]),
            content_sample=str(file_info["content_sample"]),
        )
        print(f"  [{level.value}] {file_info['name']}")

    # Step 4: Compliance check
    checker = ComplianceChecker()
    agent_output = ("User email: bob@example.com — processing request. "
                    "No medical data included.")
    compliance = checker.check(text=agent_output, domain="general")
    print(f"\nCompliance check: passed={compliance.passed}")
    for violation in compliance.violations:
        print(f"  Violation: [{violation.rule_id}] {violation.description[:60]}")


if __name__ == "__main__":
    main()
