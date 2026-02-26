"""Built-in YAML policy templates for common governance scenarios.

Seven templates are bundled covering PII protection, file access control,
cost limits, data classification enforcement, and basic HIPAA / GDPR / SOC 2
compliance starting points.

Example
-------
>>> from aumos_cowork_governance.templates.policy_templates import get_template, list_templates
>>> list_templates()
['cost_limits', 'data_classification', 'file_access_control', 'gdpr_basic', 'hipaa_basic', 'pii_protection', 'soc2_basic']
>>> yaml_str = get_template("pii_protection")
>>> print(yaml_str[:80])
"""
from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Template definitions
# ---------------------------------------------------------------------------

_PII_PROTECTION = """\
# PII Protection Policy Template
# ---------------------------------
# Blocks agent actions that would expose personally identifiable information
# to unauthorised outputs such as logs, external APIs, or public endpoints.

policies:
  - name: block-pii-in-output
    action: block
    message: >
      Action blocked: the content contains PII (personal identifiable
      information) and must not be written to unencrypted outputs or
      shared with third parties.
    conditions:
      - field: content
        operator: contains_pii
        value: null
    notify:
      - security-team@example.com

  - name: warn-pii-in-log
    action: warn
    message: >
      Warning: PII detected in log payload. Consider redacting before
      forwarding to external logging infrastructure.
    conditions:
      - field: destination
        operator: equals
        value: log
      - field: content
        operator: contains_pii
        value: null
    condition_logic: AND
    notify:
      - compliance@example.com

  - name: require-approval-pii-export
    action: approve
    message: >
      PII export to external system requires human approval.
    conditions:
      - field: action
        operator: equals
        value: export
      - field: content
        operator: contains_pii
        value: null
    condition_logic: AND
"""

_FILE_ACCESS_CONTROL = """\
# File Access Control Policy Template
# -------------------------------------
# Restricts agent access to sensitive filesystem paths and file types.

policies:
  - name: block-system-paths
    action: block
    message: >
      Access to system-level paths (/etc, /proc, /sys, Windows registry)
      is not permitted for agent operations.
    conditions:
      - field: path
        operator: matches
        value: "^(/etc/|/proc/|/sys/|/dev/|C:\\\\Windows\\\\System32)"

  - name: block-credential-files
    action: block
    message: >
      Access to credential and key files is forbidden. Use a secrets manager
      instead of reading key material from the filesystem.
    conditions:
      - field: path
        operator: matches
        value: "(\\.pem|\\.key|\\.p12|\\.pfx|\\.jks|id_rsa|id_ed25519|\\.htpasswd|\\.env)$"

  - name: warn-confidential-directory
    action: warn
    message: >
      File operation on a confidential directory. Ensure this is
      authorised and log the access for audit purposes.
    conditions:
      - field: path
        operator: matches
        value: "(?i)(confidential|restricted|hipaa|phi|pii)"

  - name: log-file-reads
    action: log
    message: File read operation recorded for audit.
    conditions:
      - field: action
        operator: equals
        value: file_read

  - name: approve-file-delete
    action: approve
    message: File deletion operations require human approval.
    conditions:
      - field: action
        operator: in_list
        value: ["file_delete", "file_move", "directory_delete"]
"""

_COST_LIMITS = """\
# Cost Limits Policy Template
# ----------------------------
# Warns and blocks agent operations that exceed per-action or per-session
# token/cost thresholds to prevent runaway API spend.

policies:
  - name: warn-high-token-usage
    action: warn
    message: >
      This operation will consume a large number of tokens. Consider
      summarising input or breaking the task into smaller chunks.
    conditions:
      - field: tokens
        operator: greater_than
        value: 8000

  - name: block-excessive-token-usage
    action: block
    message: >
      Action blocked: token count exceeds the per-action limit of 32,000.
      Split the task into smaller operations.
    conditions:
      - field: tokens
        operator: greater_than
        value: 32000

  - name: warn-high-cost-action
    action: warn
    message: >
      Estimated action cost exceeds $0.50. Review the operation before
      proceeding to avoid unexpected spend.
    conditions:
      - field: cost_usd
        operator: greater_than
        value: 0.50

  - name: block-excessive-cost-action
    action: block
    message: >
      Action blocked: estimated cost exceeds the $2.00 per-action limit.
      Require explicit human approval for high-cost operations.
    conditions:
      - field: cost_usd
        operator: greater_than
        value: 2.00

  - name: approve-expensive-bulk-operation
    action: approve
    message: >
      High-cost bulk operation requires human approval before execution.
    conditions:
      - field: operation_type
        operator: equals
        value: bulk
      - field: cost_usd
        operator: greater_than
        value: 1.00
    condition_logic: AND
"""

_DATA_CLASSIFICATION = """\
# Data Classification Enforcement Policy Template
# -------------------------------------------------
# Ensures agents handle data according to its sensitivity classification.

policies:
  - name: block-restricted-to-public
    action: block
    message: >
      Data classified as RESTRICTED cannot be written to public outputs,
      shared externally, or stored in unencrypted form.
    conditions:
      - field: data_classification
        operator: equals
        value: RESTRICTED
      - field: destination
        operator: in_list
        value: ["public", "external_api", "unencrypted_storage"]
    condition_logic: AND

  - name: require-approval-confidential-export
    action: approve
    message: >
      Exporting CONFIDENTIAL data requires human approval. Ensure the
      recipient has signed a data processing agreement.
    conditions:
      - field: data_classification
        operator: equals
        value: CONFIDENTIAL
      - field: action
        operator: equals
        value: export
    condition_logic: AND

  - name: warn-internal-to-external
    action: warn
    message: >
      INTERNAL data is being sent to an external destination. Confirm
      this is authorised by a data-sharing agreement.
    conditions:
      - field: data_classification
        operator: equals
        value: INTERNAL
      - field: destination
        operator: equals
        value: external
    condition_logic: AND

  - name: log-all-restricted-access
    action: log
    message: Access to RESTRICTED data recorded.
    conditions:
      - field: data_classification
        operator: equals
        value: RESTRICTED
"""

_HIPAA_BASIC = """\
# HIPAA Basic Compliance Policy Template
# ----------------------------------------
# A starting-point set of policies for HIPAA-covered environments.
# Review with your compliance officer before production use.

policies:
  - name: block-phi-in-unencrypted-output
    action: block
    message: >
      HIPAA VIOLATION: Protected Health Information (PHI) must not be
      written to unencrypted outputs. Encrypt all PHI at rest and in transit.
    conditions:
      - field: data_classification
        operator: in_list
        value: ["phi", "PHI", "hipaa"]
      - field: encrypted
        operator: equals
        value: false
    condition_logic: AND

  - name: block-phi-external-transfer
    action: block
    message: >
      HIPAA VIOLATION: PHI cannot be transferred to external parties
      without a signed Business Associate Agreement (BAA).
    conditions:
      - field: data_classification
        operator: in_list
        value: ["phi", "PHI"]
      - field: destination
        operator: equals
        value: external
      - field: baa_signed
        operator: not_equals
        value: true
    condition_logic: AND

  - name: require-approval-phi-access
    action: approve
    message: >
      Access to PHI requires approval and will be logged for HIPAA
      audit purposes.
    conditions:
      - field: data_classification
        operator: in_list
        value: ["phi", "PHI", "hipaa"]

  - name: log-all-phi-access
    action: log
    message: PHI access event recorded for HIPAA audit trail.
    conditions:
      - field: data_classification
        operator: in_list
        value: ["phi", "PHI", "hipaa"]

  - name: warn-phi-in-logs
    action: warn
    message: >
      PHI detected in log payload. HIPAA requires PHI to be excluded
      from application logs unless properly de-identified.
    conditions:
      - field: destination
        operator: equals
        value: log
      - field: content
        operator: contains_pii
        value: null
    condition_logic: AND
    notify:
      - hipaa-officer@example.com
"""

_GDPR_BASIC = """\
# GDPR Basic Compliance Policy Template
# ---------------------------------------
# A starting-point set of policies for GDPR-regulated environments.
# Review with your Data Protection Officer (DPO) before production use.

policies:
  - name: block-personal-data-without-consent
    action: block
    message: >
      GDPR VIOLATION: Processing personal data requires a valid legal basis
      (consent, legitimate interest, contract, etc.). Verify consent before
      proceeding.
    conditions:
      - field: consent_verified
        operator: not_equals
        value: true
      - field: data_classification
        operator: in_list
        value: ["personal", "pii", "PII", "gdpr"]
    condition_logic: AND

  - name: block-cross-border-transfer-no-safeguard
    action: block
    message: >
      GDPR VIOLATION: Cross-border transfer of personal data to a non-
      adequate country requires appropriate safeguards (SCCs, BCRs, etc.).
    conditions:
      - field: transfer_type
        operator: equals
        value: cross_border
      - field: safeguard_in_place
        operator: not_equals
        value: true
    condition_logic: AND

  - name: require-approval-data-subject-request
    action: approve
    message: >
      Data subject rights request (erasure, access, portability) requires
      human review to ensure GDPR Article 17/20 compliance.
    conditions:
      - field: operation
        operator: in_list
        value: ["data_erasure", "data_access", "data_portability"]

  - name: warn-retention-approaching
    action: warn
    message: >
      Data is approaching its maximum retention period. Schedule deletion
      or anonymisation to comply with GDPR data minimisation requirements.
    conditions:
      - field: retention_warning
        operator: equals
        value: true

  - name: log-personal-data-processing
    action: log
    message: Personal data processing event recorded for GDPR accountability.
    conditions:
      - field: data_classification
        operator: in_list
        value: ["personal", "pii", "PII", "gdpr"]

  - name: block-pii-in-public-output
    action: block
    message: >
      GDPR VIOLATION: Personal data must not be exposed in public outputs.
      Apply pseudonymisation or anonymisation before publishing.
    conditions:
      - field: destination
        operator: equals
        value: public
      - field: content
        operator: contains_pii
        value: null
    condition_logic: AND
    notify:
      - dpo@example.com
"""

_SOC2_BASIC = """\
# SOC 2 Basic Compliance Policy Template
# ----------------------------------------
# A starting-point set of policies aligned with SOC 2 Trust Service Criteria.
# Review with your security team before production use.

policies:
  - name: block-unauthenticated-access
    action: block
    message: >
      SOC 2 CC6.1: All access to sensitive systems must be authenticated.
      Unauthenticated requests are not permitted.
    conditions:
      - field: authenticated
        operator: not_equals
        value: true
      - field: data_classification
        operator: in_list
        value: ["restricted", "confidential", "RESTRICTED", "CONFIDENTIAL"]
    condition_logic: AND

  - name: block-unauthorised-data-access
    action: block
    message: >
      SOC 2 CC6.3: Access to sensitive data must be authorised and
      role-appropriate. This operation is outside the agent's permitted scope.
    conditions:
      - field: authorised
        operator: not_equals
        value: true
      - field: data_classification
        operator: in_list
        value: ["restricted", "RESTRICTED"]
    condition_logic: AND

  - name: require-approval-privileged-operation
    action: approve
    message: >
      SOC 2 CC6.8: Privileged operations require human approval and will
      be logged with full context for the audit trail.
    conditions:
      - field: privileged
        operator: equals
        value: true

  - name: log-all-system-access
    action: log
    message: System access event logged for SOC 2 CC7.2 monitoring.
    conditions:
      - field: action
        operator: not_in_list
        value: ["ping", "health_check"]

  - name: warn-anomalous-volume
    action: warn
    message: >
      SOC 2 CC7.1: Anomalous operation volume detected. Investigate for
      potential security incident or misconfigured automation.
    conditions:
      - field: volume_anomaly
        operator: equals
        value: true
    notify:
      - security-ops@example.com

  - name: block-change-without-approval
    action: block
    message: >
      SOC 2 CC8.1: Infrastructure and configuration changes require an
      approved change request. Submit a change ticket before proceeding.
    conditions:
      - field: change_type
        operator: in_list
        value: ["infrastructure", "configuration", "deployment"]
      - field: change_ticket_approved
        operator: not_equals
        value: true
    condition_logic: AND
"""

# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

TEMPLATES: dict[str, str] = {
    "pii_protection": _PII_PROTECTION,
    "file_access_control": _FILE_ACCESS_CONTROL,
    "cost_limits": _COST_LIMITS,
    "data_classification": _DATA_CLASSIFICATION,
    "hipaa_basic": _HIPAA_BASIC,
    "gdpr_basic": _GDPR_BASIC,
    "soc2_basic": _SOC2_BASIC,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_template(name: str) -> str:
    """Return the YAML string for a built-in policy template.

    Parameters
    ----------
    name:
        The template identifier.  See :func:`list_templates` for available
        names.

    Returns
    -------
    str
        The YAML policy template string, ready to write to a file or pass
        to :meth:`~aumos_cowork_governance.policies.engine.PolicyEngine.load_from_dict`.

    Raises
    ------
    KeyError
        If no template with the given name is registered.

    Example
    -------
    >>> yaml_str = get_template("pii_protection")
    >>> yaml_str.startswith("# PII")
    True
    """
    if name not in TEMPLATES:
        available = ", ".join(sorted(TEMPLATES))
        raise KeyError(
            f"Template {name!r} not found. Available templates: {available}."
        )
    return TEMPLATES[name]


def list_templates() -> list[str]:
    """Return a sorted list of all built-in template names.

    Returns
    -------
    list[str]
        Template names in alphabetical order.

    Example
    -------
    >>> list_templates()
    ['cost_limits', 'data_classification', 'file_access_control', 'gdpr_basic', 'hipaa_basic', 'pii_protection', 'soc2_basic']
    """
    return sorted(TEMPLATES)


def write_template(name: str, output_path: Path) -> Path:
    """Write a built-in policy template to a file.

    Parent directories are created automatically if they do not exist.

    Parameters
    ----------
    name:
        The template identifier.  See :func:`list_templates`.
    output_path:
        Destination file path.  Typically ends in ``.yaml`` or ``.yml``.

    Returns
    -------
    Path
        The absolute path of the written file.

    Raises
    ------
    KeyError
        If no template with the given name is registered.

    Example
    -------
    >>> from pathlib import Path
    >>> written = write_template("gdpr_basic", Path("/tmp/gdpr.yaml"))
    >>> written.exists()
    True
    """
    content = get_template(name)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path.resolve()
