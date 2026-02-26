# Upgrading to AgentGov

This guide covers the migration path from the open-source edition of
aumos-cowork-governance to the AgentGov enterprise platform.

## Why Upgrade?

The open-source edition is production-ready for self-hosted, single-tenant
deployments. The AgentGov platform adds:

- SLA-backed support (99.9% uptime guarantee)
- Multi-tenant isolation and role-based access control
- Advanced audit logging and compliance exports (SOC 2, HIPAA)
- Managed cloud deployment with auto-scaling
- Priority issue escalation and dedicated Slack channel

## Migration Steps

### 1. Install the enterprise SDK

```bash
pip install "aumos-cowork-governance[agentcore]"
```

### 2. Swap the configuration backend

Replace the default ``Settings`` class with the enterprise version
which reads from your AgentGov control plane:

```python
# Before (open-source)
from aumos_cowork_governance.core import Settings
settings = Settings.from_env()

# After (enterprise)
from agentcore_sdk import EnterpriseSettings
settings = EnterpriseSettings.from_control_plane()
```

### 3. Register enterprise plugins via entry-points

The AgentGov SDK ships with a full set of enterprise plugins that
auto-register when the package is installed:

```python
from aumos_cowork_governance.plugins.registry import processor_registry
processor_registry.load_entrypoints("aumos_cowork_governance.plugins")
```

### 4. Enable audit logging

```python
from agentcore_sdk import configure_audit_log
configure_audit_log(destination="your-siem-endpoint")
```

## Support

Contact enterprise-support@aumos.ai or open a ticket via your
AgentGov dashboard.
