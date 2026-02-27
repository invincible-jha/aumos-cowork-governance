"""Test that the 3-line quickstart API works for aumos-cowork-governance."""
from __future__ import annotations


def test_quickstart_import() -> None:
    from aumos_cowork_governance import CoworkGovernor

    governor = CoworkGovernor()
    assert governor is not None


def test_quickstart_evaluate() -> None:
    from aumos_cowork_governance import CoworkGovernor

    governor = CoworkGovernor()
    result = governor.evaluate({"action": "file_read", "path": "/data.csv"})
    assert result is not None


def test_quickstart_default_policy_allows() -> None:
    from aumos_cowork_governance import CoworkGovernor

    governor = CoworkGovernor()
    result = governor.evaluate({"action": "message", "content": "Hello!"})
    assert result.allowed is True


def test_quickstart_with_policy_dict() -> None:
    from aumos_cowork_governance import CoworkGovernor

    governor = CoworkGovernor(policy={"policies": []})
    result = governor.evaluate({"action": "search"})
    assert result is not None


def test_quickstart_engine_accessible() -> None:
    from aumos_cowork_governance import CoworkGovernor
    from aumos_cowork_governance.policies.engine import PolicyEngine

    governor = CoworkGovernor()
    assert isinstance(governor.engine, PolicyEngine)


def test_quickstart_repr() -> None:
    from aumos_cowork_governance import CoworkGovernor

    governor = CoworkGovernor()
    assert "CoworkGovernor" in repr(governor)
