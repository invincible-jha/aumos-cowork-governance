#!/usr/bin/env python3
"""Example: Agent Constitution and Voting

Demonstrates defining a multi-agent constitution, enforcing
constraints, and resolving conflicts via voting mechanisms.

Usage:
    python examples/05_constitution_voting.py

Requirements:
    pip install aumos-cowork-governance
"""
from __future__ import annotations

import aumos_cowork_governance as gov
from aumos_cowork_governance import (
    AgentAction,
    ActionType,
    Conflict,
    ConflictResolver,
    ConflictStrategy,
    Constitution,
    ConstitutionEnforcer,
    Constraint,
    DeliberationEngine,
    MajorityVote,
    Permission,
    RoleDefinition,
    Vote,
    VoteResult,
    VotingConfig,
    VotingMethod,
    WeightedVote,
    get_mechanism,
)


def main() -> None:
    print(f"aumos-cowork-governance version: {gov.__version__}")

    # Step 1: Define a constitution with roles and constraints
    constitution = Constitution(
        name="multi-agent-workspace",
        roles=[
            RoleDefinition(role="admin", permissions=[
                Permission(action=ActionType.READ, resource="*"),
                Permission(action=ActionType.WRITE, resource="*"),
                Permission(action=ActionType.DELETE, resource="/tmp/*"),
            ]),
            RoleDefinition(role="analyst", permissions=[
                Permission(action=ActionType.READ, resource="/data/*"),
                Permission(action=ActionType.WRITE, resource="/results/*"),
            ]),
            RoleDefinition(role="viewer", permissions=[
                Permission(action=ActionType.READ, resource="/reports/*"),
            ]),
        ],
        constraints=[
            Constraint(name="no-external-write",
                       description="Agents cannot write to external endpoints.",
                       rule="action.type == WRITE and action.resource.startswith('http')"),
            Constraint(name="no-bulk-delete",
                       description="Bulk deletes require admin role.",
                       rule="action.type == DELETE and not agent.role == 'admin'"),
        ],
    )

    # Step 2: Enforce the constitution
    enforcer = ConstitutionEnforcer(constitution=constitution)
    actions = [
        AgentAction(agent_id="agent-alice", role="analyst",
                    action_type=ActionType.READ, resource="/data/q3.csv"),
        AgentAction(agent_id="agent-bob", role="analyst",
                    action_type=ActionType.WRITE, resource="/tmp/output.json"),
        AgentAction(agent_id="agent-carol", role="viewer",
                    action_type=ActionType.DELETE, resource="/reports/old.pdf"),
    ]

    print("Constitution enforcement:")
    for action in actions:
        result = enforcer.enforce(action)
        icon = "ALLOW" if result.allowed else "DENY"
        print(f"  [{icon}] {action.agent_id} ({action.role}): "
              f"{action.action_type.value} {action.resource}")

    # Step 3: Resolve conflicts via majority voting
    conflict = Conflict(
        conflict_id="conf-001",
        description="Agents disagree on deleting stale data.",
        options=["delete-all", "archive", "keep"],
    )

    vote_config = VotingConfig(method=VotingMethod.MAJORITY, quorum=0.6)
    mechanism = get_mechanism(vote_config)

    votes = [
        Vote(voter_id="agent-1", option="delete-all"),
        Vote(voter_id="agent-2", option="archive"),
        Vote(voter_id="agent-3", option="archive"),
        Vote(voter_id="agent-4", option="archive"),
        Vote(voter_id="agent-5", option="keep"),
    ]

    vote_result: VoteResult = mechanism.tally(conflict=conflict, votes=votes)
    print(f"\nConflict '{conflict.conflict_id}' vote result:")
    print(f"  Winner: {vote_result.winner}")
    print(f"  Tally: {vote_result.tally}")
    print(f"  Quorum met: {vote_result.quorum_met}")


if __name__ == "__main__":
    main()
