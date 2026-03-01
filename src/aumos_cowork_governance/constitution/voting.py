"""Voting mechanisms for consensus-based conflict resolution.

Provides ``Vote``, ``VoteResult``, and the ``VotingMechanism`` hierarchy
(``MajorityVote``, ``WeightedVote``, ``SupermajorityVote``) plus helper
functions for quorum and veto checking.

Example
-------
>>> from aumos_cowork_governance.constitution.voting import (
...     Vote, MajorityVote
... )
>>> from aumos_cowork_governance.constitution.schema import VotingConfig
>>> votes = [Vote("a1", "approve"), Vote("a2", "approve"), Vote("a3", "reject")]
>>> result = MajorityVote().tally(votes, VotingConfig())
>>> result.winner
'approve'
"""
from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

from aumos_cowork_governance.constitution.schema import VotingConfig, VotingMethod


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Vote:
    """A single cast vote from one participant.

    Attributes
    ----------
    voter_id:
        Unique identifier for the voter (agent ID).
    choice:
        The candidate or option the voter selects.  Use the special string
        ``"veto"`` to exercise a veto (if the voter's role is in
        ``VotingConfig.veto_roles``).
    weight:
        Numeric weight for the vote.  Used by ``WeightedVote``; ignored by
        ``MajorityVote`` (treated as 1.0).
    role:
        Role name of the voter.  Used for veto-role checking.
    timestamp:
        UTC time the vote was cast.
    """

    voter_id: str
    choice: str
    weight: float = 1.0
    role: str = ""
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class VoteResult:
    """Outcome of tallying a collection of votes.

    Attributes
    ----------
    winner:
        The winning choice, or ``None`` when there is no decisive outcome
        (quorum failure, veto, tie with status-quo tie-breaking, or
        sub-threshold supermajority).
    vote_counts:
        Mapping of choice -> accumulated vote weight (float).
    total_votes:
        Number of individual ``Vote`` objects tallied.
    quorum_met:
        Whether the quorum requirement was satisfied.
    vetoed:
        Whether the outcome was blocked by a veto.
    vetoed_by:
        Voter ID of the agent who exercised the veto, or ``None``.
    rounds_needed:
        How many deliberation rounds were required (set by
        ``DeliberationEngine``).
    details:
        Arbitrary extra context (e.g. winning fraction, tie info).
    """

    winner: str | None
    vote_counts: dict[str, float]
    total_votes: int
    quorum_met: bool
    vetoed: bool
    vetoed_by: str | None = None
    rounds_needed: int = 1
    details: dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _check_veto(
    votes: list[Vote], config: VotingConfig
) -> tuple[bool, str | None]:
    """Check whether any veto-role voter cast a ``"veto"`` choice.

    Parameters
    ----------
    votes:
        All votes submitted.
    config:
        The ``VotingConfig`` that defines which roles may veto.

    Returns
    -------
    tuple[bool, str | None]
        ``(True, voter_id)`` if a veto was exercised, ``(False, None)``
        otherwise.
    """
    for vote in votes:
        if vote.role in config.veto_roles and vote.choice == "veto":
            return True, vote.voter_id
    return False, None


def _check_quorum(
    votes: list[Vote], total_eligible: int, config: VotingConfig
) -> bool:
    """Return ``True`` when enough eligible voters participated.

    Parameters
    ----------
    votes:
        Votes actually cast.
    total_eligible:
        Total number of voters who were eligible to vote.
    config:
        The ``VotingConfig`` containing the ``quorum_fraction`` threshold.
    """
    if total_eligible == 0:
        return True  # No eligible voters — quorum trivially met.
    required = total_eligible * config.quorum_fraction
    return len(votes) >= required


def _resolve_tie(
    tied_choices: list[str], config: VotingConfig
) -> str | None:
    """Break a tie according to ``config.tie_breaking``.

    ``"random"``    — pick uniformly at random.
    ``"status_quo"``— no winner (return ``None``).
    ``"chair"``     — pick the first choice alphabetically (deterministic).
    """
    if config.tie_breaking == "random":
        return random.choice(tied_choices)
    if config.tie_breaking == "status_quo":
        return None
    # "chair" or unrecognised — first alphabetically
    return sorted(tied_choices)[0]


def _tally_weighted(votes: list[Vote]) -> dict[str, float]:
    """Accumulate vote weights per choice, skipping ``"veto"`` choices."""
    counts: dict[str, float] = {}
    for vote in votes:
        if vote.choice == "veto":
            continue
        counts[vote.choice] = counts.get(vote.choice, 0.0) + vote.weight
    return counts


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class VotingMechanism(ABC):
    """Base class for all voting algorithms."""

    @abstractmethod
    def tally(self, votes: list[Vote], config: VotingConfig) -> VoteResult:
        """Tally *votes* under *config* and return the outcome."""
        ...

    def _quorum_and_veto_check(
        self,
        votes: list[Vote],
        config: VotingConfig,
        total_eligible: int,
    ) -> VoteResult | None:
        """Shared pre-flight: veto then quorum.

        Returns a ``VoteResult`` with ``winner=None`` if either check fails,
        otherwise returns ``None`` (proceed to tallying).
        """
        # Veto takes precedence over quorum.
        vetoed, vetoed_by = _check_veto(votes, config)
        if vetoed:
            counts = _tally_weighted(votes)
            return VoteResult(
                winner=None,
                vote_counts=counts,
                total_votes=len(votes),
                quorum_met=True,
                vetoed=True,
                vetoed_by=vetoed_by,
                details={"reason": "veto"},
            )

        quorum_met = _check_quorum(votes, total_eligible, config)
        if not quorum_met:
            counts = _tally_weighted(votes)
            return VoteResult(
                winner=None,
                vote_counts=counts,
                total_votes=len(votes),
                quorum_met=False,
                vetoed=False,
                details={"reason": "quorum_not_met"},
            )
        return None


# ---------------------------------------------------------------------------
# Concrete mechanisms
# ---------------------------------------------------------------------------


class MajorityVote(VotingMechanism):
    """Simple majority: the choice with the most votes wins.

    Each vote counts as exactly 1 regardless of ``Vote.weight``.
    Ties are broken according to ``VotingConfig.tie_breaking``.
    """

    def tally(self, votes: list[Vote], config: VotingConfig) -> VoteResult:
        total_eligible = len(votes)
        pre = self._quorum_and_veto_check(votes, config, total_eligible)
        if pre is not None:
            return pre

        # Build integer counts (weight=1 for majority).
        counts: dict[str, float] = {}
        for vote in votes:
            if vote.choice == "veto":
                continue
            counts[vote.choice] = counts.get(vote.choice, 0.0) + 1.0

        if not counts:
            return VoteResult(
                winner=None,
                vote_counts=counts,
                total_votes=len(votes),
                quorum_met=True,
                vetoed=False,
                details={"reason": "no_valid_choices"},
            )

        max_count = max(counts.values())
        leaders = [c for c, v in counts.items() if v == max_count]

        if len(leaders) == 1:
            winner: str | None = leaders[0]
            details: dict[str, object] = {"winning_count": max_count}
        else:
            winner = _resolve_tie(leaders, config)
            details = {
                "tied_choices": leaders,
                "tie_breaking": config.tie_breaking,
            }

        return VoteResult(
            winner=winner,
            vote_counts=counts,
            total_votes=len(votes),
            quorum_met=True,
            vetoed=False,
            details=details,
        )


class WeightedVote(VotingMechanism):
    """Weighted majority: votes are accumulated by ``Vote.weight``.

    The choice with the highest total weight wins.  Ties are broken
    according to ``VotingConfig.tie_breaking``.
    """

    def tally(self, votes: list[Vote], config: VotingConfig) -> VoteResult:
        total_eligible = len(votes)
        pre = self._quorum_and_veto_check(votes, config, total_eligible)
        if pre is not None:
            return pre

        counts = _tally_weighted(votes)

        if not counts:
            return VoteResult(
                winner=None,
                vote_counts=counts,
                total_votes=len(votes),
                quorum_met=True,
                vetoed=False,
                details={"reason": "no_valid_choices"},
            )

        max_weight = max(counts.values())
        leaders = [c for c, w in counts.items() if w == max_weight]

        if len(leaders) == 1:
            winner: str | None = leaders[0]
            details: dict[str, object] = {"winning_weight": max_weight}
        else:
            winner = _resolve_tie(leaders, config)
            details = {
                "tied_choices": leaders,
                "tie_breaking": config.tie_breaking,
            }

        return VoteResult(
            winner=winner,
            vote_counts=counts,
            total_votes=len(votes),
            quorum_met=True,
            vetoed=False,
            details=details,
        )


class SupermajorityVote(VotingMechanism):
    """Supermajority: the winner must capture at least ``supermajority_fraction``
    of the total vote weight.

    If no candidate meets the threshold, ``winner`` is ``None`` (no decision).
    """

    def tally(self, votes: list[Vote], config: VotingConfig) -> VoteResult:
        total_eligible = len(votes)
        pre = self._quorum_and_veto_check(votes, config, total_eligible)
        if pre is not None:
            return pre

        counts = _tally_weighted(votes)

        if not counts:
            return VoteResult(
                winner=None,
                vote_counts=counts,
                total_votes=len(votes),
                quorum_met=True,
                vetoed=False,
                details={"reason": "no_valid_choices"},
            )

        total_weight = sum(counts.values())
        winner: str | None = None
        winning_fraction = 0.0

        for choice, weight in counts.items():
            fraction = weight / total_weight if total_weight > 0 else 0.0
            if fraction >= config.supermajority_fraction:
                if fraction > winning_fraction:
                    winner = choice
                    winning_fraction = fraction

        details: dict[str, object] = {
            "required_fraction": config.supermajority_fraction,
            "fractions": {
                c: w / total_weight if total_weight > 0 else 0.0
                for c, w in counts.items()
            },
        }
        if winner is None:
            details["reason"] = "below_supermajority_threshold"

        return VoteResult(
            winner=winner,
            vote_counts=counts,
            total_votes=len(votes),
            quorum_met=True,
            vetoed=False,
            details=details,
        )


# ---------------------------------------------------------------------------
# Mechanism factory
# ---------------------------------------------------------------------------


def get_mechanism(config: VotingConfig) -> VotingMechanism:
    """Return the concrete ``VotingMechanism`` for the given ``VotingConfig``.

    Parameters
    ----------
    config:
        The voting configuration whose ``method`` field selects the algorithm.

    Returns
    -------
    VotingMechanism
        An instance of the appropriate subclass.
    """
    if config.method == VotingMethod.WEIGHTED:
        return WeightedVote()
    if config.method == VotingMethod.SUPERMAJORITY:
        return SupermajorityVote()
    return MajorityVote()
