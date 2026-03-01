"""Multi-round deliberation engine for consensus conflict resolution.

The ``DeliberationEngine`` wraps any ``VotingMechanism`` and implements an
iterative elimination loop:

1. Collect votes from a caller-supplied callback.
2. Tally the votes.
3. If there is a clear winner, return immediately.
4. Otherwise eliminate the lowest-voted option (instant-runoff style).
5. Repeat up to ``VotingConfig.max_rounds``.

Example
-------
>>> from aumos_cowork_governance.constitution.voting import Vote, MajorityVote
>>> from aumos_cowork_governance.constitution.deliberation import DeliberationEngine
>>> from aumos_cowork_governance.constitution.schema import VotingConfig
>>>
>>> def ballot(round_num: int, options: list[str]) -> list[Vote]:
...     return [Vote("a1", options[0]), Vote("a2", options[0])]
...
>>> engine = DeliberationEngine(MajorityVote())
>>> result = engine.run(ballot, ["approve", "reject"], VotingConfig())
>>> result.winner
'approve'
"""
from __future__ import annotations

import logging
from typing import Callable

from aumos_cowork_governance.constitution.schema import VotingConfig
from aumos_cowork_governance.constitution.voting import Vote, VoteResult, VotingMechanism

logger = logging.getLogger(__name__)


class DeliberationEngine:
    """Runs multi-round deliberation with instant-runoff elimination.

    Parameters
    ----------
    mechanism:
        The ``VotingMechanism`` used to tally each round.
    """

    def __init__(self, mechanism: VotingMechanism) -> None:
        self._mechanism = mechanism

    def run(
        self,
        votes_per_round: Callable[[int, list[str]], list[Vote]],
        options: list[str],
        config: VotingConfig,
    ) -> VoteResult:
        """Execute the deliberation loop.

        Parameters
        ----------
        votes_per_round:
            Callback called at the start of each round.  Receives
            ``(round_number: int, remaining_options: list[str])`` and
            must return a ``list[Vote]`` for that round.  Round numbers
            are 1-indexed.
        options:
            Initial list of candidate options.  Must be non-empty.
        config:
            Voting configuration, including ``max_rounds``.

        Returns
        -------
        VoteResult
            The result from the round that produced a winner (or the final
            round if ``max_rounds`` was reached with no winner).
        """
        if not options:
            return VoteResult(
                winner=None,
                vote_counts={},
                total_votes=0,
                quorum_met=False,
                vetoed=False,
                rounds_needed=0,
                details={"reason": "no_options"},
            )

        remaining_options = list(options)
        result: VoteResult | None = None

        for round_number in range(1, config.max_rounds + 1):
            votes = votes_per_round(round_number, remaining_options)
            result = self._mechanism.tally(votes, config)
            result.rounds_needed = round_number

            logger.debug(
                "deliberation round=%d winner=%s options=%s",
                round_number,
                result.winner,
                remaining_options,
            )

            # Clear winner or decisive failure (veto / no quorum) — stop.
            if result.winner is not None or result.vetoed or not result.quorum_met:
                return result

            # Eliminate the lowest-voted option when more than two remain.
            if len(remaining_options) > 2 and result.vote_counts:
                lowest_choice = min(
                    result.vote_counts, key=lambda c: result.vote_counts[c]
                )
                if lowest_choice in remaining_options:
                    remaining_options.remove(lowest_choice)
                    logger.debug(
                        "deliberation eliminated option=%s", lowest_choice
                    )

        # Max rounds exhausted — return the last result as-is.
        if result is None:
            return VoteResult(
                winner=None,
                vote_counts={},
                total_votes=0,
                quorum_met=False,
                vetoed=False,
                rounds_needed=config.max_rounds,
                details={"reason": "max_rounds_exhausted_no_votes"},
            )
        return result
