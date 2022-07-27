#!/usr/bin/env python
from copy import deepcopy
from os import path

from electionguard.serialize import from_file, to_file
from electionguard.tally import PlaintextTally
from electionguard_tools.helpers.export import ELECTION_RECORD_DIR, TALLY_FILE_NAME
from electionguard_tools.scripts.antiverification.processing import (
    add_plaintext_vote,
    duplicate_election_data,
)


def antiverify_11(
    _data: str,
    contest_id: str,
    selection_id: str,
) -> None:
    """
    For each subcheck in Verification 11, generate an election record
    which fails only that subcheck.
    """
    antiverify_11_a(_data, contest_id, selection_id)
    antiverify_11_b(_data, contest_id, selection_id)
    antiverify_11_c(_data, contest_id)


def antiverify_11_a(
    _data: str,
    contest_id: str,
    selection_id: str,
) -> None:
    """
    Generate an election record which fails only Verification (11.A).
    To this end, we scale an encrypted tally value then adjust the
    plaintext tally accordingly.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "11", "A")
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection = tally.contests[contest_id].selections[selection_id]

    # Recompute values
    add_plaintext_vote(selection, 1)

    # Override plaintext tally
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))


def antiverify_11_b(
    _data: str,
    contest_id: str,
    selection_id: str,
) -> None:
    """
    Generate an election record which fails only Verification (11.B).
    To this end, we manipulate a plaintext tally.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "11", "B")
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection = tally.contests[contest_id].selections[selection_id]

    # Recompute values
    selection.tally = selection.tally + 1

    # Override plaintext tally
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))


def antiverify_11_c(
    _data: str,
    contest_id: str,
) -> None:
    """
    Generate an election record which fails only Verification (11.C).
    To this end, we duplicate a plaintext tally contest under a pseudonym.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "11", "C")
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    contest = tally.contests[contest_id]

    # Recompute values
    duplicate = deepcopy(contest)
    duplicate.object_id = "pseudo-" + duplicate.object_id
    tally.contests[duplicate.object_id] = duplicate

    # Override plaintext tally
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))
