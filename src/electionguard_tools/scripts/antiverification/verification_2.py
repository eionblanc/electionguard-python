#!/usr/bin/env python
from os import path
from json import load, dump

# pylint: disable=no-name-in-module
from gmpy2 import mpz

from electionguard.big_integer import BigInteger
from electionguard.constants import get_small_prime
from electionguard.group import ONE_MOD_Q, add_q
from electionguard.guardian import GuardianRecord, GuardianId
from electionguard.serialize import from_file, to_file
from electionguard_tools.helpers.export import (
    ELECTION_RECORD_DIR,
    GUARDIAN_PREFIX,
    GUARDIANS_DIR,
)
from electionguard_tools.scripts.antiverification.processing import (
    duplicate_election_data,
)


def antiverify_2(
    _data: str,
    guardian_id: GuardianId,
) -> None:
    """
    For each subcheck in Verification 2, generate an election record
    which fails only that subcheck.
    """
    antiverify_2_a(_data, guardian_id)
    antiverify_2_b(_data, guardian_id)


def antiverify_2_a(
    _data: str,
    guardian_id: GuardianId,
) -> None:
    """
    Generate an election record which fails only Verification (2.A).
    To this end, we add the small prime to the proof challenge.

    This example requires no private election data.
    """
    _cex = duplicate_election_data(_data, "2", "A")
    guardian_filename = path.join(
        _cex,
        ELECTION_RECORD_DIR,
        GUARDIANS_DIR,
        GUARDIAN_PREFIX + guardian_id + ".json",
    )
    public_record = from_file(GuardianRecord, guardian_filename)
    proof = public_record.election_proofs[0]

    # Recompute values
    c = proof.challenge
    c_corrupt = BigInteger(mpz(c.value) + get_small_prime())

    # Apply changes to JSON
    with open(guardian_filename, "r", encoding="utf-8") as infile:
        json_corrupt = load(infile)
        json_corrupt["election_proofs"][0]["challenge"] = c_corrupt.to_hex()
    with open(guardian_filename, "w", encoding="utf-8") as outfile:
        dump(json_corrupt, outfile)


def antiverify_2_b(
    _data: str,
    guardian_id: GuardianId,
) -> None:
    """
    Generate an election record which fails only Verification (2.B).
    To this end, we increment the proof response.

    This example requires no private election data.
    """
    _cex = duplicate_election_data(_data, "2", "B")
    guardian_filename = path.join(
        _cex,
        ELECTION_RECORD_DIR,
        GUARDIANS_DIR,
        GUARDIAN_PREFIX + guardian_id + ".json",
    )
    public_record = from_file(GuardianRecord, guardian_filename)
    proof = public_record.election_proofs[0]

    # Recompute values
    proof.response = add_q(proof.response, ONE_MOD_Q)

    # Apply changes and serialize
    to_file(
        public_record,
        GUARDIAN_PREFIX + guardian_id,
        path.join(_cex, ELECTION_RECORD_DIR, GUARDIANS_DIR),
    )
