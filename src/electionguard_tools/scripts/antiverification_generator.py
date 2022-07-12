#!/usr/bin/env python
from os import path, environ
import shutil
from copy import deepcopy
import json
from typing import Union, Tuple, List

# pylint: disable=no-name-in-module
from gmpy2 import mpz

from electionguard.ballot import (
    CiphertextBallotContest,
    CiphertextBallot,
    SubmittedBallot,
)
from electionguard.chaum_pedersen import ConstantChaumPedersenProof
from electionguard.constants import (
    ElectionConstants,
    get_large_prime,
    get_small_prime,
    get_generator,
)
from electionguard.election import CiphertextElectionContext
from electionguard.elgamal import ElGamalCiphertext
from electionguard.group import (
    ElementModQ,
    ONE_MOD_Q,
    pow_p,
    g_pow_p,
    mult_p,
    div_p,
    mult_q,
    add_q,
    a_minus_b_q,
)
from electionguard.hash import hash_elems
from electionguard.manifest import Manifest
from electionguard.nonces import Nonces
from electionguard.serialize import from_file, to_file
from electionguard_tools.helpers.export import (
    CONTEXT_FILE_NAME,
    PRIVATE_DATA_DIR,
    ELECTION_RECORD_DIR,
    SUBMITTED_BALLOTS_DIR,
    CONSTANTS_FILE_NAME,
    CIPHERTEXT_BALLOT_PREFIX,
    SUBMITTED_BALLOT_PREFIX,
)

CIPHERTEXT_BALLOTS_DIR = "ciphertext_ballots"

# pylint: disable=redefined-outer-name
def antiverify_5_a(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    nonce: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (5.A).
    To this end, we delete a placeholder selection that did not have
    an affirmative vote, then recompute the contest accumulation and
    Chaum-Pedersen proof.

    This example requires access to private election data (or at least
    knowledge that a particular vote is not an undervote) to ensure no
    affirmative votes are removed.
    """
    _cex = duplicate_election_data(_data, "5", "A")
    ballot, ciphertext = import_ballot_from_files(_data, ballot_id)
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext.contests, contest_id)
    contest = ciphertext.contests[contest_idx]
    selections = contest.ballot_selections
    alpha = contest.ciphertext_accumulation.pad
    beta = contest.ciphertext_accumulation.data
    r_sum = contest.aggregate_nonce()
    proof = contest.proof
    deleted_nonce = selections[-1].nonce
    assert isinstance(r_sum, ElementModQ)
    assert isinstance(proof, ConstantChaumPedersenProof)
    assert isinstance(deleted_nonce, ElementModQ)

    # Recompute values
    cipher_selections_corrupt = selections[:-1]
    ballot_selections_corrupt = ballot.contests[contest_idx].ballot_selections[:-1]

    alpha_corrupt = div_p(alpha, selections[-1].ciphertext.pad)
    beta_corrupt = div_p(beta, selections[-1].ciphertext.data)
    accumulation_corrupt = ElGamalCiphertext(alpha_corrupt, beta_corrupt)
    r_sum_corrupt = a_minus_b_q(r_sum, deleted_nonce)

    a = g_pow_p(nonce)
    b = pow_p(context.elgamal_public_key, nonce)
    c = hash_elems(context.crypto_extended_base_hash, alpha_corrupt, beta_corrupt, a, b)
    v = add_q(nonce, mult_q(c, r_sum_corrupt))
    proof_corrupt = ConstantChaumPedersenProof(
        pad=a,
        data=b,
        challenge=c,
        response=v,
        constant=proof.constant,
        usage=proof.usage,
    )

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {
        "ballot_selections": cipher_selections_corrupt,
        "ciphertext_accumulation": accumulation_corrupt,
        "nonce": nonce,
        "proof": proof_corrupt,
    }
    corrupt_contest_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, replacements
    )
    replacements["ballot_selections"] = ballot_selections_corrupt
    corrupt_contest_and_serialize_ballot(
        _cex, ballot, ballot_id, contest_idx, replacements, is_cipher=False
    )


def antiverify_5_b(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    nonce: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (5.B).
    To this end, we multiply the ciphertext accumulation by some nontrivial power of
    the generator, then adjust the Chaum-Pedersen proof accordingly.

    This example requires access to the ciphertext ballot (for the aggregate nonce).
    """
    _cex = duplicate_election_data(_data, "5", "B")
    ballot, ciphertext = import_ballot_from_files(_data, ballot_id)
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext.contests, contest_id)
    contest = ciphertext.contests[contest_idx]
    alpha = contest.ciphertext_accumulation.pad
    beta = contest.ciphertext_accumulation.data
    r_sum = contest.aggregate_nonce()
    proof = contest.proof
    assert isinstance(r_sum, ElementModQ)
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Recompute values
    t = ONE_MOD_Q  # Pick any nonzero element of Z_q
    alpha_corrupt = mult_p(g_pow_p(t), alpha)
    beta_corrupt = mult_p(pow_p(context.elgamal_public_key, t), beta)
    accumulation_corrupt = ElGamalCiphertext(alpha_corrupt, beta_corrupt)

    a = g_pow_p(nonce)
    b = pow_p(context.elgamal_public_key, nonce)
    c = hash_elems(context.crypto_extended_base_hash, alpha_corrupt, beta_corrupt, a, b)
    v = add_q(nonce, mult_q(c, add_q(r_sum, t)))
    proof_corrupt = ConstantChaumPedersenProof(
        pad=a,
        data=b,
        challenge=c,
        response=v,
        constant=proof.constant,
        usage=proof.usage,
    )

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {
        "ciphertext_accumulation": accumulation_corrupt,
        "nonce": nonce,
        "proof": proof_corrupt,
    }
    corrupt_contest_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, replacements
    )
    corrupt_contest_and_serialize_ballot(
        _cex, ballot, ballot_id, contest_idx, replacements, is_cipher=False
    )


def antiverify_5_c(_data: str, ballot_id: str, contest_id: str) -> None:
    """
    Generate an election record which fails only Verification (5.C).
    To this end, we add the small prime to the proof response.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "5", "C")
    ballot, _ = import_ballot_from_files(_data, ballot_id, private_data=False)

    # Select contest and gather relevant values from ballot
    contest_idx = get_contest_index_by_id(ballot.contests, contest_id)
    contest = ballot.contests[contest_idx]
    proof = contest.proof
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Recompute values
    response_corrupt = f"{mpz(proof.response.value) + get_small_prime():X}"

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {"proof_response": response_corrupt}
    for filename in get_corrupt_filenames(_cex):
        corrupt_contest_and_json_ballot(filename, contest_idx, replacements)


def antiverify_5_d(
    _data: str, context: CiphertextElectionContext, ballot_id: str, contest_id: str
) -> None:
    """
    Generate an election record which fails only Verification (5.D).
    To this end, we add the large prime to the proof pad.
    An alternative approach could do the same instead to the proof data.

    This example requires access to the ciphertext ballot (for the aggregate nonce).
    """
    _cex = duplicate_election_data(_data, "5", "D")
    _, ciphertext = import_ballot_from_files(_data, ballot_id)
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext.contests, contest_id)
    contest = ciphertext.contests[contest_idx]
    alpha = contest.ciphertext_accumulation.pad
    beta = contest.ciphertext_accumulation.data
    r_sum = contest.aggregate_nonce()
    proof = contest.proof
    assert isinstance(r_sum, ElementModQ)
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Recompute values
    a = proof.pad
    b = proof.data
    a_corrupt = mpz(a.value) + get_large_prime()
    pad_corrupt = f"{a_corrupt:X}"

    c_corrupt = hash_elems(context.crypto_extended_base_hash, alpha, beta, a_corrupt, b)
    v_corrupt = add_q(
        proof.response, mult_q(r_sum, a_minus_b_q(c_corrupt, proof.challenge))
    )

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {
        "proof_pad": pad_corrupt,
        "proof_challenge": c_corrupt,
        "proof_response": v_corrupt,
    }
    for filename in get_corrupt_filenames(_cex):
        corrupt_contest_and_json_ballot(filename, contest_idx, replacements)


def antiverify_5_e(_data: str, ballot_id: str, contest_id: str) -> None:
    """
    Generate an election record which fails only Verification (5.E).
    To this end, we add the small prime to the proof challenge.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "5", "E")
    ballot, _ = import_ballot_from_files(_data, ballot_id, private_data=False)

    # Select contest and gather relevant values from ballot
    contest_idx = get_contest_index_by_id(ballot.contests, contest_id)
    contest = ballot.contests[contest_idx]
    proof = contest.proof
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Recompute values
    challenge_corrupt = f"{mpz(proof.challenge.value) + get_small_prime():X}"

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {"proof_challenge": challenge_corrupt}
    for filename in get_corrupt_filenames(_cex):
        corrupt_contest_and_json_ballot(filename, contest_idx, replacements)


def antiverify_5_f(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    nonce_a: ElementModQ,
    nonce_b: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (5.F).
    To this end, we select commitments to violate a corollary of (5.F) and (5.G),
    then carefully pick a response to satisfy (5.G).

    This example requires access to the ciphertext ballot (for the aggregate nonce).
    """
    _cex = duplicate_election_data(_data, "5", "F")
    ballot, ciphertext = import_ballot_from_files(_data, ballot_id)
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext.contests, contest_id)
    contest = ciphertext.contests[contest_idx]
    alpha = contest.ciphertext_accumulation.pad
    beta = contest.ciphertext_accumulation.data
    r_sum = contest.aggregate_nonce()
    proof = contest.proof
    assert isinstance(r_sum, ElementModQ)
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Inspect manifest to determine contest selection limit
    limit = manifest.contests[contest_idx].votes_allowed
    assert isinstance(limit, int)

    # Recompute values
    b_corrupt = pow_p(context.elgamal_public_key, nonce_b)
    a_corrupt = g_pow_p(nonce_a)
    c_corrupt = hash_elems(
        context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt
    )
    # The econtext.crypto_extended_base_hashuation in the while condition should easily fail
    while mult_p(
        g_pow_p(mult_q(limit, c_corrupt)),
        pow_p(context.elgamal_public_key, add_q(nonce_a, mult_q(r_sum, c_corrupt))),
    ) == mult_p(b_corrupt, pow_p(beta, c_corrupt)):
        a_corrupt = mult_p(a_corrupt, get_generator())
        nonce_a = add_q(nonce_a, ONE_MOD_Q)
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt
        )
    v_corrupt = add_q(nonce_b, mult_q(r_sum, c_corrupt))
    proof_corrupt = ConstantChaumPedersenProof(
        pad=a_corrupt,
        data=b_corrupt,
        challenge=c_corrupt,
        response=v_corrupt,
        constant=proof.constant,
        usage=proof.usage,
    )

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {"nonce": nonce_b, "proof": proof_corrupt}
    corrupt_contest_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, replacements
    )
    corrupt_contest_and_serialize_ballot(
        _cex, ballot, ballot_id, contest_idx, replacements, is_cipher=False
    )


def antiverify_5_g(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    nonce_a: ElementModQ,
    nonce_b: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (5.G).
    To this end, we select commitments to violate a corollary of (5.F) and (5.G),
    then carefully pick a response to satisfy (5.F).

    This example requires access to the ciphertext ballot (for the aggregate nonce).
    """
    _cex = duplicate_election_data(_data, "5", "G")
    ballot, ciphertext = import_ballot_from_files(_data, ballot_id)
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext.contests, contest_id)
    contest = ciphertext.contests[contest_idx]
    alpha = contest.ciphertext_accumulation.pad
    beta = contest.ciphertext_accumulation.data
    r_sum = contest.aggregate_nonce()
    proof = contest.proof
    assert isinstance(r_sum, ElementModQ)
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Inspect manifest to determine contest selection limit
    limit = manifest.contests[contest_idx].votes_allowed
    assert isinstance(limit, int)

    # Recompute values
    a_corrupt = g_pow_p(nonce_a)
    b_corrupt = g_pow_p(nonce_b)
    c_corrupt = hash_elems(
        context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt
    )
    # The equation in the while condition should easily fail
    while mult_p(
        g_pow_p(mult_q(limit, c_corrupt)),
        pow_p(context.elgamal_public_key, add_q(nonce_a, mult_q(r_sum, c_corrupt))),
    ) == mult_p(b_corrupt, pow_p(beta, c_corrupt)):
        b_corrupt = mult_p(b_corrupt, get_generator())
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt
        )
    v_corrupt = add_q(nonce_a, mult_q(r_sum, c_corrupt))
    proof_corrupt = ConstantChaumPedersenProof(
        pad=a_corrupt,
        data=b_corrupt,
        challenge=c_corrupt,
        response=v_corrupt,
        constant=proof.constant,
        usage=proof.usage,
    )

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {"nonce": nonce_a, "proof": proof_corrupt}
    corrupt_contest_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, replacements
    )
    corrupt_contest_and_serialize_ballot(
        _cex, ballot, ballot_id, contest_idx, replacements, is_cipher=False
    )


def antiverify_5(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
) -> None:
    """
    For each subcheck in Verification 5, generate an election record
    which fails only that subcheck.
    Contest hash values are not currently re-computed.

    An appropriate ballot and contest is one which is not an undervote
    and for which there is a ciphertext ballot available.
    """
    seed = ElementModQ(17)
    nonces = Nonces(seed)
    antiverify_5_a(_data, context, ballot_id, contest_id, nonces[0])
    antiverify_5_b(_data, context, ballot_id, contest_id, nonces[1])
    antiverify_5_c(_data, ballot_id, contest_id)
    antiverify_5_d(_data, context, ballot_id, contest_id)
    antiverify_5_e(_data, ballot_id, contest_id)
    antiverify_5_f(_data, manifest, context, ballot_id, contest_id, *nonces[2:4])
    antiverify_5_g(_data, manifest, context, ballot_id, contest_id, *nonces[4:6])


def duplicate_election_data(_data: str, check: str, subcheck: str) -> str:
    # Duplicate files into _data + '_failure/{check}/{subcheck}'
    _cex = path.join(_data + "_failure", check, subcheck)
    if path.exists(_cex):
        shutil.rmtree(_cex)
    shutil.copytree(_data, _cex)
    return _cex


def import_ballot_from_files(
    _data: str, ballot_id: str, private_data: bool = True
) -> Tuple[SubmittedBallot, Union[CiphertextBallot, None]]:
    # Import ciphertext and corresponding submitted ballot to manipulate
    ballot = from_file(
        SubmittedBallot,
        path.join(
            _data,
            ELECTION_RECORD_DIR,
            SUBMITTED_BALLOTS_DIR,
            SUBMITTED_BALLOT_PREFIX + ballot_id + ".json",
        ),
    )
    assert isinstance(ballot, SubmittedBallot)
    if private_data:
        ciphertext = from_file(
            CiphertextBallot,
            path.join(
                _data,
                PRIVATE_DATA_DIR,
                CIPHERTEXT_BALLOTS_DIR,
                CIPHERTEXT_BALLOT_PREFIX + ballot_id + ".json",
            ),
        )
        return ballot, ciphertext
    return ballot, None


def get_contest_index_by_id(
    contests: List[CiphertextBallotContest], contest_id: str
) -> int:
    # Step through contests until match is found; this accommodates contests
    # listed out of sequence order as well as contests from compact ballots
    for j, contest in enumerate(contests):
        if contest.object_id == contest_id:
            return j
    return -1


def get_corrupt_filenames(_cex: str) -> Tuple[str, str]:
    # Generate filenames for JSON-editing the submitted and ciphertext ballot
    ballot_file_corrupt = path.join(
        _cex,
        ELECTION_RECORD_DIR,
        SUBMITTED_BALLOTS_DIR,
        SUBMITTED_BALLOT_PREFIX + ballot_id + ".json",
    )
    cipher_file_corrupt = path.join(
        _cex,
        PRIVATE_DATA_DIR,
        CIPHERTEXT_BALLOTS_DIR,
        CIPHERTEXT_BALLOT_PREFIX + ballot_id + ".json",
    )
    return ballot_file_corrupt, cipher_file_corrupt


def corrupt_contest_and_serialize_ballot(
    _cex: str,
    ballot: CiphertextBallot,
    ballot_id: str,
    contest_idx: int,
    replacements: dict,
    is_cipher: bool = True,
) -> None:
    # Imbue corruptions to copy of ciphertext or submitted ballot according
    # to replacements dictionary, then serialize result
    ballot_corrupt = deepcopy(ballot)
    contest_corrupt = ballot_corrupt.contests[contest_idx]
    for key, value in replacements.items():
        if key == "ballot_selections":
            contest_corrupt.ballot_selections = value
        elif key == "ciphertext_accumulation":
            contest_corrupt.ciphertext_accumulation = value
        elif key == "nonce" and is_cipher:
            contest_corrupt.nonce = value
        elif key == "proof":
            contest_corrupt.proof = value
    to_file(
        ballot_corrupt,
        (CIPHERTEXT_BALLOT_PREFIX if is_cipher else SUBMITTED_BALLOT_PREFIX)
        + ballot_id,
        path.join(
            _cex,
            (PRIVATE_DATA_DIR if is_cipher else ELECTION_RECORD_DIR),
            (CIPHERTEXT_BALLOTS_DIR if is_cipher else SUBMITTED_BALLOTS_DIR),
        ),
    )


def corrupt_contest_and_json_ballot(
    filename: str, contest_idx: int, replacements: dict
) -> None:
    # Edit JSON of ciphertext or submitted ballot according
    # to replacements dictionary to imbue corruptions
    # This is necessary, e.g., when we cannot construct a corrupted
    # Chaum-Pedersen proof object with a challenge that isn't of type
    # ElementModQ, so edits are made via JSON rather than serialization
    with open(filename, "r", encoding="utf-8") as infile:
        json_corrupt = json.load(infile)
        for key, value in replacements.items():
            if key[:5] == "proof":
                json_corrupt["contests"][contest_idx]["proof"][key[7:]] = value
    with open(filename, "w", encoding="utf-8") as outfile:
        json.dump(json_corrupt, outfile)


if __name__ == "__main__":
    # Locate existing election record and election private data folders
    _data = path.realpath(
        path.join(__file__, "../../../../data/1.0.0/jefferson-primary")
    )
    # Import constants and context
    constants = from_file(
        ElectionConstants,
        path.join(_data, ELECTION_RECORD_DIR, CONSTANTS_FILE_NAME + ".json"),
    )
    # Assume the constants are the LARGE_TEST_CONSTANTS
    environ.setdefault("PRIME_OPTION", "TestOnly")
    context = from_file(
        CiphertextElectionContext,
        path.join(_data, ELECTION_RECORD_DIR, CONTEXT_FILE_NAME + ".json"),
    )
    manifest = from_file(
        Manifest, path.join(_data, ELECTION_RECORD_DIR, "manifest.json")
    )

    # Select ballot and contest to tweak
    ballot_id = "03a29d15-667c-4ac8-afd7-549f19b8e4eb"
    contest_id = "justice-supreme-court"

    # Call helper functions for example generation
    antiverify_5(_data, manifest, context, ballot_id, contest_id)
