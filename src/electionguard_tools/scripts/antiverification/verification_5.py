#!/usr/bin/env python

# pylint: disable=no-name-in-module
from gmpy2 import mpz

from electionguard.ballot import CiphertextBallot
from electionguard.big_integer import BigInteger
from electionguard.chaum_pedersen import ConstantChaumPedersenProof
from electionguard.constants import (
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
    a_plus_bc_q,
)
from electionguard.hash import hash_elems
from electionguard.manifest import Manifest
from electionguard.nonces import Nonces
from electionguard_tools.scripts.antiverification.processing import (
    duplicate_election_data,
    import_ballot_from_files,
    get_contest_index_by_id,
    corrupt_contest_and_serialize_ballot,
    get_corrupt_filenames,
    corrupt_contest_and_json_ballot,
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
    Ballot hash values are recomputed in (5.A); otherwise, they do not
    need to be updated.

    An appropriate ballot and contest is one which is not an undervote
    and for which there is a ciphertext ballot available.
    """
    seed = ElementModQ(5)
    nonces = Nonces(seed)
    antiverify_5_a(_data, context, ballot_id, contest_id, nonces[0])
    antiverify_5_b(_data, context, ballot_id, contest_id, nonces[1])
    antiverify_5_c(_data, ballot_id, contest_id)
    antiverify_5_d(_data, context, ballot_id, contest_id)
    antiverify_5_e(_data, ballot_id, contest_id)
    antiverify_5_f(_data, manifest, context, ballot_id, contest_id, *nonces[2:4])
    antiverify_5_g(_data, manifest, context, ballot_id, contest_id, *nonces[4:6])


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
    This changes the contest hash and thus the ballot hash and code.

    This example requires access to private election data (or at least
    knowledge that a particular vote is not an undervote) to ensure no
    affirmative votes are removed.
    """
    _cex = duplicate_election_data(_data, "5", "A")
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext, contest_id)
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
    v = a_plus_bc_q(nonce, c, r_sum_corrupt)
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
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext, contest_id)
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
    v = a_plus_bc_q(nonce, c, add_q(r_sum, t))
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
    ballot, _, _ = import_ballot_from_files(_data, ballot_id)

    # Select contest and gather relevant values from ballot
    contest_idx = get_contest_index_by_id(ballot, contest_id)
    contest = ballot.contests[contest_idx]
    proof = contest.proof
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Recompute values
    response_corrupt = BigInteger(mpz(proof.response.value) + get_small_prime())
    response_corrupt_hex = response_corrupt.to_hex()

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {"proof_response": response_corrupt_hex}
    for filename in get_corrupt_filenames(_cex, ballot_id):
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
    _, ciphertext, _ = import_ballot_from_files(_data, ballot_id, ciphertext_data=True)
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext, contest_id)
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
    a_corrupt = BigInteger(mpz(a.value) + get_large_prime())
    a_corrupt_hex = a_corrupt.to_hex()

    # Hash hex string from corrupt proof commitment, which does not lie in Z_p
    # and thus cannot be cast to ElementModP. Currently, elements of type BigInteger
    # but not either ElementModP or ElementModQ are hashed as decimal strings, not hex.
    c_corrupt = hash_elems(
        context.crypto_extended_base_hash, alpha, beta, a_corrupt_hex, b
    )
    v_corrupt = a_plus_bc_q(
        proof.response, r_sum, a_minus_b_q(c_corrupt, proof.challenge)
    )

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {
        "proof_pad": a_corrupt_hex,
        "proof_challenge": c_corrupt,
        "proof_response": v_corrupt,
    }
    for filename in get_corrupt_filenames(_cex, ballot_id):
        corrupt_contest_and_json_ballot(filename, contest_idx, replacements)


def antiverify_5_e(_data: str, ballot_id: str, contest_id: str) -> None:
    """
    Generate an election record which fails only Verification (5.E).
    To this end, we add the small prime to the proof challenge.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "5", "E")
    ballot, _, _ = import_ballot_from_files(_data, ballot_id)

    # Select contest and gather relevant values from ballot
    contest_idx = get_contest_index_by_id(ballot, contest_id)
    contest = ballot.contests[contest_idx]
    proof = contest.proof
    assert isinstance(proof, ConstantChaumPedersenProof)

    # Recompute values
    challenge_corrupt = BigInteger(mpz(proof.challenge.value) + get_small_prime())
    challenge_corrupt_hex = challenge_corrupt.to_hex()

    # Override contest proof and other values for ciphertext and submitted ballots
    replacements = {"proof_challenge": challenge_corrupt_hex}
    for filename in get_corrupt_filenames(_cex, ballot_id):
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
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext, contest_id)
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
    # The equation in the while condition should easily fail
    while mult_p(
        g_pow_p(mult_q(limit, c_corrupt)),
        pow_p(context.elgamal_public_key, a_plus_bc_q(nonce_a, r_sum, c_corrupt)),
    ) == mult_p(b_corrupt, pow_p(beta, c_corrupt)):
        a_corrupt = mult_p(a_corrupt, get_generator())
        nonce_a = add_q(nonce_a, ONE_MOD_Q)
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt
        )
    v_corrupt = a_plus_bc_q(nonce_b, r_sum, c_corrupt)
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
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx = get_contest_index_by_id(ciphertext, contest_id)
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
        pow_p(context.elgamal_public_key, a_plus_bc_q(nonce_a, r_sum, c_corrupt)),
    ) == mult_p(b_corrupt, pow_p(beta, c_corrupt)):
        b_corrupt = mult_p(b_corrupt, get_generator())
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt
        )
    v_corrupt = a_plus_bc_q(nonce_a, r_sum, c_corrupt)
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
