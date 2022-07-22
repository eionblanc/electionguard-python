#!/usr/bin/env python

# pylint: disable=no-name-in-module
from gmpy2 import mpz

from electionguard.ballot import CiphertextBallot
from electionguard.big_integer import BigInteger
from electionguard.chaum_pedersen import DisjunctiveChaumPedersenProof
from electionguard.constants import (
    get_large_prime,
    get_small_prime,
    get_generator,
)
from electionguard.election import CiphertextElectionContext
from electionguard.group import (
    ElementModQ,
    ONE_MOD_Q,
    pow_p,
    g_pow_p,
    mult_p,
    add_q,
    a_minus_b_q,
    a_plus_bc_q,
)
from electionguard.hash import hash_elems
from electionguard.nonces import Nonces
from electionguard_tools.scripts.antiverification.processing import (
    duplicate_election_data,
    import_ballot_from_files,
    get_selection_index_by_id,
    get_corrupt_filenames,
    corrupt_selection_and_json_ballot,
    corrupt_selection_and_serialize_ballot,
)


def antiverify_4(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_0: str,
    selection_id_1: str,
) -> None:
    """
    For each subcheck in Verification 4, generate an election record
    which fails only that subcheck.
    Ballot hash values are not currently re-computed.

    An appropriate ballot and contest is one which is not an undervote
    and for which there is a ciphertext ballot available.
    """
    seed = ElementModQ(4)
    nonces = Nonces(seed)
    antiverify_4_a(_data, context, ballot_id, contest_id, selection_id_0)
    antiverify_4_b(_data, ballot_id, contest_id, selection_id_0)
    antiverify_4_c(_data, ballot_id, contest_id, selection_id_0)
    antiverify_4_d(_data, context, ballot_id, contest_id, selection_id_0, *nonces[0:4])
    antiverify_4_e(_data, context, ballot_id, contest_id, selection_id_0, *nonces[5:7])
    antiverify_4_f(_data, context, ballot_id, contest_id, selection_id_1, *nonces[7:9])
    antiverify_4_g(_data, context, ballot_id, contest_id, selection_id_0, *nonces[9:11])
    antiverify_4_h(
        _data, context, ballot_id, contest_id, selection_id_1, *nonces[11:13]
    )


def antiverify_4_a(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_0: str,
) -> None:
    """
    Generate an election record which fails only Verification (4.A).
    To this end, we add the large prime to the first proof pad.
    An alternative approach could do the same instead to the other proof pad
    or either proof data. With more care, we could do the same to the ciphertext.

    This example requires access to the ciphertext ballot (for the selection nonce)
    and knowledge that the selection encrypts 0.
    """
    _cex = duplicate_election_data(_data, "4", "A")
    _, ciphertext, _ = import_ballot_from_files(_data, ballot_id, ciphertext_data=True)
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx, selection_idx = get_selection_index_by_id(
        ciphertext, contest_id, selection_id_0
    )
    selection = ciphertext.contests[contest_idx].ballot_selections[selection_idx]
    alpha = selection.ciphertext.pad
    beta = selection.ciphertext.data
    r = selection.nonce
    proof = selection.proof
    assert isinstance(r, ElementModQ)
    assert isinstance(proof, DisjunctiveChaumPedersenProof)

    # Recompute values
    a0 = proof.proof_zero_pad
    b0 = proof.proof_zero_data
    a0_corrupt = BigInteger(mpz(a0.value) + get_large_prime())
    a0_corrupt_hex = a0_corrupt.to_hex()

    c_corrupt = hash_elems(
        context.crypto_extended_base_hash,
        alpha,
        beta,
        a0_corrupt_hex,
        b0,
        proof.proof_one_pad,
        proof.proof_one_data,
    )
    c0_corrupt = a_minus_b_q(c_corrupt, proof.proof_one_challenge)
    v0_corrupt = a_plus_bc_q(
        proof.proof_zero_response,
        a_minus_b_q(c0_corrupt, proof.proof_zero_challenge),
        r,
    )

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {
        "proof_zero_pad": a0_corrupt_hex,
        "proof_zero_challenge": c0_corrupt,
        "proof_zero_response": v0_corrupt,
        "challenge": c_corrupt,
    }
    for filename in get_corrupt_filenames(_cex, ballot_id):
        corrupt_selection_and_json_ballot(
            filename, contest_idx, selection_idx, replacements
        )


def antiverify_4_b(
    _data: str, ballot_id: str, contest_id: str, selection_id_0: str
) -> None:
    """
    Generate an election record which fails only Verification (4.B).
    To this end, we increment the proof challenge away from the correct
    hash value and change the proof accordingly.

    This example requires access to the ciphertext ballot (for the selection nonce)
    and knowledge that the selection encrypts 0.
    """
    _cex = duplicate_election_data(_data, "4", "B")
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ballot
    contest_idx, selection_idx = get_selection_index_by_id(
        ciphertext, contest_id, selection_id_0
    )
    selection = ciphertext.contests[contest_idx].ballot_selections[selection_idx]
    r = selection.nonce
    proof = selection.proof
    assert isinstance(r, ElementModQ)
    assert isinstance(proof, DisjunctiveChaumPedersenProof)

    # Recompute values
    challenge_corrupt = add_q(proof.challenge, ONE_MOD_Q)
    c0_corrupt = add_q(proof.proof_zero_challenge, ONE_MOD_Q)
    v0_corrupt = add_q(proof.proof_zero_response, r)
    proof_corrupt = DisjunctiveChaumPedersenProof(
        proof_zero_pad=proof.proof_zero_pad,
        proof_zero_data=proof.proof_zero_data,
        proof_one_pad=proof.proof_one_pad,
        proof_one_data=proof.proof_one_data,
        proof_zero_challenge=c0_corrupt,
        proof_one_challenge=proof.proof_one_challenge,
        challenge=challenge_corrupt,
        proof_zero_response=v0_corrupt,
        proof_one_response=proof.proof_one_response,
    )

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {"proof": proof_corrupt}
    corrupt_selection_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, selection_idx, replacements
    )
    corrupt_selection_and_serialize_ballot(
        _cex,
        ballot,
        ballot_id,
        contest_idx,
        selection_idx,
        replacements,
        is_cipher=False,
    )


def antiverify_4_c(
    _data: str, ballot_id: str, contest_id: str, selection_id: str
) -> None:
    """
    Generate an election record which fails only Verification (4.C).
    To this end, we add the small prime to the first proof response.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "4", "C")
    ballot, _, _ = import_ballot_from_files(_data, ballot_id)

    # Select contest and gather relevant values from ballot
    contest_idx, selection_idx = get_selection_index_by_id(
        ballot, contest_id, selection_id
    )
    selection = ballot.contests[contest_idx].ballot_selections[selection_idx]
    proof = selection.proof
    assert isinstance(proof, DisjunctiveChaumPedersenProof)

    # Recompute values
    v0_corrupt = BigInteger(mpz(proof.proof_zero_response.value) + get_small_prime())
    v0_corrupt_hex = v0_corrupt.to_hex()

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {"proof_zero_response": v0_corrupt_hex}
    for filename in get_corrupt_filenames(_cex, ballot_id):
        corrupt_selection_and_json_ballot(
            filename, contest_idx, selection_idx, replacements
        )


def antiverify_4_d(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id: str,
    nonce_c0: ElementModQ,
    nonce_c1: ElementModQ,
    nonce_u0: ElementModQ,
    nonce_u1: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (4.D).
    To this end, we construct the disjunctive Chaum-Pedersen proof without concern
    for the hashed challenge value equaling the sum of anticipated challenges.

    This example requires access to the ciphertext ballot (for the selection nonce)
    and knowledge that the selection encrypts 0.
    """
    _cex = duplicate_election_data(_data, "4", "D")
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx, selection_idx = get_selection_index_by_id(
        ciphertext, contest_id, selection_id
    )
    selection = ciphertext.contests[contest_idx].ballot_selections[selection_idx]
    alpha = selection.ciphertext.pad
    beta = selection.ciphertext.data
    r = selection.nonce
    assert isinstance(r, ElementModQ)

    # Recompute values
    a0 = g_pow_p(nonce_u0)
    b0 = pow_p(context.elgamal_public_key, nonce_u0)
    a1 = g_pow_p(nonce_u1)
    b1 = mult_p(pow_p(context.elgamal_public_key, nonce_u1), g_pow_p(nonce_c1))
    c = hash_elems(context.crypto_extended_base_hash, alpha, beta, a0, b0, a1, b1)
    # The equation in the while loop should easily fail
    while c == add_q(nonce_c0, nonce_c1):
        a0 = mult_p(a0, get_generator())
        nonce_u0 = add_q(nonce_u0, ONE_MOD_Q)
        b0 = mult_p(b0, context.elgamal_public_key)
        c = hash_elems(context.crypto_extended_base_hash, alpha, beta, a0, b0, a1, b1)

    v0 = a_plus_bc_q(nonce_u0, nonce_c0, r)
    v1 = a_plus_bc_q(nonce_u1, nonce_c1, r)
    proof_corrupt = DisjunctiveChaumPedersenProof(
        a0, b0, a1, b1, nonce_c0, nonce_c1, c, v0, v1
    )

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {"proof": proof_corrupt}
    corrupt_selection_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, selection_idx, replacements
    )
    corrupt_selection_and_serialize_ballot(
        _cex,
        ballot,
        ballot_id,
        contest_idx,
        selection_idx,
        replacements,
        is_cipher=False,
    )


def antiverify_4_e(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_0: str,
    nonce_a: ElementModQ,
    nonce_b: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (4.E).
    To this end, we select commitments to violate a corollary of (4.E) and (4.G),
    then carefully pick a response to satisfy (4.G).

    This example requires access to the ciphertext ballot (for the selection nonce)
    and knowledge that the selection encrypts 0.
    """
    _cex = duplicate_election_data(_data, "4", "E")
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx, selection_idx = get_selection_index_by_id(
        ciphertext, contest_id, selection_id_0
    )
    selection = ciphertext.contests[contest_idx].ballot_selections[selection_idx]
    alpha = selection.ciphertext.pad
    beta = selection.ciphertext.data
    r = selection.nonce
    proof = selection.proof
    assert isinstance(r, ElementModQ)
    assert isinstance(proof, DisjunctiveChaumPedersenProof)

    # Recompute values only for true proof
    b_corrupt = pow_p(context.elgamal_public_key, nonce_b)
    a_corrupt = g_pow_p(nonce_a)
    a1 = proof.proof_one_pad
    b1 = proof.proof_one_data
    c_corrupt = hash_elems(
        context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt, a1, b1
    )
    c1 = proof.proof_one_challenge
    c0_corrupt = a_minus_b_q(c_corrupt, c1)
    # The equation in the while condition should easily fail
    while pow_p(
        context.elgamal_public_key, a_plus_bc_q(nonce_a, r, c0_corrupt)
    ) == mult_p(b_corrupt, pow_p(beta, c0_corrupt)):
        a_corrupt = mult_p(a_corrupt, get_generator())
        nonce_a = add_q(nonce_a, ONE_MOD_Q)
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt, a1, b1
        )
        c0_corrupt = a_minus_b_q(c_corrupt, c1)
    v_corrupt = a_plus_bc_q(nonce_b, r, c0_corrupt)

    proof_corrupt = DisjunctiveChaumPedersenProof(
        proof_zero_pad=a_corrupt,
        proof_zero_data=b_corrupt,
        proof_one_pad=a1,
        proof_one_data=b1,
        proof_zero_challenge=c0_corrupt,
        proof_one_challenge=c1,
        challenge=c_corrupt,
        proof_zero_response=v_corrupt,
        proof_one_response=proof.proof_one_response,
    )

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {"proof": proof_corrupt}
    corrupt_selection_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, selection_idx, replacements
    )
    corrupt_selection_and_serialize_ballot(
        _cex,
        ballot,
        ballot_id,
        contest_idx,
        selection_idx,
        replacements,
        is_cipher=False,
    )


def antiverify_4_f(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_1: str,
    nonce_a: ElementModQ,
    nonce_b: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (4.F).
    To this end, we select commitments to violate a corollary of (4.F) and (4.H),
    then carefully pick a response to satisfy (4.H).

    This example requires access to the ciphertext ballot (for the selection nonce)
    and knowledge that the selection encrypts 1.
    """
    _cex = duplicate_election_data(_data, "4", "F")
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx, selection_idx = get_selection_index_by_id(
        ciphertext, contest_id, selection_id_1
    )
    selection = ciphertext.contests[contest_idx].ballot_selections[selection_idx]
    alpha = selection.ciphertext.pad
    beta = selection.ciphertext.data
    r = selection.nonce
    proof = selection.proof
    assert isinstance(r, ElementModQ)
    assert isinstance(proof, DisjunctiveChaumPedersenProof)

    # Recompute values only for true proof
    b_corrupt = pow_p(context.elgamal_public_key, nonce_b)
    a_corrupt = g_pow_p(nonce_a)
    a0 = proof.proof_zero_pad
    b0 = proof.proof_zero_data
    c_corrupt = hash_elems(
        context.crypto_extended_base_hash, alpha, beta, a0, b0, a_corrupt, b_corrupt
    )
    c0 = proof.proof_zero_challenge
    c1_corrupt = a_minus_b_q(c_corrupt, c0)
    # The equation in the while condition should easily fail
    while mult_p(
        g_pow_p(c1_corrupt),
        pow_p(context.elgamal_public_key, a_plus_bc_q(nonce_a, r, c1_corrupt)),
    ) == mult_p(b_corrupt, pow_p(beta, c1_corrupt)):
        a_corrupt = mult_p(a_corrupt, get_generator())
        nonce_a = add_q(nonce_a, ONE_MOD_Q)
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a0, b0, a_corrupt, b_corrupt
        )
        c1_corrupt = a_minus_b_q(c_corrupt, c0)
    v_corrupt = a_plus_bc_q(nonce_b, r, c1_corrupt)

    proof_corrupt = DisjunctiveChaumPedersenProof(
        proof_zero_pad=a0,
        proof_zero_data=b0,
        proof_one_pad=a_corrupt,
        proof_one_data=b_corrupt,
        proof_zero_challenge=c0,
        proof_one_challenge=c1_corrupt,
        challenge=c_corrupt,
        proof_zero_response=proof.proof_zero_response,
        proof_one_response=v_corrupt,
    )

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {"proof": proof_corrupt}
    corrupt_selection_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, selection_idx, replacements
    )
    corrupt_selection_and_serialize_ballot(
        _cex,
        ballot,
        ballot_id,
        contest_idx,
        selection_idx,
        replacements,
        is_cipher=False,
    )


def antiverify_4_g(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_0: str,
    nonce_a: ElementModQ,
    nonce_b: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (4.G).
    To this end, we select commitments to violate a corollary of (4.E) and (4.G),
    then carefully pick a response to satisfy (4.E).

    This example requires access to the ciphertext ballot (for the selection nonce)
    and knowledge that the selection encrypts 0.
    """
    _cex = duplicate_election_data(_data, "4", "G")
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx, selection_idx = get_selection_index_by_id(
        ciphertext, contest_id, selection_id_0
    )
    selection = ciphertext.contests[contest_idx].ballot_selections[selection_idx]
    alpha = selection.ciphertext.pad
    beta = selection.ciphertext.data
    r = selection.nonce
    proof = selection.proof
    assert isinstance(r, ElementModQ)
    assert isinstance(proof, DisjunctiveChaumPedersenProof)

    # Recompute values only for true proof
    a_corrupt = g_pow_p(nonce_a)
    b_corrupt = g_pow_p(nonce_b)
    a1 = proof.proof_one_pad
    b1 = proof.proof_one_data
    c_corrupt = hash_elems(
        context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt, a1, b1
    )
    c1 = proof.proof_one_challenge
    c0_corrupt = a_minus_b_q(c_corrupt, c1)
    # The equation in the while condition should easily fail
    while pow_p(
        context.elgamal_public_key, a_plus_bc_q(nonce_a, r, c0_corrupt)
    ) == mult_p(b_corrupt, pow_p(beta, c0_corrupt)):
        b_corrupt = mult_p(b_corrupt, get_generator())
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a_corrupt, b_corrupt, a1, b1
        )
        c0_corrupt = a_minus_b_q(c_corrupt, c1)
    v_corrupt = a_plus_bc_q(nonce_a, r, c0_corrupt)

    proof_corrupt = DisjunctiveChaumPedersenProof(
        proof_zero_pad=a_corrupt,
        proof_zero_data=b_corrupt,
        proof_one_pad=a1,
        proof_one_data=b1,
        proof_zero_challenge=c0_corrupt,
        proof_one_challenge=c1,
        challenge=c_corrupt,
        proof_zero_response=v_corrupt,
        proof_one_response=proof.proof_one_response,
    )

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {"proof": proof_corrupt}
    corrupt_selection_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, selection_idx, replacements
    )
    corrupt_selection_and_serialize_ballot(
        _cex,
        ballot,
        ballot_id,
        contest_idx,
        selection_idx,
        replacements,
        is_cipher=False,
    )


def antiverify_4_h(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_1: str,
    nonce_a: ElementModQ,
    nonce_b: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (4.H).
    To this end, we select commitments to violate a corollary of (4.F) and (4.H),
    then carefully pick a response to satisfy (4.F).

    This example requires access to the ciphertext ballot (for the selection nonce)
    and knowledge that the selection encrypts 1.
    """
    _cex = duplicate_election_data(_data, "4", "H")
    ballot, ciphertext, _ = import_ballot_from_files(
        _data, ballot_id, ciphertext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)

    # Select contest and gather relevant values from ciphertext
    contest_idx, selection_idx = get_selection_index_by_id(
        ciphertext, contest_id, selection_id_1
    )
    selection = ciphertext.contests[contest_idx].ballot_selections[selection_idx]
    alpha = selection.ciphertext.pad
    beta = selection.ciphertext.data
    r = selection.nonce
    proof = selection.proof
    assert isinstance(r, ElementModQ)
    assert isinstance(proof, DisjunctiveChaumPedersenProof)

    # Recompute values only for true proof
    a_corrupt = g_pow_p(nonce_a)
    b_corrupt = g_pow_p(nonce_b)
    a0 = proof.proof_zero_pad
    b0 = proof.proof_zero_data
    c_corrupt = hash_elems(
        context.crypto_extended_base_hash, alpha, beta, a0, b0, a_corrupt, b_corrupt
    )
    c0 = proof.proof_zero_challenge
    c1_corrupt = a_minus_b_q(c_corrupt, c0)
    # The equation in the while condition should easily fail
    while mult_p(
        g_pow_p(c1_corrupt),
        pow_p(context.elgamal_public_key, a_plus_bc_q(nonce_a, r, c1_corrupt)),
    ) == mult_p(b_corrupt, pow_p(beta, c1_corrupt)):
        b_corrupt = mult_p(b_corrupt, get_generator())
        c_corrupt = hash_elems(
            context.crypto_extended_base_hash, alpha, beta, a0, b0, a_corrupt, b_corrupt
        )
        c1_corrupt = a_minus_b_q(c_corrupt, c0)
    v_corrupt = a_plus_bc_q(nonce_a, r, c1_corrupt)

    proof_corrupt = DisjunctiveChaumPedersenProof(
        proof_zero_pad=a0,
        proof_zero_data=b0,
        proof_one_pad=a_corrupt,
        proof_one_data=b_corrupt,
        proof_zero_challenge=c0,
        proof_one_challenge=c1_corrupt,
        challenge=c_corrupt,
        proof_zero_response=proof.proof_zero_response,
        proof_one_response=v_corrupt,
    )

    # Override selection proof and other values for ciphertext and submitted ballots
    replacements = {"proof": proof_corrupt}
    corrupt_selection_and_serialize_ballot(
        _cex, ciphertext, ballot_id, contest_idx, selection_idx, replacements
    )
    corrupt_selection_and_serialize_ballot(
        _cex,
        ballot,
        ballot_id,
        contest_idx,
        selection_idx,
        replacements,
        is_cipher=False,
    )
