#!/usr/bin/env python
from os import listdir, path

# pylint: disable=no-name-in-module
from gmpy2 import mpz

from electionguard import get_small_prime, get_large_prime
from electionguard.ballot import BallotBoxState, CiphertextBallot, SubmittedBallot
from electionguard.big_integer import BigInteger
from electionguard.chaum_pedersen import ChaumPedersenProof
from electionguard.election import CiphertextElectionContext
from electionguard.group import (
    ONE_MOD_Q,
    ZERO_MOD_Q,
    ElementModQ,
    a_minus_b_q,
    a_plus_bc_q,
    add_q,
    g_pow_p,
    mult_p,
    pow_p,
)
from electionguard.hash import hash_elems
from electionguard.nonces import Nonces
from electionguard.serialize import from_file
from electionguard.tally import PlaintextTally
from electionguard.type import GuardianId
from electionguard_tools.helpers.export import (
    CIPHERTEXT_BALLOT_PREFIX,
    ELECTION_RECORD_DIR,
    PRIVATE_DATA_DIR,
    SUBMITTED_BALLOTS_DIR,
    TALLY_FILE_NAME,
)

from electionguard_tools.scripts.antiverification.processing import (
    CIPHERTEXT_BALLOTS_DIR,
    add_plaintext_vote,
    corrupt_share_and_json_tally,
    corrupt_share_and_serialize_tally,
    duplicate_election_data,
    get_selection_index_by_id,
    get_share_index_by_id,
    import_private_guardian_data,
)


def antiverify_8(
    _data: str,
    context: CiphertextElectionContext,
    contest_id: str,
    selection_id: str,
    guardian_id: GuardianId,
) -> None:
    """
    For each subcheck in Verification 8, generate an election record
    which fails only that subcheck.
    """
    seed = ElementModQ(8)
    nonces = Nonces(seed)
    antiverify_8_a(_data, contest_id, selection_id, guardian_id)
    antiverify_8_b(_data, context, contest_id, selection_id, guardian_id)
    antiverify_8_c(_data, contest_id, selection_id, guardian_id)
    antiverify_8_d(_data, context, contest_id, selection_id, guardian_id, nonces[0])
    antiverify_8_e(_data, context, contest_id, selection_id, guardian_id, nonces[1])


def antiverify_8_a(
    _data: str, contest_id: str, selection_id: str, guardian_id: GuardianId
) -> None:
    """
    Generate an election record which fails only Verification (8.A).
    To this end, we add the small prime to the proof response.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "8", "A")
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection = tally.contests[contest_id].selections[selection_id]
    share_idx = get_share_index_by_id(tally, contest_id, selection_id, guardian_id)
    share = selection.shares[share_idx]
    proof = share.proof
    assert isinstance(proof, ChaumPedersenProof)

    # Recompute values
    response_corrupt = BigInteger(mpz(proof.response.value) + get_small_prime())
    response_corrupt_hex = response_corrupt.to_hex()

    # Override share proof for plaintext tally
    replacements = {"proof_response": response_corrupt_hex}
    corrupt_share_and_json_tally(
        path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json"),
        contest_id,
        selection_id,
        share_idx,
        replacements,
    )


def antiverify_8_b(
    _data: str,
    context: CiphertextElectionContext,
    contest_id: str,
    selection_id: str,
    guardian_id: GuardianId,
) -> None:
    """
    Generate an election record which fails only Verification (8.B).
    To this end, we add the large prime to the proof pad.
    An alternative approach could do the same instead to the proof data.

    This example requires access to the secret guardian key.
    """
    _cex = duplicate_election_data(_data, "8", "B")
    private_records, _, _ = import_private_guardian_data(_cex, context)
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection = tally.contests[contest_id].selections[selection_id]
    share_idx = get_share_index_by_id(tally, contest_id, selection_id, guardian_id)
    share = selection.shares[share_idx]
    A = selection.message.pad
    B = selection.message.data
    m = share.share
    proof = share.proof
    assert isinstance(proof, ChaumPedersenProof)

    # Recompute values
    a = proof.pad
    b = proof.data
    a_corrupt = BigInteger(mpz(a.value) + get_large_prime())
    a_corrupt_hex = a_corrupt.to_hex()

    # Hash hex string from corrupt proof commitment, which does not lie in Z_p
    # and thus cannot be cast to ElementModP. Currently, elements of type BigInteger
    # but not either ElementModP or ElementModQ are hashed as decimal strings, not hex.
    c_corrupt = hash_elems(context.crypto_extended_base_hash, A, B, a_corrupt_hex, b, m)
    v_corrupt = a_plus_bc_q(
        proof.response,
        private_records[guardian_id].election_keys.key_pair.secret_key,
        a_minus_b_q(c_corrupt, proof.challenge),
    )

    # Override share proof for plaintext tally
    replacements = {
        "proof_pad": a_corrupt_hex,
        "proof_challenge": c_corrupt,
        "proof_response": v_corrupt,
    }
    corrupt_share_and_json_tally(
        path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json"),
        contest_id,
        selection_id,
        share_idx,
        replacements,
    )


def antiverify_8_c(
    _data: str, contest_id: str, selection_id: str, guardian_id: GuardianId
) -> None:
    """
    Generate an election record which fails only Verification (8.C).
    To this end, we add the small prime to the proof challenge.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "8", "C")
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection = tally.contests[contest_id].selections[selection_id]
    share_idx = get_share_index_by_id(tally, contest_id, selection_id, guardian_id)
    share = selection.shares[share_idx]
    proof = share.proof
    assert isinstance(proof, ChaumPedersenProof)

    # Recompute values
    challenge_corrupt = BigInteger(mpz(proof.challenge.value) + get_small_prime())
    challenge_corrupt_hex = challenge_corrupt.to_hex()

    # Override share proof for plaintext tally
    replacements = {"proof_challenge": challenge_corrupt_hex}
    corrupt_share_and_json_tally(
        path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json"),
        contest_id,
        selection_id,
        share_idx,
        replacements,
    )


def antiverify_8_d(
    _data: str,
    context: CiphertextElectionContext,
    contest_id: str,
    selection_id: str,
    guardian_id: GuardianId,
    nonce: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (8.D).
    To this end, we select commitments to violate (8.E),
    then carefully pick a response to satisfy (8.D).

    This example requires access to the secret guardian key.
    """
    _cex = duplicate_election_data(_data, "8", "D")
    private_records, _, _ = import_private_guardian_data(_cex, context)
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection = tally.contests[contest_id].selections[selection_id]
    share_idx = get_share_index_by_id(tally, contest_id, selection_id, guardian_id)
    share = selection.shares[share_idx]
    A = selection.message.pad
    B = selection.message.data
    m = share.share
    proof = share.proof
    assert isinstance(proof, ChaumPedersenProof)

    # Recompute values
    a_corrupt = g_pow_p(add_q(nonce, ONE_MOD_Q))
    b = pow_p(A, nonce)
    c_corrupt = hash_elems(context.crypto_extended_base_hash, A, B, a_corrupt, b, m)
    v_corrupt = a_plus_bc_q(
        nonce, private_records[guardian_id].election_keys.key_pair.secret_key, c_corrupt
    )
    proof_corrupt = ChaumPedersenProof(
        pad=a_corrupt,
        data=b,
        challenge=c_corrupt,
        response=v_corrupt,
        usage=proof.usage,
    )

    # Override share proof for plaintext tally
    replacements = {"proof": proof_corrupt}
    corrupt_share_and_serialize_tally(
        _cex,
        tally,
        contest_id,
        selection_id,
        share_idx,
        replacements,
    )


def antiverify_8_e(
    _data: str,
    context: CiphertextElectionContext,
    contest_id: str,
    selection_id: str,
    guardian_id: GuardianId,
    nonce: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (8.E).
    To this end, we select commitments to violate (8.D),
    then carefully pick a response to satisfy (8.E).
    This wildly affects the tally.

    This example requires access to the secret guardian key.
    """
    _cex = duplicate_election_data(_data, "8", "E")
    private_records, _, _ = import_private_guardian_data(_cex, context)
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection = tally.contests[contest_id].selections[selection_id]
    share_idx = get_share_index_by_id(tally, contest_id, selection_id, guardian_id)
    share = selection.shares[share_idx]
    A = selection.message.pad
    B = selection.message.data
    m = share.share
    proof = share.proof
    assert isinstance(proof, ChaumPedersenProof)

    # Recompute values
    a = g_pow_p(nonce)
    b = pow_p(A, nonce)
    m_corrupt = mult_p(m, A)
    c_corrupt = hash_elems(context.crypto_extended_base_hash, A, B, a, b, m_corrupt)
    v_corrupt = a_plus_bc_q(
        nonce, private_records[guardian_id].election_keys.key_pair.secret_key, c_corrupt
    )
    proof_corrupt = ChaumPedersenProof(
        pad=a,
        data=b,
        challenge=c_corrupt,
        response=v_corrupt,
        usage=proof.usage,
    )

    # Adjust plaintext tally
    negated_R = ZERO_MOD_Q
    submitted_ballot_path = path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR)
    for filename in listdir(submitted_ballot_path):
        ballot = from_file(SubmittedBallot, path.join(submitted_ballot_path, filename))
        if ballot.state == BallotBoxState.CAST:
            # Ballot was cast and thus counted in accumulation tally (if voted in contest)
            ciphertext = from_file(
                CiphertextBallot,
                path.join(
                    _data,
                    PRIVATE_DATA_DIR,
                    CIPHERTEXT_BALLOTS_DIR,
                    CIPHERTEXT_BALLOT_PREFIX + ballot.object_id + ".json",
                ),
            )
            contest_idx, selection_idx = get_selection_index_by_id(
                ciphertext, contest_id, selection_id
            )
            if contest_idx != -1:
                r = (
                    ciphertext.contests[contest_idx]
                    .ballot_selections[selection_idx]
                    .nonce
                )
                negated_R = a_minus_b_q(negated_R, r)
    add_plaintext_vote(selection, negated_R)

    # Override share proof for plaintext tally
    replacements = {"proof": proof_corrupt, "share": m_corrupt}
    corrupt_share_and_serialize_tally(
        _cex,
        tally,
        contest_id,
        selection_id,
        share_idx,
        replacements,
    )
