#!/usr/bin/env python
from os import path

from electionguard.constants import get_generator
from electionguard.election import CiphertextElectionContext
from electionguard.group import ONE_MOD_P, ONE_MOD_Q, ZERO_MOD_Q, ElementModQ, negate_q
from electionguard.nonces import Nonces
from electionguard.serialize import from_file, to_file
from electionguard.tally import PlaintextTally, PublishedCiphertextTally
from electionguard_tools.helpers.export import (
    ELECTION_RECORD_DIR,
    ENCRYPTED_TALLY_FILE_NAME,
    TALLY_FILE_NAME,
)
from electionguard_tools.scripts.antiverification.processing import (
    add_plaintext_vote,
    corrupt_selection_accumulation,
    duplicate_election_data,
    edit_and_prove_shares,
    import_private_guardian_data,
)


def antiverify_7(
    _data: str,
    context: CiphertextElectionContext,
    contest_id: str,
    selection_id: str,
) -> None:
    """
    For each subcheck in Verification 7, generate an election record
    which fails only that subcheck.
    No ballot hashes need to be updated.
    """
    seed = ElementModQ(7)
    nonces = Nonces(seed)
    antiverify_7_a(_data, context, contest_id, selection_id, nonces[0])
    antiverify_7_b(_data, context, contest_id, selection_id, nonces[1])


def antiverify_7_a(
    _data: str,
    context: CiphertextElectionContext,
    contest_id: str,
    selection_id: str,
    nonce: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (7.A).
    To this end, we adjust the accumulation ciphertext pad for a contest
    selection then fix the partial decryption shares accordingly.
    This wildly affects the plaintext tally.

    This example uses access to private election data for the
    guardian secret keys to regenerate Chaum-Pedersen proofs.
    """
    # Intake data
    _cex = duplicate_election_data(_data, "7", "A")
    ciphertext_tally = from_file(
        PublishedCiphertextTally,
        path.join(_cex, ELECTION_RECORD_DIR, ENCRYPTED_TALLY_FILE_NAME + ".json"),
    )
    private_records, guardians, _ = import_private_guardian_data(_cex, context)
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )

    # Adjust accumulation ciphertext
    corrupt_selection_accumulation(
        [ciphertext_tally, tally],
        contest_id,
        selection_id,
        get_generator(),
        ONE_MOD_P,
    )
    # Adjust partial decryption shares
    selection_tally = tally.contests[contest_id].selections[selection_id]
    edit_and_prove_shares(
        context,
        selection_tally,
        private_records,
        guardians,
        ONE_MOD_Q,
        nonce,
    )
    # Edit actual tally count
    for private_record in private_records.values():
        # Secret election key is sum of secret guardian keys
        add_plaintext_vote(
            selection_tally, negate_q(private_record.election_keys.key_pair.secret_key)
        )
    to_file(
        ciphertext_tally,
        ENCRYPTED_TALLY_FILE_NAME,
        path.join(_cex, ELECTION_RECORD_DIR),
    )
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))


def antiverify_7_b(
    _data: str,
    context: CiphertextElectionContext,
    contest_id: str,
    selection_id: str,
    nonce: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (7.A).
    To this end, we adjust the accumulation ciphertext data for a contest
    selection then fix the partial decryption shares accordingly.
    This incrementally affects the plaintext tally.

    This example uses access to private election data for the
    guardian secret keys to regenerate Chaum-Pedersen proofs.
    """
    # Intake data
    _cex = duplicate_election_data(_data, "7", "B")
    ciphertext_tally = from_file(
        PublishedCiphertextTally,
        path.join(_cex, ELECTION_RECORD_DIR, ENCRYPTED_TALLY_FILE_NAME + ".json"),
    )
    private_records, guardians, _ = import_private_guardian_data(_cex, context)
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )

    # Adjust accumulation ciphertext
    corrupt_selection_accumulation(
        [ciphertext_tally, tally],
        contest_id,
        selection_id,
        ONE_MOD_P,
        get_generator(),
    )
    # Adjust partial decryption shares
    selection_tally = tally.contests[contest_id].selections[selection_id]
    edit_and_prove_shares(
        context,
        selection_tally,
        private_records,
        guardians,
        ZERO_MOD_Q,
        nonce,
    )
    # Edit actual tally count
    add_plaintext_vote(selection_tally, 1)
    to_file(
        ciphertext_tally,
        ENCRYPTED_TALLY_FILE_NAME,
        path.join(_cex, ELECTION_RECORD_DIR),
    )
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))
