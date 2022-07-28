#!/usr/bin/env python
from os import listdir, path, remove
from typing import Iterable

from electionguard.ballot import BallotBoxState, CiphertextBallot, SubmittedBallot
from electionguard.constants import get_generator
from electionguard.election import CiphertextElectionContext
from electionguard.group import ONE_MOD_Q, ElementModQ, add_q, mult_p, negate_q
from electionguard.guardian import GuardianRecord, GuardianId
from electionguard.nonces import Nonces
from electionguard.serialize import from_file, to_file
from electionguard.tally import PlaintextTally
from electionguard_tools.helpers.export import (
    CIPHERTEXT_BALLOT_PREFIX,
    ELECTION_RECORD_DIR,
    GUARDIAN_PREFIX,
    GUARDIANS_DIR,
    PRIVATE_DATA_DIR,
    SPOILED_BALLOTS_DIR,
    SUBMITTED_BALLOTS_DIR,
    TALLY_FILE_NAME,
)
from electionguard_tools.scripts.antiverification.processing import (
    CIPHERTEXT_BALLOTS_DIR,
    add_plaintext_vote,
    duplicate_election_data,
    edit_and_prove_selection_shares,
    get_accumulation_pad_power,
    get_selection_index_by_id,
    import_private_guardian_data,
)


def antiverify_3(
    _data: str,
    context: CiphertextElectionContext,
    guardian_id: GuardianId,
) -> None:
    """
    For each subcheck in Verification 3, generate an election record
    which fails only that subcheck.
    """
    seed = ElementModQ(3)
    nonces = iter(Nonces(seed))
    antiverify_3_a(_data, context, guardian_id, nonces)


def antiverify_3_a(
    _data: str,
    context: CiphertextElectionContext,
    guardian_id: GuardianId,
    nonces: Iterable[ElementModQ],
) -> None:
    """
    Generate an election record which fails only Verification (3.A).
    To this end, we scale a guardian's public key and adjust its
    partial decryption shares, as well as the resulting decryptions
    which change wildly, accordingly. To preserve well-formedness of
    spoiled ballots under the wild tally changes, all spoiled ballots
    and their corresponding submitted ballots are deleted.

    This example requires access to private election data for ciphertext
    ballots and the guardian secret key.
    """
    _cex = duplicate_election_data(_data, "3", "A")
    guardian_filename = path.join(
        _cex,
        ELECTION_RECORD_DIR,
        GUARDIANS_DIR,
        GUARDIAN_PREFIX + guardian_id + ".json",
    )
    public_record = from_file(GuardianRecord, guardian_filename)
    private_records, _, _ = import_private_guardian_data(_cex, context)
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )

    # Recompute values
    public_record.election_public_key = mult_p(
        public_record.election_public_key, get_generator()
    )
    guardian_secret_key = add_q(
        private_records[guardian_id].election_keys.key_pair.secret_key, ONE_MOD_Q
    )

    # Serialize
    to_file(
        public_record,
        GUARDIAN_PREFIX + guardian_id,
        path.join(_cex, ELECTION_RECORD_DIR, GUARDIANS_DIR),
    )

    for contest_id, contest in tally.contests.items():
        for selection_id, selection in contest.selections.items():
            nonce = next(nonces)
            # Adjust partial decryption shares
            edit_and_prove_selection_shares(
                context,
                tally,
                contest_id,
                selection_id,
                guardian_id,
                guardian_secret_key,
                nonce,
            )
            # Adjust plaintext tally
            add_plaintext_vote(
                selection,
                get_accumulation_pad_power(_cex, contest_id, selection_id, negate=True),
            )
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))

    # Delete spoiled ballots
    spoiled_ballot_path = path.join(_cex, ELECTION_RECORD_DIR, SPOILED_BALLOTS_DIR)
    for filename in listdir(spoiled_ballot_path):
        remove(path.join(spoiled_ballot_path, filename))
    submitted_ballot_path = path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR)
    for filename in listdir(submitted_ballot_path):
        ballot = from_file(SubmittedBallot, path.join(submitted_ballot_path, filename))
        if ballot.state == BallotBoxState.SPOILED:
            remove(path.join(submitted_ballot_path, filename))
