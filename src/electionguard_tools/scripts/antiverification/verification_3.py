#!/usr/bin/env python
from os import listdir, path, remove

from electionguard.ballot import (
    BallotBoxState,
    CiphertextBallot,
    PlaintextBallot,
    SubmittedBallot,
    create_ballot_hash,
    make_ciphertext_ballot,
    make_ciphertext_ballot_contest,
    make_ciphertext_ballot_selection,
    make_ciphertext_submitted_ballot,
)
from electionguard.ballot_code import get_ballot_code
from electionguard.chaum_pedersen import ConstantChaumPedersenProof
from electionguard.constants import get_generator
from electionguard.election import CiphertextElectionContext
from electionguard.elgamal import ElGamalCiphertext, elgamal_encrypt
from electionguard.group import ONE_MOD_Q, ElementModQ, add_q, mult_p, negate_q
from electionguard.guardian import GuardianRecord, GuardianId
from electionguard.manifest import Manifest
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
    SUBMITTED_BALLOT_PREFIX,
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
    get_submitted_pseudonym,
    import_ballot_from_files,
    import_private_guardian_data,
    spoil_ballot,
)


def antiverify_3(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
    guardian_id: GuardianId,
) -> None:
    """
    For each subcheck in Verification 3, generate an election record
    which fails only that subcheck.
    """
    seed = ElementModQ(3)
    nonces = Nonces(seed)
    antiverify_3_a(_data, manifest, context, ballot_id, guardian_id, nonces)


def antiverify_3_a(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
    guardian_id: GuardianId,
    nonces: Nonces,
) -> None:
    """
    Generate an election record which fails only Verification (3.A).
    To this end, we scale a guardian's public key and adjust its
    partial decryption shares, as well as the resulting decryptions
    which change wildly. To preserve well-formedness of
    spoiled ballots under the wild tally changes, spoiled ballots
    must have particular encryption nonces; we delete all spoiled
    ballots then duplicate, re-encrypt, then spoil another ballot
    to exemplify a spoiled ballot that is valid after the wild changes.

    This example requires access to private election data for ciphertext
    ballots and the guardian secret key.
    """
    _cex = duplicate_election_data(_data, "3", "A")
    public_record = from_file(
        GuardianRecord,
        path.join(
            _cex,
            ELECTION_RECORD_DIR,
            GUARDIANS_DIR,
            GUARDIAN_PREFIX + guardian_id + ".json",
        ),
    )
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )

    # Recompute values
    public_record.election_public_key = mult_p(
        public_record.election_public_key, get_generator()
    )
    guardian_secret_key = add_q(
        import_private_guardian_data(_cex, context)[0][
            guardian_id
        ].election_keys.key_pair.secret_key,
        ONE_MOD_Q,
    )

    # Serialize
    to_file(
        public_record,
        GUARDIAN_PREFIX + guardian_id,
        path.join(_cex, ELECTION_RECORD_DIR, GUARDIANS_DIR),
    )

    n = 0
    for contest_id, pt_contest in tally.contests.items():
        for selection_id, pt_selection in pt_contest.selections.items():
            # Adjust partial decryption shares
            edit_and_prove_selection_shares(
                context,
                tally,
                contest_id,
                selection_id,
                guardian_id,
                guardian_secret_key,
                nonces[n],
            )
            n += 1
            # Adjust plaintext tally
            add_plaintext_vote(
                pt_selection,
                get_accumulation_pad_power(_cex, contest_id, selection_id, negate=True),
            )
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))

    # Delete spoiled ballots
    spoiled_ballot_path = path.join(_cex, ELECTION_RECORD_DIR, SPOILED_BALLOTS_DIR)
    for filename in listdir(spoiled_ballot_path):
        remove(path.join(spoiled_ballot_path, filename))
    for filename in listdir(
        path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR)
    ):
        ballot = from_file(
            SubmittedBallot,
            path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR, filename),
        )
        if ballot.state == BallotBoxState.SPOILED:
            remove(
                path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR, filename)
            )

    # Construct spoiled ballot as a duplicate plaintext with control over
    # the encryption nonce determining the ciphertext ballot
    # Intake ballot to be duplicated
    _, ciphertext, plaintext = import_ballot_from_files(
        _cex, ballot_id, ciphertext_data=True, plaintext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)
    assert isinstance(plaintext, PlaintextBallot)

    # Duplicate submitted ballot under pseudonym filename
    _, duplicate_id = get_submitted_pseudonym(_cex, ballot_id, nonces[n])
    n += 1

    # Re-encrypt each contest selection according to plaintext value
    # and update hashes
    for i, contest in enumerate(ciphertext.contests):
        for j, selection in enumerate(contest.ballot_selections):
            # Find plaintext value
            pt_contest_idx, pt_selection_idx = get_selection_index_by_id(
                plaintext, contest.object_id, selection.object_id
            )
            t = (
                (
                    plaintext.contests[pt_contest_idx]
                    .ballot_selections[pt_selection_idx]
                    .vote
                )
                if pt_selection_idx != -1
                else 0
            )
            # Determine encryption nonce and re-encrypt selection
            R = ONE_MOD_Q if t == 1 else negate_q(ONE_MOD_Q)
            ciphertext_R = elgamal_encrypt(t, R, context.elgamal_public_key)
            assert isinstance(ciphertext_R, ElGamalCiphertext)
            contest.ballot_selections[j] = make_ciphertext_ballot_selection(
                selection.object_id,
                selection.sequence_order,
                selection.description_hash,
                ciphertext_R,
                context.elgamal_public_key,
                context.crypto_extended_base_hash,
                nonces[n],
                t,
                is_placeholder_selection=selection.is_placeholder_selection,
                nonce=R,
            )
            n += 1
        # Refresh contest accumulation and hash
        assert isinstance(contest.proof, ConstantChaumPedersenProof)
        ciphertext.contests[i] = make_ciphertext_ballot_contest(
            contest.object_id,
            contest.sequence_order,
            contest.description_hash,
            contest.ballot_selections,
            context.elgamal_public_key,
            context.crypto_extended_base_hash,
            nonces[n],
            contest.proof.constant,
        )
        n += 1
    duplicate_ciphertext = make_ciphertext_ballot(
        duplicate_id,
        ciphertext.style_id,
        ciphertext.manifest_hash,
        ciphertext.code_seed,
        ciphertext.contests,
        timestamp=ciphertext.timestamp,
    )
    to_file(
        duplicate_ciphertext,
        CIPHERTEXT_BALLOT_PREFIX + duplicate_id,
        path.join(_cex, PRIVATE_DATA_DIR, CIPHERTEXT_BALLOTS_DIR),
    )
    duplicate_ballot = make_ciphertext_submitted_ballot(
        duplicate_id,
        ciphertext.style_id,
        ciphertext.manifest_hash,
        ciphertext.code_seed,
        ciphertext.contests,
        ballot_code=get_ballot_code(
            ciphertext.code_seed,
            ciphertext.timestamp,
            create_ballot_hash(
                ciphertext.object_id, ciphertext.manifest_hash, ciphertext.contests
            ),
        ),
        timestamp=ciphertext.timestamp,
        state=BallotBoxState.SPOILED,
    )
    to_file(
        duplicate_ballot,
        SUBMITTED_BALLOT_PREFIX + duplicate_id,
        path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR),
    )

    # Compute, edit, and publish spoil of duplicate ballot
    _ = spoil_ballot(
        _cex,
        manifest,
        context,
        duplicate_ballot,
        import_private_guardian_data(
            _cex,
            context,
            ballot_for_shares=duplicate_ballot,
        )[2],
        spoiled_suffix=duplicate_id,
    )

    # Adjust spoiled ballot
    for filename in listdir(spoiled_ballot_path):
        spoiled_ballot = from_file(
            PlaintextTally, path.join(spoiled_ballot_path, filename)
        )
        ciphertext = from_file(
            CiphertextBallot,
            path.join(
                _cex,
                PRIVATE_DATA_DIR,
                CIPHERTEXT_BALLOTS_DIR,
                CIPHERTEXT_BALLOT_PREFIX + spoiled_ballot.object_id + ".json",
            ),
        )
        for contest_id, pt_contest in spoiled_ballot.contests.items():
            for selection_id, pt_selection in pt_contest.selections.items():
                # Adjust partial decryption shares
                edit_and_prove_selection_shares(
                    context,
                    spoiled_ballot,
                    contest_id,
                    selection_id,
                    guardian_id,
                    guardian_secret_key,
                    nonces[n],
                )
                n += 1
                # Adjust plaintext tally
                contest_idx, selection_idx = get_selection_index_by_id(
                    ciphertext, contest_id, selection_id
                )
                R = (
                    ciphertext.contests[contest_idx]
                    .ballot_selections[selection_idx]
                    .nonce
                )
                add_plaintext_vote(pt_selection, negate_q(R))
        to_file(spoiled_ballot, filename[:-5], spoiled_ballot_path)
