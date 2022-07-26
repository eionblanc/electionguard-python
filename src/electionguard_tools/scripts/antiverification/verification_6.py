#!/usr/bin/env python
from os import path
from copy import deepcopy

from electionguard.ballot import (
    CiphertextBallot,
    PlaintextBallot,
    make_ciphertext_submitted_ballot,
    create_ballot_hash,
    get_ballot_code,
)
from electionguard.ballot_box import BallotBoxState
from electionguard.election import CiphertextElectionContext
from electionguard.group import (
    ElementModQ,
    a_minus_b_q,
    mult_p,
    div_p,
    mult_inv_p,
    negate_q,
)
from electionguard.manifest import Manifest
from electionguard.nonces import Nonces
from electionguard.serialize import to_file, from_file
from electionguard.tally import PlaintextTally, PublishedCiphertextTally
from electionguard_tools.helpers.export import (
    ELECTION_RECORD_DIR,
    SUBMITTED_BALLOTS_DIR,
    SUBMITTED_BALLOT_PREFIX,
    ENCRYPTED_TALLY_FILE_NAME,
    TALLY_FILE_NAME,
)
from electionguard_tools.scripts.antiverification.processing import (
    corrupt_selection_accumulation,
    duplicate_election_data,
    get_contest_index_by_id,
    get_selection_index_by_id,
    import_ballot_from_files,
    get_submitted_pseudonym,
    import_private_guardian_data,
    spoil_ballot,
    edit_and_prove_shares,
    add_plaintext_vote,
)


def antiverify_6(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_0: str,
    selection_id_1: str,
) -> None:
    """
    For each subcheck in Verification 6, generate an election record
    which fails only that subcheck.
    Ballot hash values are not currently re-computed.

    An appropriate ballot and contest is one which is not an undervote
    and for which there is a ciphertext ballot available.
    """
    seed = ElementModQ(6)
    nonces = Nonces(seed)
    antiverify_6_a(
        _data, context, ballot_id, contest_id, selection_id_0, selection_id_1
    )
    antiverify_6_b(_data, manifest, context, ballot_id, nonces[0])


def antiverify_6_a(
    _data: str,
    context: CiphertextElectionContext,
    ballot_id: str,
    contest_id: str,
    selection_id_0: str,
    selection_id_1: str,
) -> None:
    """
    Generate an election record which fails only Verification (6.A).
    To this end, we switch votes between two selections on a particular
    cast ballot and contest. We do not update the selection (or contest
    or ballot) hashes, so the resulting ballot fails (6.A). To satisfy
    the remaining checks, we update the accumulation ciphertext,
    partial decryption shares, and plaintext tally.

    This example uses access to private election data for the ciphertext
    and plaintext ballots. Simpler examples could be constructed
    solely with public data.
    """
    # Intake ballot to have votes swapped
    _cex = duplicate_election_data(_data, "6", "A")
    ballot, ciphertext, _ = import_ballot_from_files(
        _cex,
        ballot_id,
        ciphertext_data=True,
    )
    assert isinstance(ciphertext, CiphertextBallot)

    ballot_corrupt = deepcopy(ballot)
    contest_idx, selection_idx_0 = get_selection_index_by_id(
        ballot_corrupt, contest_id, selection_id_0
    )
    _, selection_idx_1 = get_selection_index_by_id(
        ballot_corrupt, contest_id, selection_id_1
    )
    corrupt_selections = [
        ballot_corrupt.contests[contest_idx].ballot_selections[selection_idx_0],
        ballot_corrupt.contests[contest_idx].ballot_selections[selection_idx_1],
    ]
    true_selections = [
        ciphertext.contests[contest_idx].ballot_selections[selection_idx_0],
        ciphertext.contests[contest_idx].ballot_selections[selection_idx_1],
    ]

    # Swap selection ciphertexts, nonces, and proofs among selections in contest
    for j, selection in enumerate(corrupt_selections):
        selection.ciphertext = true_selections[1 - j].ciphertext
        selection.proof = true_selections[1 - j].proof

    # Corrupted selections now encode opposite of variable name suffix
    to_file(
        ballot_corrupt,
        SUBMITTED_BALLOT_PREFIX + ballot_id,
        path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR),
    )

    ciphertext_tally = from_file(
        PublishedCiphertextTally,
        path.join(_cex, ELECTION_RECORD_DIR, ENCRYPTED_TALLY_FILE_NAME + ".json"),
    )
    private_records, guardians, _ = import_private_guardian_data(_cex, context)
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    selection_ids = [selection_id_0, selection_id_1]
    for x in [0, 1]:
        y = 1 - x
        # Adjust accumulation
        corrupt_selection_accumulation(
            ciphertext_tally,
            contest_id,
            selection_ids[x],
            mult_p(
                true_selections[y].ciphertext.pad,
                mult_inv_p(true_selections[x].ciphertext.pad),
            ),
            mult_p(
                true_selections[y].ciphertext.data,
                mult_inv_p(true_selections[x].ciphertext.data),
            ),
        )
        # Adjust partial decryption shares
        selection_tally = tally.contests[contest_id].selections[selection_ids[x]]
        # Edit ciphertext messages
        selection_tally.message.pad = mult_p(
            selection_tally.message.pad,
            true_selections[y].ciphertext.pad,
            mult_inv_p(true_selections[x].ciphertext.pad),
        )
        selection_tally.message.data = mult_p(
            selection_tally.message.data,
            true_selections[y].ciphertext.data,
            mult_inv_p(true_selections[x].ciphertext.data),
        )
        # Edit shares and reconstruct proofs
        edit_and_prove_shares(
            context,
            selection_tally,
            private_records,
            guardians,
            a_minus_b_q(true_selections[y].nonce, true_selections[x].nonce),
            true_selections[x].nonce,
        )
        # Edit actual tally count
        add_plaintext_vote(selection_tally, y - x)

    to_file(
        ciphertext_tally,
        ENCRYPTED_TALLY_FILE_NAME,
        path.join(_cex, ELECTION_RECORD_DIR),
    )
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))


def antiverify_6_b(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
    nonce: ElementModQ,
) -> None:
    """
    Generate an election record which fails only Verification (6.B).
    To this end, we duplicate and spoil a cast ballot under a nonsensical
    filename that does not align with its object_id.
    Since the ballot is spoiled, we remove its vote from the accumulation
    (contributed by the original cast ballot) and adjust the partial
    decryption shares and tally accordingly.
    Finally, we publish the ballot spoil.
    No ballot hashes need to be updated.

    This example requires access to private election data for the ciphertext
    and plaintext ballots as well as the secret guardian keys for decryption.
    """
    # Intake ballot to be duplicated
    _cex = duplicate_election_data(_data, "6", "B")
    ballot, ciphertext, plaintext = import_ballot_from_files(
        _cex, ballot_id, ciphertext_data=True, plaintext_data=True
    )
    assert isinstance(ciphertext, CiphertextBallot)
    assert isinstance(plaintext, PlaintextBallot)

    # Duplicate submitted ballot under pseudonym filename
    _, duplicate_id = get_submitted_pseudonym(_cex, ballot_id, nonce)
    duplicate = make_ciphertext_submitted_ballot(
        ballot.object_id,
        ballot.style_id,
        ballot.manifest_hash,
        ballot.code_seed,
        ballot.contests,
        ballot_code=get_ballot_code(
            ballot.code_seed,
            ballot.timestamp,
            create_ballot_hash(ballot.object_id, ballot.manifest_hash, ballot.contests),
        ),
        timestamp=ballot.timestamp,
        state=BallotBoxState.SPOILED,
    )
    to_file(
        duplicate,
        SUBMITTED_BALLOT_PREFIX + duplicate_id,
        path.join(_cex, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR),
    )

    # Edit accumulation ciphertext for each contest and selection
    # Iterate through contests > selections from encrypted_tally.json, dividing by duplicated ballot
    ciphertext_tally = from_file(
        PublishedCiphertextTally,
        path.join(_cex, ELECTION_RECORD_DIR, ENCRYPTED_TALLY_FILE_NAME + ".json"),
    )
    for contest in ballot.contests:
        for selection in contest.ballot_selections:
            if not selection.is_placeholder_selection:
                # With published spoil, both the cast ballot and its spoiled duplicate
                # will be considered spoiled and thus left uncounted
                corrupt_selection_accumulation(
                    ciphertext_tally,
                    contest.object_id,
                    selection.object_id,
                    mult_inv_p(selection.ciphertext.pad),
                    mult_inv_p(selection.ciphertext.data),
                )
    to_file(
        ciphertext_tally,
        ENCRYPTED_TALLY_FILE_NAME,
        path.join(_cex, ELECTION_RECORD_DIR),
    )

    # Import private guardian data
    private_records, guardians, shares = import_private_guardian_data(
        _cex,
        context,
        ballot_for_shares=duplicate,
    )

    # Compute and export spoil of duplicate
    _ = spoil_ballot(
        _cex,
        manifest,
        context,
        duplicate,
        shares,
        spoiled_suffix=duplicate_id,
    )

    # Edit plaintext tally
    # Iterate through contests > selections > shares from tally.json, dividing by duplicate ballot
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    for contest in ciphertext.contests:
        pt_contest_idx = get_contest_index_by_id(plaintext, contest.object_id)
        pt_contest = plaintext.contests[pt_contest_idx]
        for selection in contest.ballot_selections:
            if not selection.is_placeholder_selection:
                selection_tally = tally.contests[contest.object_id].selections[
                    selection.object_id
                ]
                # Edit ciphertext message
                selection_tally.message.pad = div_p(
                    selection_tally.message.pad, selection.ciphertext.pad
                )
                selection_tally.message.data = div_p(
                    selection_tally.message.data, selection.ciphertext.data
                )
                # Edit shares and reconstruct proofs
                edit_and_prove_shares(
                    context,
                    selection_tally,
                    private_records,
                    guardians,
                    negate_q(selection.nonce),
                    selection.nonce,
                )
                # Edit actual tally count by subtracting off spoiled vote
                _, pt_selection_idx = get_selection_index_by_id(
                    plaintext,
                    pt_contest_idx,
                    selection.object_id,
                )
                if pt_selection_idx != -1:
                    pt_selection = pt_contest.ballot_selections[pt_selection_idx]
                    add_plaintext_vote(selection_tally, -pt_selection.vote)
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))
