#!/usr/bin/env python
from os import path, listdir
from typing import Dict

from electionguard.ballot import (
    CiphertextBallot,
    PlaintextBallot,
    make_ciphertext_submitted_ballot,
    create_ballot_hash,
    get_ballot_code,
)
from electionguard.ballot_box import BallotBoxState
from electionguard.chaum_pedersen import make_chaum_pedersen
from electionguard.decrypt_with_shares import decrypt_ballot
from electionguard.decryption import (
    DecryptionShare,
    compute_decryption_share_for_ballot,
)
from electionguard.election import CiphertextElectionContext
from electionguard.group import (
    ElementModP,
    ElementModQ,
    div_p,
    g_pow_p,
    pow_p,
)
from electionguard.guardian import (
    Guardian,
    GuardianId,
    PrivateGuardianRecord,
)
from electionguard.manifest import Manifest
from electionguard.nonces import Nonces
from electionguard.serialize import to_file, from_file
from electionguard.tally import PlaintextTally, PublishedCiphertextTally
from electionguard_tools.helpers.export import (
    ELECTION_RECORD_DIR,
    PRIVATE_DATA_DIR,
    SUBMITTED_BALLOTS_DIR,
    SUBMITTED_BALLOT_PREFIX,
    SPOILED_BALLOTS_DIR,
    SPOILED_BALLOT_PREFIX,
    ENCRYPTED_TALLY_FILE_NAME,
    TALLY_FILE_NAME,
)
from electionguard_tools.scripts.antiverification.processing import (
    duplicate_election_data,
    import_ballot_from_files,
    get_submitted_pseudonym,
)


def antiverify_6(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot_id: str,
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
    antiverify_6_b(_data, manifest, context, ballot_id, nonces[0])


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
                acc_ciphertext = (
                    ciphertext_tally.contests[contest.object_id]
                    .selections[selection.object_id]
                    .ciphertext
                )
                # With published spoil, both the cast ballot and its spoiled duplicate
                # will be considered spoiled and thus left uncounted
                acc_ciphertext.pad = div_p(acc_ciphertext.pad, selection.ciphertext.pad)
                acc_ciphertext.data = div_p(
                    acc_ciphertext.data, selection.ciphertext.data
                )
    to_file(
        ciphertext_tally,
        ENCRYPTED_TALLY_FILE_NAME,
        path.join(_cex, ELECTION_RECORD_DIR),
    )

    # Import private guardian data
    shares: Dict[GuardianId, DecryptionShare] = {}
    guardians: Dict[GuardianId, Guardian] = {}
    private_records: Dict[GuardianId, PrivateGuardianRecord] = {}
    private_guardian_directory = path.join(_cex, PRIVATE_DATA_DIR, "private_guardians")
    for filename in listdir(private_guardian_directory):
        private_record = from_file(
            PrivateGuardianRecord, path.join(private_guardian_directory, filename)
        )
        private_records[private_record.guardian_id] = private_record
        guardians[private_record.guardian_id] = Guardian.from_private_record(
            private_record,
            context.number_of_guardians,
            context.quorum,
        )
        guardian_ballot_share = compute_decryption_share_for_ballot(
            private_record.election_keys,
            duplicate,
            context,
        )
        if guardian_ballot_share:
            shares[private_record.guardian_id] = guardian_ballot_share

    # Compute and export spoil of duplicate
    duplicate_spoiled = decrypt_ballot(
        duplicate,
        shares,
        context.crypto_extended_base_hash,
        manifest,
    )
    to_file(
        duplicate_spoiled,
        SPOILED_BALLOT_PREFIX + duplicate_id,
        path.join(_cex, ELECTION_RECORD_DIR, SPOILED_BALLOTS_DIR),
    )

    # Edit plaintext tally
    # Iterate through contests > selections > shares from tally.json, dividing by duplicate ballot
    tally = from_file(
        PlaintextTally, path.join(_cex, ELECTION_RECORD_DIR, TALLY_FILE_NAME + ".json")
    )
    for contest in ciphertext.contests:
        for selection in contest.ballot_selections:
            if not selection.is_placeholder_selection:
                selection_tally = tally.contests[contest.object_id].selections[
                    selection.object_id
                ]
                # Edit actual tally count
                for pt_contest in plaintext.contests:
                    if pt_contest.object_id == contest.object_id:
                        for pt_selection in pt_contest.ballot_selections:
                            if pt_selection.object_id == selection.object_id:
                                # Subtract off spoiled vote
                                vote = pt_selection.vote
                                selection_tally.tally = selection_tally.tally - vote
                                selection_tally.value = div_p(
                                    selection_tally.value, g_pow_p(vote)
                                )
                                break
                        break
                # Edit ciphertext message
                selection_tally.message.pad = div_p(
                    selection_tally.message.pad, selection.ciphertext.pad
                )
                selection_tally.message.data = div_p(
                    selection_tally.message.data, selection.ciphertext.data
                )
                # Edit shares and proofs
                nonce = selection.nonce
                for share in selection_tally.shares:
                    guardian = guardians[share.guardian_id]
                    assert isinstance(guardian.share_key().key, ElementModP)
                    share.share = div_p(
                        share.share, pow_p(guardian.share_key().key, nonce)
                    )
                    share.proof = make_chaum_pedersen(
                        selection_tally.message,
                        private_records[
                            share.guardian_id
                        ].election_keys.key_pair.secret_key,
                        share.share,
                        nonce,
                        context.crypto_extended_base_hash,
                    )
    to_file(tally, TALLY_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))
