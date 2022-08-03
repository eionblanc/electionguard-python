#!/usr/bin/env python
from importlib import reload
from os import listdir, path, environ
import shutil
from typing import Dict, List

from electionguard.ballot import (
    BallotBoxState,
    CiphertextBallot,
    PlaintextBallot,
    SubmittedBallot,
)
from electionguard.ballot_box import BallotBox, get_ballots
import electionguard.constants
from electionguard.constants import ElectionConstants, get_constants
from electionguard.data_store import DataStore
from electionguard.decryption_mediator import DecryptionMediator
from electionguard.decryption_share import DecryptionShare
from electionguard.election import CiphertextElectionContext
from electionguard.election_polynomial import LagrangeCoefficientsRecord
from electionguard.encrypt import EncryptionDevice, EncryptionMediator
from electionguard.group import ElementModP, mult_p
from electionguard.guardian import Guardian
from electionguard.key_ceremony import (
    ElectionJointKey,
    ElectionPartialKeyBackup,
    ElectionPartialKeyVerification,
)
from electionguard.key_ceremony_mediator import KeyCeremonyMediator
from electionguard.manifest import InternalManifest, Manifest
from electionguard.serialize import from_file, to_file
from electionguard.tally import CiphertextTally, PlaintextTally, tally_ballots
from electionguard_tools.helpers.election_builder import ElectionBuilder
from electionguard_tools.helpers.export import (
    CONSTANTS_FILE_NAME,
    DEVICES_DIR,
    ELECTION_RECORD_DIR,
    PRIVATE_DATA_DIR,
    SUBMITTED_BALLOTS_DIR,
    export_private_data,
    export_record,
)
from electionguard_tools.scripts.antiverification.processing import (
    PLAINTEXT_BALLOTS_DIR,
    duplicate_election_data,
)


def antiverify_1(
    run_selection: str,
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
) -> None:
    """
    For each subcheck in Verification 1, generate an election record
    which fails only that subcheck.
    """
    if run_selection == "Standard":
        antiverify_1_c(_data)
    elif run_selection == "1B":
        print("Running (1.B)...")
        antiverify_1_b(_data, manifest, context)
        print("...done!")
    elif run_selection == "1D":
        print("Running (1.D)...")
        antiverify_1_d(_data, manifest, context)
        print("...done!")


def antiverify_1_b(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
) -> None:
    """
    Generate an election record which fails only Verification (1.B).
    To this end, we adjust the small prime and cofactor constants then
    re-run the election.
    Currently, the imported (nonstandard) constants are not restored to
    the usual test constants; no other verification checks should be
    run after this.

    This example requires access to private election data for the plaintext
    ballots and guardian keys.
    """
    environ["PRIME_OPTION"] = "Antiverification_1_b"
    reload(electionguard.constants)
    _cex = duplicate_election_data(_data, "1", "B")
    rerun_election(_cex, manifest, context)


def antiverify_1_c(_data: str) -> None:
    """
    Generate an election record which fails only Verification (1.C).
    To this end, we adjust the generator contstant, but not any of the
    election encryptions.

    This example requires no access to private election data.
    """
    _cex = duplicate_election_data(_data, "1", "C")
    constants = from_file(
        ElectionConstants,
        path.join(_cex, ELECTION_RECORD_DIR, CONSTANTS_FILE_NAME + ".json"),
    )
    constants.cofactor = mult_p(ElementModP(constants.cofactor), ElementModP(2))
    to_file(constants, CONSTANTS_FILE_NAME, path.join(_cex, ELECTION_RECORD_DIR))


def antiverify_1_d(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
) -> None:
    """
    Generate an election record which fails only Verification (1.D).
    To this end, we adjust the generator constant then re-run the election.
    Currently, the imported (nonstandard) constants are not restored to
    the usual test constants; no other verification checks should be
    run after this.

    This example requires access to private election data for the plaintext
    ballots and guardian keys.
    """
    environ["PRIME_OPTION"] = "Antiverification_1_d"
    reload(electionguard.constants)
    _cex = duplicate_election_data(_data, "1", "D")
    rerun_election(_cex, manifest, context)


# pylint: disable=too-many-statements
def rerun_election(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
) -> None:
    # Get plaintext ballots
    plaintext_ballots: List[PlaintextBallot] = []
    plaintext_ballot_path = path.join(_data, PRIVATE_DATA_DIR, PLAINTEXT_BALLOTS_DIR)
    for filename in listdir(plaintext_ballot_path):
        ballot = from_file(PlaintextBallot, path.join(plaintext_ballot_path, filename))
        plaintext_ballots.append(ballot)

    # Determine which ballots should be spoiled
    spoiled_ballot_ids: List[str] = []
    submitted_ballot_path = path.join(_data, ELECTION_RECORD_DIR, SUBMITTED_BALLOTS_DIR)
    for filename in listdir(submitted_ballot_path):
        submitted_ballot = from_file(
            SubmittedBallot, path.join(submitted_ballot_path, filename)
        )
        if submitted_ballot.state == BallotBoxState.SPOILED:
            spoiled_ballot_ids.append(submitted_ballot.object_id)

    # Re-run election with same guardian information
    election_builder = ElectionBuilder(
        context.number_of_guardians, context.quorum, manifest
    )
    guardians: List[Guardian] = []
    for i in range(context.number_of_guardians):
        guardians.append(
            Guardian.from_nonce(
                str(i + 1), i + 1, context.number_of_guardians, context.quorum
            )
        )

    mediator = KeyCeremonyMediator("mediator_1", guardians[0].ceremony_details)
    for guardian in guardians:
        mediator.announce(guardian.share_key())

    for guardian in guardians:
        announced_keys = mediator.share_announced()
        assert isinstance(announced_keys, List)
        for key in announced_keys:
            if guardian.id is not key.owner_id:
                guardian.save_guardian_key(key)

    for sending_guardian in guardians:
        sending_guardian.generate_election_partial_key_backups()
        backups: List[ElectionPartialKeyBackup] = []
        for designated_guardian in guardians:
            if designated_guardian.id != sending_guardian.id:
                backup = sending_guardian.share_election_partial_key_backup(
                    designated_guardian.id
                )
                assert isinstance(backup, ElectionPartialKeyBackup)
                backups.append(backup)
        mediator.receive_backups(backups)

    for designated_guardian in guardians:
        share_backups = mediator.share_backups(designated_guardian.id)
        assert isinstance(share_backups, List)
        for share_backup in share_backups:
            designated_guardian.save_election_partial_key_backup(share_backup)

    for designated_guardian in guardians:
        verifications = []
        for backup_owner in guardians:
            if designated_guardian.id is not backup_owner.id:
                verification = designated_guardian.verify_election_partial_key_backup(
                    backup_owner.id
                )
                assert isinstance(verification, ElectionPartialKeyVerification)
                verifications.append(verification)
        mediator.receive_backup_verifications(verifications)

    joint_key = mediator.publish_joint_key()
    assert isinstance(joint_key, ElectionJointKey)
    election_builder.set_public_key(joint_key.joint_public_key)
    election_builder.set_commitment_hash(joint_key.commitment_hash)
    build_results = election_builder.build()
    assert build_results is not None
    internal_manifest, context = build_results
    constants = get_constants()
    assert isinstance(internal_manifest, InternalManifest)
    assert isinstance(context, CiphertextElectionContext)

    for filename in listdir(path.join(_data, ELECTION_RECORD_DIR, DEVICES_DIR)):
        # Assume just a single encryption device
        device = from_file(
            EncryptionDevice,
            path.join(_data, ELECTION_RECORD_DIR, DEVICES_DIR, filename),
        )
    encrypter = EncryptionMediator(internal_manifest, context, device)

    ciphertext_ballots: List[CiphertextBallot] = []
    for plaintext_ballot in plaintext_ballots:
        encrypted_ballot = encrypter.encrypt(plaintext_ballot)
        assert isinstance(encrypted_ballot, CiphertextBallot)
        ciphertext_ballots.append(encrypted_ballot)

    ballot_store: DataStore = DataStore()
    ballot_box = BallotBox(internal_manifest, context, ballot_store)

    for cipher_ballot in ciphertext_ballots:
        if cipher_ballot.object_id in spoiled_ballot_ids:
            _ = ballot_box.spoil(cipher_ballot)
        else:
            _ = ballot_box.cast(cipher_ballot)

    ciphertext_tally = tally_ballots(ballot_store, internal_manifest, context)
    assert isinstance(ciphertext_tally, CiphertextTally)
    spoiled_ballots = get_ballots(ballot_store, BallotBoxState.SPOILED)
    spoiled_ballots_list = list(spoiled_ballots.values())
    decryption_mediator = DecryptionMediator("decryption-mediator", context)
    for guardian in guardians:
        guardian_key = guardian.share_key()
        tally_share = guardian.compute_tally_share(ciphertext_tally, context)
        assert isinstance(tally_share, DecryptionShare)
        ballot_shares = guardian.compute_ballot_shares(spoiled_ballots_list, context)
        decryption_mediator.announce(guardian_key, tally_share, ballot_shares)
    lagrange_coefficients = LagrangeCoefficientsRecord(
        decryption_mediator.get_lagrange_coefficients()
    )

    plaintext_tally = decryption_mediator.get_plaintext_tally(
        ciphertext_tally, manifest
    )
    assert isinstance(plaintext_tally, PlaintextTally)
    plaintext_spoiled_ballots = decryption_mediator.get_plaintext_ballots(
        spoiled_ballots_list, manifest
    )
    assert isinstance(plaintext_spoiled_ballots, Dict)

    guardian_records = [guardian.publish() for guardian in guardians]
    private_guardian_records = [
        guardian.export_private_data() for guardian in guardians
    ]

    if path.exists(_data):
        shutil.rmtree(_data)
    export_record(
        manifest,
        context,
        constants,
        [device],
        ballot_store.all(),
        plaintext_spoiled_ballots.values(),
        ciphertext_tally.publish(),
        plaintext_tally,
        guardian_records,
        lagrange_coefficients,
        election_record_directory=path.join(_data, ELECTION_RECORD_DIR),
    )
    export_private_data(
        plaintext_ballots,
        ciphertext_ballots,
        private_guardian_records,
        private_directory=path.join(_data, PRIVATE_DATA_DIR),
    )
