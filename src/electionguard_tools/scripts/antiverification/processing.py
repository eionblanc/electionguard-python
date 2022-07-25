#!/usr/bin/env python
from os import path, listdir
import shutil
from copy import deepcopy
import json
from typing import Tuple, Optional, Dict, Union

from electionguard.ballot import (
    CiphertextBallot,
    SubmittedBallot,
    PlaintextBallot,
)
from electionguard.big_integer import BigInteger
from electionguard.chaum_pedersen import make_chaum_pedersen
from electionguard.decryption import (
    DecryptionShare,
    compute_decryption_share_for_ballot,
)
from electionguard.decrypt_with_shares import decrypt_ballot
from electionguard.election import CiphertextElectionContext
from electionguard.group import (
    ElementModP,
    ElementModQ,
    g_pow_p,
    pow_p,
    mult_p,
    mult_q,
)
from electionguard.guardian import PrivateGuardianRecord, GuardianId, Guardian
from electionguard.manifest import Manifest
from electionguard.serialize import from_file, to_file
from electionguard.tally import (
    PlaintextTally,
    PublishedCiphertextTally,
    PlaintextTallySelection,
)
from electionguard_tools.helpers.export import (
    PRIVATE_DATA_DIR,
    ELECTION_RECORD_DIR,
    SUBMITTED_BALLOTS_DIR,
    SPOILED_BALLOTS_DIR,
    CIPHERTEXT_BALLOT_PREFIX,
    SUBMITTED_BALLOT_PREFIX,
    PLAINTEXT_BALLOT_PREFIX,
    SPOILED_BALLOT_PREFIX,
)

CIPHERTEXT_BALLOTS_DIR = "ciphertext_ballots"
PLAINTEXT_BALLOTS_DIR = "plaintext_ballots"


def duplicate_election_data(_data: str, check: str, subcheck: str) -> str:
    # Duplicate files into _data + '_failure/{check}/{subcheck}'
    _cex = path.join(_data + "_failure", check, subcheck)
    if path.exists(_cex):
        shutil.rmtree(_cex)
    shutil.copytree(_data, _cex)
    return _cex


def import_ballot_from_files(
    _data: str,
    ballot_id: str,
    ciphertext_data: bool = False,
    plaintext_data: bool = False,
) -> Tuple[SubmittedBallot, Optional[CiphertextBallot], Optional[PlaintextBallot]]:
    # Import submitted ballot to manipulate
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

    ciphertext = (
        from_file(
            CiphertextBallot,
            path.join(
                _data,
                PRIVATE_DATA_DIR,
                CIPHERTEXT_BALLOTS_DIR,
                CIPHERTEXT_BALLOT_PREFIX + ballot_id + ".json",
            ),
        )
        if ciphertext_data
        else None
    )
    plaintext = (
        from_file(
            PlaintextBallot,
            path.join(
                _data,
                PRIVATE_DATA_DIR,
                PLAINTEXT_BALLOTS_DIR,
                PLAINTEXT_BALLOT_PREFIX + ballot_id + ".json",
            ),
        )
        if plaintext_data
        else None
    )
    return ballot, ciphertext, plaintext


def import_private_guardian_data(
    _data: str,
    context: CiphertextElectionContext,
    ballot_for_shares: SubmittedBallot = None,
) -> Tuple[
    Dict[GuardianId, PrivateGuardianRecord],
    Dict[GuardianId, Guardian],
    Dict[GuardianId, DecryptionShare],
]:
    private_guardian_directory = path.join(_data, PRIVATE_DATA_DIR, "private_guardians")
    private_records: Dict[GuardianId, PrivateGuardianRecord] = {}
    guardians: Dict[GuardianId, Guardian] = {}
    shares: Dict[GuardianId, DecryptionShare] = {}
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
        if ballot_for_shares:
            guardian_ballot_share = compute_decryption_share_for_ballot(
                private_record.election_keys,
                ballot_for_shares,
                context,
            )
            if guardian_ballot_share:
                shares[private_record.guardian_id] = guardian_ballot_share
    return private_records, guardians, shares


def get_contest_index_by_id(
    ballot: Union[CiphertextBallot, PlaintextBallot], contest_id: str
) -> int:
    # Step through contests until match is found; this accommodates contests
    # listed out of sequence order as well as contests from compact ballots
    for j, contest in enumerate(ballot.contests):
        if contest.object_id == contest_id:
            return j
    return -1


def get_selection_index_by_id(
    ballot: Union[CiphertextBallot, PlaintextBallot],
    contest_id: Union[str, int],
    selection_id: str,
) -> Tuple[int, int]:
    if isinstance(contest_id, str):
        contest_idx = get_contest_index_by_id(ballot, contest_id)
    else:
        contest_idx = contest_id
    if contest_idx != -1:
        # Step through ballot selections until match is found; this accommodates selections
        # listed out of sequence order as well as contests from compact ballots
        for j, selection in enumerate(ballot.contests[contest_idx].ballot_selections):
            if selection.object_id == selection_id:
                return contest_idx, j
    return contest_idx, -1


def get_corrupt_filenames(_cex: str, ballot_id: str) -> Tuple[str, str]:
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


def get_submitted_pseudonym(
    _cex: str, ballot_id: str, nonce: ElementModQ
) -> Tuple[str, str]:
    fragments = [
        [ElementModQ(BigInteger(s[4 * i : 4 * (i + 1)])) for i in range(len(s) // 4)]
        for s in ballot_id.split("-")
    ]
    fake_fragments = [
        [mult_q(nonce, f).to_hex().lower() for f in fragment] for fragment in fragments
    ]
    fake_id = "-".join(["".join(fragment) for fragment in fake_fragments])
    fake_filename = path.join(
        _cex,
        ELECTION_RECORD_DIR,
        SUBMITTED_BALLOTS_DIR,
        SUBMITTED_BALLOT_PREFIX + fake_id + ".json",
    )
    return fake_filename, fake_id


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


def corrupt_selection_and_serialize_ballot(
    _cex: str,
    ballot: CiphertextBallot,
    ballot_id: str,
    contest_idx: int,
    selection_idx: int,
    replacements: dict,
    is_cipher: bool = True,
) -> None:
    # Imbue corruptions to copy of ciphertext or submitted ballot according
    # to replacements dictionary, then serialize result
    ballot_corrupt = deepcopy(ballot)
    selection_corrupt = ballot_corrupt.contests[contest_idx].ballot_selections[
        selection_idx
    ]
    for key, value in replacements.items():
        if key == "proof":
            selection_corrupt.proof = value
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
                json_corrupt["contests"][contest_idx]["proof"][key[6:]] = value
    with open(filename, "w", encoding="utf-8") as outfile:
        json.dump(json_corrupt, outfile)


def corrupt_selection_and_json_ballot(
    filename: str, contest_idx: int, selection_idx: int, replacements: dict
) -> None:
    # Edit JSON of ciphertext or submitted ballot according
    # to replacements dictionary to imbue corruptions
    # This is necessary, e.g., when we cannot construct a corrupted
    # Chaum-Pedersen proof object with a challenge that isn't of type
    # ElementModQ, so edits are made via JSON rather than serialization
    with open(filename, "r", encoding="utf-8") as infile:
        json_corrupt = json.load(infile)
        selection = json_corrupt["contests"][contest_idx]["ballot_selections"][
            selection_idx
        ]
        for key, value in replacements.items():
            if key[:5] == "proof" or key == "challenge":
                selection["proof"][key] = value
    with open(filename, "w", encoding="utf-8") as outfile:
        json.dump(json_corrupt, outfile)


def corrupt_selection_accumulation(
    ciphertext_tally: PublishedCiphertextTally,
    contest_id: str,
    selection_id: str,
    pad_factor: ElementModP,
    data_factor: ElementModP,
) -> None:
    acc_ciphertext = (
        ciphertext_tally.contests[contest_id].selections[selection_id].ciphertext
    )
    acc_ciphertext.pad = mult_p(acc_ciphertext.pad, pad_factor)
    acc_ciphertext.data = mult_p(acc_ciphertext.data, data_factor)


def edit_and_prove_shares(
    context: CiphertextElectionContext,
    selection_tally: PlaintextTallySelection,
    private_records: Dict[GuardianId, PrivateGuardianRecord],
    guardians: Dict[GuardianId, Guardian],
    public_key_power: ElementModQ,
    nonce: ElementModQ,
) -> None:
    for share in selection_tally.shares:
        guardian = guardians[share.guardian_id]
        assert isinstance(guardian.share_key().key, ElementModP)
        share.share = mult_p(
            share.share, pow_p(guardian.share_key().key, public_key_power)
        )
        share.proof = make_chaum_pedersen(
            selection_tally.message,
            private_records[share.guardian_id].election_keys.key_pair.secret_key,
            share.share,
            nonce,
            context.crypto_extended_base_hash,
        )


def add_plaintext_vote(
    selection_tally: PlaintextTallySelection,
    vote: int,
) -> None:
    selection_tally.tally = selection_tally.tally + vote
    selection_tally.value = mult_p(selection_tally.value, g_pow_p(vote))


def spoil_ballot(
    _data: str,
    manifest: Manifest,
    context: CiphertextElectionContext,
    ballot: SubmittedBallot,
    shares: Dict[GuardianId, DecryptionShare],
    spoiled_suffix: str = None,
) -> Optional[PlaintextTally]:
    spoiled_ballot = decrypt_ballot(
        ballot,
        shares,
        context.crypto_extended_base_hash,
        manifest,
    )
    if not spoiled_suffix:
        spoiled_suffix = ballot.object_id
    to_file(
        spoiled_ballot,
        SPOILED_BALLOT_PREFIX + spoiled_suffix,
        path.join(_data, ELECTION_RECORD_DIR, SPOILED_BALLOTS_DIR),
    )
    return spoiled_ballot
