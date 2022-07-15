#!/usr/bin/env python
from os import path
import shutil
from copy import deepcopy
import json
from typing import Union, Tuple

from electionguard.ballot import (
    CiphertextBallot,
    SubmittedBallot,
)
from electionguard.serialize import from_file, to_file
from electionguard_tools.helpers.export import (
    PRIVATE_DATA_DIR,
    ELECTION_RECORD_DIR,
    SUBMITTED_BALLOTS_DIR,
    CIPHERTEXT_BALLOT_PREFIX,
    SUBMITTED_BALLOT_PREFIX,
)

CIPHERTEXT_BALLOTS_DIR = "ciphertext_ballots"


def duplicate_election_data(_data: str, check: str, subcheck: str) -> str:
    # Duplicate files into _data + '_failure/{check}/{subcheck}'
    _cex = path.join(_data + "_failure", check, subcheck)
    if path.exists(_cex):
        shutil.rmtree(_cex)
    shutil.copytree(_data, _cex)
    return _cex


def import_ballot_from_files(
    _data: str, ballot_id: str, private_data: bool = True
) -> Tuple[SubmittedBallot, Union[CiphertextBallot, None]]:
    # Import ciphertext and corresponding submitted ballot to manipulate
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
    if private_data:
        ciphertext = from_file(
            CiphertextBallot,
            path.join(
                _data,
                PRIVATE_DATA_DIR,
                CIPHERTEXT_BALLOTS_DIR,
                CIPHERTEXT_BALLOT_PREFIX + ballot_id + ".json",
            ),
        )
        return ballot, ciphertext
    return ballot, None


def get_contest_index_by_id(ballot: CiphertextBallot, contest_id: str) -> int:
    # Step through contests until match is found; this accommodates contests
    # listed out of sequence order as well as contests from compact ballots
    for j, contest in enumerate(ballot.contests):
        if contest.object_id == contest_id:
            return j
    return -1


def get_selection_index_by_id(
    ballot: CiphertextBallot, contest_id: str, selection_id: str
) -> Tuple[int, int]:
    contest_idx = get_contest_index_by_id(ballot, contest_id)
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
