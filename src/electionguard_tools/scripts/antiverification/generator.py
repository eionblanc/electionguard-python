#!/usr/bin/env python
from os import path, environ

from electionguard.constants import ElectionConstants
from electionguard.election import CiphertextElectionContext
from electionguard.manifest import Manifest
from electionguard.serialize import from_file
from electionguard_tools.helpers.export import (
    CONTEXT_FILE_NAME,
    ELECTION_RECORD_DIR,
    CONSTANTS_FILE_NAME,
)
from electionguard_tools.scripts.antiverification.verification_4 import antiverify_4
from electionguard_tools.scripts.antiverification.verification_5 import antiverify_5
from electionguard_tools.scripts.antiverification.verification_6 import antiverify_6


if __name__ == "__main__":
    # Locate existing election record and election private data folders
    _data = path.realpath(
        path.join(__file__, "../../../../../data/1.0.0/jefferson-primary")
    )
    manifest = from_file(
        Manifest, path.join(_data, ELECTION_RECORD_DIR, "manifest.json")
    )
    # Import constants and context
    constants = from_file(
        ElectionConstants,
        path.join(_data, ELECTION_RECORD_DIR, CONSTANTS_FILE_NAME + ".json"),
    )
    # Assume the constants are the LARGE_TEST_CONSTANTS
    environ.setdefault("PRIME_OPTION", "TestOnly")
    context = from_file(
        CiphertextElectionContext,
        path.join(_data, ELECTION_RECORD_DIR, CONTEXT_FILE_NAME + ".json"),
    )

    # Select ballot and contest to tweak
    ballot_id = "03a29d15-667c-4ac8-afd7-549f19b8e4eb"
    contest_id = "justice-supreme-court"
    selection_id_0 = "benjamin-franklin-selection"
    selection_id_1 = "john-adams-selection"

    # Call helper functions for example generation
    antiverify_4(_data, context, ballot_id, contest_id, selection_id_0, selection_id_1)
    antiverify_5(_data, manifest, context, ballot_id, contest_id)

    ballot_id_cast = "1048ce32-f1b1-4b05-b7fb-8c615ac842ee"
    antiverify_6(_data, manifest, context, ballot_id_cast)
