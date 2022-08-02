#!/usr/bin/env python
from os import path, environ

from electionguard.constants import ElectionConstants
from electionguard.election import CiphertextElectionContext
from electionguard.manifest import Manifest
from electionguard.serialize import from_file
from electionguard.type import GuardianId
from electionguard_tools.helpers.export import (
    CONTEXT_FILE_NAME,
    ELECTION_RECORD_DIR,
    CONSTANTS_FILE_NAME,
)
from electionguard_tools.scripts.antiverification.verification_1 import antiverify_1
from electionguard_tools.scripts.antiverification.verification_2 import antiverify_2
from electionguard_tools.scripts.antiverification.verification_3 import antiverify_3
from electionguard_tools.scripts.antiverification.verification_4 import antiverify_4
from electionguard_tools.scripts.antiverification.verification_5 import antiverify_5
from electionguard_tools.scripts.antiverification.verification_6 import antiverify_6
from electionguard_tools.scripts.antiverification.verification_7 import antiverify_7
from electionguard_tools.scripts.antiverification.verification_8 import antiverify_8
from electionguard_tools.scripts.antiverification.verification_11 import antiverify_11


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

    # Choose which ballot, contest, selection, guardian, ... to manipulate
    # Then call antiverification generation functions
    guardian_id = GuardianId("2")
    ballot_id_cast = "1048ce32-f1b1-4b05-b7fb-8c615ac842ee"
    ballot_id = "03a29d15-667c-4ac8-afd7-549f19b8e4eb"
    contest_id = "justice-supreme-court"
    selection_id_0 = "benjamin-franklin-selection"
    selection_id_1 = "john-adams-selection"
    run_nonstandard = False

    if run_nonstandard:
        antiverify_1(_data, manifest, context, constants)
    else:
        antiverify_2(_data, guardian_id)
        antiverify_3(_data, manifest, context, ballot_id_cast, guardian_id)
        antiverify_4(
            _data, context, ballot_id, contest_id, selection_id_0, selection_id_1
        )
        antiverify_5(_data, manifest, context, ballot_id, contest_id)
        antiverify_6(
            _data,
            manifest,
            context,
            ballot_id_cast,
            contest_id,
            selection_id_0,
            selection_id_1,
        )
        antiverify_7(_data, context, contest_id, selection_id_0)
        antiverify_8(_data, context, contest_id, selection_id_0, guardian_id)
        antiverify_11(_data, contest_id, selection_id_0)
