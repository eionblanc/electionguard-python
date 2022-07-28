from pymongo.database import Database
from electionguard import DecryptionMediator
from electionguard.ballot import BallotBoxState
from electionguard_gui.models.decryption_dto import DecryptionDto
from electionguard_gui.services.decryption_stages.decryption_stage_base import (
    DecryptionStageBase,
    get_tally,
)


class DecryptionS2AnnounceService(DecryptionStageBase):
    """Responsible for the 2nd stage in decryptions where the admin announces guardian decryptions"""

    def should_run(self, db: Database, decryption: DecryptionDto) -> bool:
        isAdmin = self._auth_service.is_admin()
        allGuardiansJoined = len(decryption.guardians_joined) >= decryption.guardians
        isCompleted = decryption.completed_at_utc is not None
        return isAdmin and allGuardiansJoined and not isCompleted

    def run(self, db: Database, decryption: DecryptionDto) -> None:
        self._log.info(f"S2: Announcing decryption {decryption.decryption_id}")
        election = self._election_service.get(db, decryption.election_id)
        context = election.get_context()

        decryption_mediator = DecryptionMediator(
            "decryption-mediator",
            context,
        )
        decryption_shares = decryption.get_decryption_shares()
        for decryption_share_dict in decryption_shares:
            self._log.debug(f"announcing {decryption_share_dict.guardian_id}")
            decryption_mediator.announce(
                decryption_share_dict.guardian_key,
                decryption_share_dict.tally_share,
                decryption_share_dict.ballot_shares,
            )

        manifest = election.get_manifest()
        ballots = self._ballot_upload_service.get_ballots(db, election.id)
        spoiled_ballots = [
            ballot for ballot in ballots if ballot.state == BallotBoxState.SPOILED
        ]
        ciphertext_tally = get_tally(manifest, context, ballots)
        self._log.debug("getting plaintext tally")
        plaintext_tally = decryption_mediator.get_plaintext_tally(
            ciphertext_tally, manifest
        )
        if plaintext_tally is None:
            raise Exception("No plaintext tally found")
        self._log.debug("getting plaintext spoiled ballots")
        plaintext_spoiled_ballots = decryption_mediator.get_plaintext_ballots(
            spoiled_ballots, manifest
        )
        if plaintext_spoiled_ballots is None:
            raise Exception("No plaintext spoiled ballots found")

        self._log.debug("setting decryption completed")
        self._decryption_service.set_decryption_completed(
            db, decryption.decryption_id, plaintext_tally, plaintext_spoiled_ballots
        )

        self._decryption_service.notify_changed(db, decryption.decryption_id)
