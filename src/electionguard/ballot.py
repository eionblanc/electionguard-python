from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from functools import cached_property, reduce
from typing import (
    Any,
    Dict,
    List,
    Iterable,
    Optional,
    Protocol,
    runtime_checkable,
)


from .ballot_code import get_ballot_code
from .chaum_pedersen import (
    ConstantChaumPedersenProof,
    RangeChaumPedersenProof,
    make_constant_chaum_pedersen,
    make_range_chaum_pedersen,
)
from .election_object_base import (
    ElectionObjectBase,
    OrderedObjectBase,
    sequence_order_sort,
    list_eq,
)
from .elgamal import (
    ElGamalCiphertext,
    ElGamalPublicKey,
    HashedElGamalCiphertext,
    elgamal_add,
)
from .group import add_q, ElementModQ, ZERO_MOD_Q
from .hash import CryptoHashCheckable, hash_elems
from .logs import log_warning
from .manifest import ContestDescription
from .type import SelectionId
from .utils import (
    ContestException,
    NullVoteException,
    OverVoteException,
    UnderVoteException,
    flatmap_optional,
    to_ticks,
)


@dataclass(unsafe_hash=True)
class PlaintextBallotSelection(ElectionObjectBase):
    """
    A BallotSelection represents an individual selection on a ballot.

    This class accepts a `vote` integer field which has no constraints.
    The range Chaum-Pedersen proofs now support encodings of any nonnegative integer,
    not just the binary 0 or 1 as previously supported.

    This class can also be designated as `is_placeholder_selection` which has no
    context to the data specification but is useful for running validity checks internally.

    Write_in field exists to support the cleartext representation of a write-in candidate value.
    """

    vote: int

    is_placeholder_selection: bool = field(default=False)
    """Determines if this is a placeholder selection"""

    write_in: Optional[str] = field(default=None)
    """
    Write_in field exists to support the cleartext representation of a write-in candidate value.
    """

    def is_valid(self, expected_object_id: str) -> bool:
        """
        Given a PlaintextBallotSelection validates that the object matches an expected object
        and that the plaintext string can resolve to a valid representation
        """

        if self.object_id != expected_object_id:
            log_warning(
                f"invalid object_id: expected({expected_object_id}) actual({self.object_id})"
            )
            return False

        vote = self.vote
        if vote < 0:
            log_warning(f"Currently only supporting nonnegative choices: {str(self)}")
            return False

        return True

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, PlaintextBallotSelection)
            and self.object_id == other.object_id
            and self.vote == other.vote
            and self.is_placeholder_selection == other.is_placeholder_selection
            and self.write_in == other.write_in
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


@runtime_checkable
class CiphertextSelection(Protocol):
    """
    Encrypted selection
    """

    object_id: str

    sequence_order: int
    """Order the selection"""

    description_hash: ElementModQ
    """The SelectionDescription hash"""

    ciphertext: ElGamalCiphertext
    """The encrypted representation of the selection"""


@dataclass(eq=True, unsafe_hash=True)
class CiphertextBallotSelection(
    OrderedObjectBase, CiphertextSelection, CryptoHashCheckable
):
    """
    A CiphertextBallotSelection represents an individual encrypted selection on a ballot.

    This class accepts a `description_hash` and a `ciphertext` as required parameters
    in its constructor.

    When a selection is encrypted, the `description_hash` and `ciphertext` required fields must
    be populated at construction; however, the `nonce` is also usually provided by convention.

    After construction, the `crypto_hash` field is populated automatically in the `__post_init__` cycle.

    A consumer of this object has the option to discard the `nonce` and/or discard the `proof`,
    or keep both values.

    By discarding the `nonce`, the encrypted representation and `proof`
    can only be regenerated if the nonce was derived from the ballot's master nonce.  If the nonce
    used for this selection is truly random and is discarded, then the proofs cannot be regenerated.

    By keeping the `nonce` or deriving the selection nonce from the ballot nonce, an external system can
    regenerate the proofs on demand.  This is useful for storage- or memory-constrained systems.

    By keeping the `proof`, the nonce is not required to verify the encrypted selection.
    """

    description_hash: ElementModQ
    """The SelectionDescription hash"""

    ciphertext: ElGamalCiphertext
    """The encrypted representation of the vote field"""

    crypto_hash: ElementModQ
    """The hash of the encrypted values"""

    is_placeholder_selection: bool = field(default=False)
    """Determines if this is a placeholder selection"""

    nonce: Optional[ElementModQ] = field(default=None)
    """The nonce used to generate the encryption. Sensitive & should be treated as a secret"""

    proof: Optional[RangeChaumPedersenProof] = field(default=None)
    """The proof demonstrating that the selection used the `nonce` to encrypt a nonnegative integer"""

    def is_valid_encryption(
        self,
        encryption_seed: ElementModQ,
        elgamal_public_key: ElGamalPublicKey,
        crypto_extended_base_hash: ElementModQ,
    ) -> bool:
        """
        Given an encrypted BallotSelection, validates the encryption state against a specific
        seed and public key. Calling this function expects that the object is in a well-formed
        encrypted state with the ElGamal encrypted `message` field populated along with the
        RangeChaumPedersenProof `proof` populated.
        The ElementModQ `description_hash` and the ElementModQ `crypto_hash` are also checked.

        :param encryption_seed: the hash of the SelectionDescription, or
                                whatever `ElementModQ` was used to populate the `description_hash` field.
        :param elgamal_public_key: The election public key
        """

        if encryption_seed != self.description_hash:
            log_warning(
                (
                    f"mismatching selection hash: {self.object_id} expected({str(encryption_seed)}), "
                    f"actual({str(self.description_hash)})"
                )
            )
            return False

        recalculated_crypto_hash = self.crypto_hash_with(encryption_seed)
        if self.crypto_hash != recalculated_crypto_hash:
            log_warning(
                (
                    f"mismatching crypto hash: {self.object_id} expected({str(recalculated_crypto_hash)}), "
                    f"actual({str(self.crypto_hash)})"
                )
            )
            return False

        if self.proof is None:
            log_warning(f"no proof exists for: {self.object_id}")
            return False

        return self.proof.is_valid(
            self.ciphertext, elgamal_public_key, crypto_extended_base_hash
        )

    def crypto_hash_with(self, encryption_seed: ElementModQ) -> ElementModQ:
        """
        Given an encrypted BallotSelection, generates a hash, suitable for rolling up
        into a hash for an entire ballot / ballot code. Of note, this particular hash examines
        the `encryption_seed` and `message`, but not the proof.
        This is deliberate, allowing for the possibility of ElectionGuard variants running on
        much more limited hardware, wherein the range Chaum-Pedersen proofs might be computed
        later on.

        In most cases the encryption_seed should match the `description_hash`
        """
        return _ciphertext_ballot_selection_crypto_hash_with(
            self.object_id, encryption_seed, self.ciphertext
        )


def _ciphertext_ballot_selection_crypto_hash_with(
    object_id: str, encryption_seed: ElementModQ, ciphertext: ElGamalCiphertext
) -> ElementModQ:
    return hash_elems(object_id, encryption_seed, ciphertext.crypto_hash())


def make_ciphertext_ballot_selection(
    object_id: str,
    sequence_order: int,
    description_hash: ElementModQ,
    ciphertext: ElGamalCiphertext,
    elgamal_public_key: ElGamalPublicKey,
    crypto_extended_base_hash: ElementModQ,
    proof_seed: ElementModQ,
    selection_representation: int,
    is_placeholder_selection: bool = False,
    nonce: Optional[ElementModQ] = None,
    crypto_hash: Optional[ElementModQ] = None,
    proof: Optional[RangeChaumPedersenProof] = None,
) -> CiphertextBallotSelection:
    """
    Constructs a `CipherTextBallotSelection` object. Most of the parameters here match up to fields
    in the class, but this helper function will optionally compute a Chaum-Pedersen proof if the
    given nonce isn't `None`. Likewise, if a crypto_hash is not provided, it will be derived from
    the other fields.
    """
    if crypto_hash is None:
        crypto_hash = _ciphertext_ballot_selection_crypto_hash_with(
            object_id, description_hash, ciphertext
        )

    if proof is None:
        proof = flatmap_optional(
            nonce,
            lambda n: make_range_chaum_pedersen(
                ciphertext,
                n,
                elgamal_public_key,
                crypto_extended_base_hash,
                proof_seed,
                selection_representation,
            ),
        )

    return CiphertextBallotSelection(
        object_id,
        sequence_order,
        description_hash,
        ciphertext,
        crypto_hash,
        is_placeholder_selection,
        nonce,
        proof,
    )


@dataclass(unsafe_hash=True)
class PlaintextBallotContest(ElectionObjectBase):
    """
    A PlaintextBallotContest represents the selections made by a voter for a specific ContestDescription

    This class can be either a partial or a complete representation of a contest dataset.  Specifically,
    a partial representation must include at a minimum the "affirmative" selections of a contest.
    A complete representation of a ballot must include both affirmative and negative selections of
    the contest AND the placeholder selections necessary to satisfy the ConstantChaumPedersen proof
    in the CiphertextBallotContest.

    Typically partial contests are passed into Electionguard for memory constrained systems,
    while complete contests are passed into ElectionGuard when running encryption on an existing dataset.
    """

    ballot_selections: List[PlaintextBallotSelection] = field(
        default_factory=lambda: []
    )
    """Collection of ballot selections"""

    @cached_property
    def selected_ids(self) -> List[SelectionId]:
        return [
            selection.object_id
            for selection in self.ballot_selections
            if selection.vote > 0
        ]

    @cached_property
    def total_selected(self) -> int:
        """Returns the total number of selected selections."""
        return reduce(
            lambda prev, next: prev + (1 if next.vote > 0 else 0),
            self.ballot_selections,
            0,
        )

    @cached_property
    def total_votes(self) -> int:
        """Returns the total number of votes on selections."""
        return reduce(lambda prev, next: prev + next.vote, self.ballot_selections, 0)

    @cached_property
    def write_ins(self) -> Optional[Dict[SelectionId, str]]:
        write_ins = {
            selection.object_id: selection.write_in
            for selection in self.ballot_selections
            if selection.write_in is not None  # Required due to empty strings
        }
        return write_ins if len(write_ins) else None

    def valid(self, description: ContestDescription) -> None:
        """Determine if a contest is valid."""

        # Contest id matches description and ballot selections don't exceed description
        if (
            self.object_id != description.object_id
            or len(self.ballot_selections) > len(description.ballot_selections)
            or not description.is_valid()
        ):
            raise ContestException(
                self.object_id,
                override_message=f"invalid format of contest or description for contest {self.object_id}",
            )

        # Selections ids match description
        selection_ids = {
            selection.object_id for selection in description.ballot_selections
        }
        for selection in self.ballot_selections:
            if selection.object_id not in selection_ids:
                raise ContestException(
                    self.object_id,
                    override_message=f"invalid selection id ${selection.object_id} on contest {self.object_id}",
                )

        # Specialty cases
        if self.total_selected < 1:
            raise NullVoteException(self.object_id)

        if self.total_selected < description.number_elected:
            raise UnderVoteException(self.object_id)

        if self.total_selected > description.number_elected:
            raise OverVoteException(self.object_id, self.selected_ids)

        if description.votes_allowed is not None:
            if self.total_votes > description.votes_allowed:
                raise OverVoteException(self.object_id, self.selected_ids)

            # Support for other cases such as cumulative voting not currently supported.
            # (individual selections being an encryption of > 1)
            if self.total_selected < description.votes_allowed:
                raise ContestException(
                    self.object_id,
                    override_message=f"`on contest {self.object_id}: only n-of-m style elections are supported",
                )

    def is_valid(
        self,
        expected_object_id: str,
        expected_number_selections: int,
        expected_number_elected: int,
        votes_allowed: Optional[int] = None,
    ) -> bool:
        """
        Given a PlaintextBallotContest returns true if the state is representative of the expected values.

        Note: because this class supports partial representations, undervotes are considered a valid state.
        """

        if self.object_id != expected_object_id:
            log_warning(
                (
                    f"invalid object_id: expected({expected_object_id}) "
                    f"actual({self.object_id})"
                )
            )
            return False

        if len(self.ballot_selections) > expected_number_selections:
            log_warning(
                (
                    f"invalid number_selections: expected({expected_number_selections}) "
                    f"actual({len(self.ballot_selections)})"
                )
            )
            return False

        number_elected = 0
        votes = 0

        # Verify the selections are well-formed
        for selection in self.ballot_selections:
            votes += selection.vote
            if selection.vote >= 1:
                number_elected += 1

        if number_elected > expected_number_elected:
            log_warning(
                f"invalid number_elected: expected({expected_number_elected}) actual({number_elected})"
            )
            return False

        if votes_allowed is not None and votes > votes_allowed:
            log_warning(f"invalid votes: expected({votes_allowed}) actual({votes})")
            return False

        return True

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, PlaintextBallotContest) and list_eq(
            self.ballot_selections, other.ballot_selections
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


@dataclass
class CiphertextContest(OrderedObjectBase):
    """
    Base encrypted contest for both tally and ballot
    """

    description_hash: ElementModQ
    """The description hash"""

    selections: Iterable[CiphertextSelection]
    """Collection of selections"""


@dataclass(unsafe_hash=True)
class CiphertextBallotContest(OrderedObjectBase, CryptoHashCheckable):
    """
    A CiphertextBallotContest represents the selections made by a voter for a specific ContestDescription

    CiphertextBallotContest can only be a complete representation of a contest dataset.  While
    PlaintextBallotContest supports a partial representation, a CiphertextBallotContest includes all data
    necessary for a verifier to verify the contest.  Specifically, it includes both explicit affirmative
    and negative selections of the contest, as well as the placeholder selections that satisfy
    the ConstantChaumPedersen proof.

    Similar to `CiphertextBallotSelection` the consuming application can choose to discard or keep both
    the `nonce` and the `proof` in some circumstances.  For deterministic nonce's derived from the
    master nonce, both values can be regenerated.  If the `nonce` for this contest is completely random,
    then it is required in order to regenerate the proof.
    """

    description_hash: ElementModQ
    """Hash from contestDescription"""

    ballot_selections: List[CiphertextBallotSelection]
    """Collection of ballot selections"""

    ciphertext_accumulation: ElGamalCiphertext
    """The encrypted representation of all of the vote fields (the contest total)"""

    crypto_hash: ElementModQ
    """Hash of the encrypted values"""

    nonce: Optional[ElementModQ] = None
    """The nonce used to generate the encryption. Sensitive & should be treated as a secret"""

    proof: Optional[ConstantChaumPedersenProof] = None
    """
    The proof demonstrates the sum of the selections does not exceed the maximum
    available selections for the contest, and that the proof was generated with the nonce
    """

    extended_data: Optional[HashedElGamalCiphertext] = field(default=None)
    """encrypted representation of the extended_data field"""

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, CiphertextBallotContest)
            and self.object_id == other.object_id
            and list_eq(self.ballot_selections, other.ballot_selections)
            and self.description_hash == other.description_hash
            and self.crypto_hash == other.crypto_hash
            and self.nonce == other.nonce
            and self.proof == other.proof
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def aggregate_nonce(self) -> Optional[ElementModQ]:
        """
        :return: an aggregate nonce for the contest composed of the nonces of the selections
        """
        return _ciphertext_ballot_contest_aggregate_nonce(
            self.object_id, self.ballot_selections
        )

    def crypto_hash_with(self, encryption_seed: ElementModQ) -> ElementModQ:
        """
        Given an encrypted BallotContest, generates a hash, suitable for rolling up
        into a hash for an entire ballot / ballot code. Of note, this particular hash examines
        the `encryption_seed` and `ballot_selections`, but not the proof.
        This is deliberate, allowing for the possibility of ElectionGuard variants running on
        much more limited hardware, wherein the Chaum-Pedersen proofs might be computed
        later on.

        In most cases, the encryption_seed is the description_hash
        """
        return _ciphertext_ballot_context_crypto_hash(
            self.object_id, self.ballot_selections, encryption_seed
        )

    def elgamal_accumulate(self) -> ElGamalCiphertext:
        """
        Add the individual ballot_selections `message` fields together, suitable for use
        in a Chaum-Pedersen proof.
        """
        return _ciphertext_ballot_elgamal_accumulate(self.ballot_selections)

    def is_valid_encryption(
        self,
        encryption_seed: ElementModQ,
        elgamal_public_key: ElGamalPublicKey,
        crypto_extended_base_hash: ElementModQ,
    ) -> bool:
        """
        Given an encrypted BallotContest, validates the encryption state against a specific seed and public key
        by verifying the accumulated sum of selections match the proof.
        Calling this function expects that the object is in a well-formed encrypted state
        with the `ballot_selections` populated with valid encrypted ballot selections,
        the ElementModQ `description_hash`, the ElementModQ `crypto_hash`,
        and the ConstantChaumPedersenProof all populated.
        Specifically, the seed in this context is the hash of the ContestDescription,
        or whatever `ElementModQ` was used to populate the `description_hash` field.
        """
        if encryption_seed != self.description_hash:
            log_warning(
                (
                    f"mismatching contest hash: {self.object_id} expected({str(encryption_seed)}), "
                    f"actual({str(self.description_hash)})"
                )
            )
            return False

        recalculated_crypto_hash = self.crypto_hash_with(encryption_seed)
        if self.crypto_hash != recalculated_crypto_hash:
            log_warning(
                (
                    f"mismatching crypto hash: {self.object_id} expected({str(recalculated_crypto_hash)}), "
                    f"actual({str(self.crypto_hash)})"
                )
            )
            return False

        # NOTE: this check does not verify the proofs of the individual selections by design.

        if self.proof is None:
            log_warning(f"no proof exists for: {self.object_id}")
            return False

        computed_ciphertext_accumulation = self.elgamal_accumulate()

        # Verify that the contest ciphertext matches the elgamal accumulation of all selections
        if self.ciphertext_accumulation != computed_ciphertext_accumulation:
            log_warning(
                f"ciphertext does not equal elgamal accumulation for : {self.object_id}"
            )
            return False

        # Verify the sum of the selections matches the proof
        return self.proof.is_valid(
            computed_ciphertext_accumulation,
            elgamal_public_key,
            crypto_extended_base_hash,
        )


def _ciphertext_ballot_elgamal_accumulate(
    ballot_selections: List[CiphertextBallotSelection],
) -> ElGamalCiphertext:
    return elgamal_add(*[selection.ciphertext for selection in ballot_selections])


def _ciphertext_ballot_context_crypto_hash(
    object_id: str,
    ballot_selections: List[CiphertextBallotSelection],
    encryption_seed: ElementModQ,
) -> ElementModQ:
    if len(ballot_selections) == 0:
        log_warning(
            f"mismatching ballot_selections state: {object_id} expected(some), actual(none)"
        )
        return ZERO_MOD_Q

    selection_hashes = [
        selection.crypto_hash for selection in sequence_order_sort(ballot_selections)
    ]

    return hash_elems(object_id, encryption_seed, *selection_hashes)


def _ciphertext_ballot_contest_aggregate_nonce(
    object_id: str, ballot_selections: List[CiphertextBallotSelection]
) -> Optional[ElementModQ]:
    selection_nonces: List[ElementModQ] = []
    for selection in ballot_selections:
        if selection.nonce is None:
            log_warning(
                f"missing nonce values for contest {object_id} cannot calculate aggregate nonce"
            )
            return None
        selection_nonces.append(selection.nonce)

    return add_q(*selection_nonces)


def make_ciphertext_ballot_contest(
    object_id: str,
    sequence_order: int,
    description_hash: ElementModQ,
    ballot_selections: List[CiphertextBallotSelection],
    elgamal_public_key: ElGamalPublicKey,
    crypto_extended_base_hash: ElementModQ,
    proof_seed: ElementModQ,
    number_elected: int,
    crypto_hash: Optional[ElementModQ] = None,
    proof: Optional[ConstantChaumPedersenProof] = None,
    nonce: Optional[ElementModQ] = None,
    extended_data: Optional[HashedElGamalCiphertext] = None,
) -> CiphertextBallotContest:
    """
    Constructs a `CipherTextBallotContest` object. Most of the parameters here match up to fields
    in the class, but this helper function will optionally compute a Chaum-Pedersen proof if the
    ballot selections include their encryption nonces. Likewise, if a crypto_hash is not provided,
    it will be derived from the other fields.
    """
    if crypto_hash is None:
        crypto_hash = _ciphertext_ballot_context_crypto_hash(
            object_id, ballot_selections, description_hash
        )

    aggregate = _ciphertext_ballot_contest_aggregate_nonce(object_id, ballot_selections)
    elgamal_accumulation = _ciphertext_ballot_elgamal_accumulate(ballot_selections)
    if proof is None:
        proof = flatmap_optional(
            aggregate,
            lambda ag: make_constant_chaum_pedersen(
                elgamal_accumulation,
                number_elected,
                ag,
                elgamal_public_key,
                proof_seed,
                crypto_extended_base_hash,
            ),
        )
    return CiphertextBallotContest(
        object_id,
        sequence_order,
        description_hash,
        ballot_selections,
        elgamal_accumulation,
        crypto_hash,
        nonce,
        proof,
        extended_data,
    )


@dataclass(unsafe_hash=True)
class PlaintextBallot(ElectionObjectBase):
    """
    A PlaintextBallot represents a voters selections for a given ballot and ballot style
    :field object_id: A unique Ballot ID that is relevant to the external system
    """

    style_id: str
    """The `object_id` of the `BallotStyle` in the `Election` Manifest"""

    contests: List[PlaintextBallotContest]
    """The list of contests for this ballot"""

    def is_valid(self, expected_ballot_style_id: str) -> bool:
        """
        Check if expected ballot style is valid
        :param expected_ballot_style_id: Expected ballot style id
        :return: True if valid
        """
        if self.style_id != expected_ballot_style_id:
            log_warning(
                (
                    f"invalid ballot_style: for: {self.object_id} expected({expected_ballot_style_id}) "
                    f"actual({self.style_id})"
                )
            )
            return False

        return True

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, PlaintextBallot)
            and self.style_id == other.style_id
            and list_eq(self.contests, other.contests)
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


# pylint: disable=too-many-instance-attributes
@dataclass(unsafe_hash=True)
class CiphertextBallot(ElectionObjectBase, CryptoHashCheckable):
    """
    A CiphertextBallot represents a voters encrypted selections for a given ballot and ballot style.

    When a ballot is in it's complete, encrypted state, the `nonce` is the master nonce
    from which all other nonces can be derived to encrypt the ballot.  Allong with the `nonce`
    fields on `Ballotcontest` and `BallotSelection`, this value is sensitive.

    Don't make this directly. Use `make_ciphertext_ballot` instead.
    :field object_id: A unique Ballot ID that is relevant to the external system
    """

    style_id: str
    """The `object_id` of the `BallotStyle` in the `Election` Manifest"""

    manifest_hash: ElementModQ
    """Hash of the election manifest"""

    code_seed: ElementModQ
    """Seed for ballot code"""

    contests: List[CiphertextBallotContest]
    """List of contests for this ballot"""

    code: ElementModQ
    """Unique ballot code for this ballot"""

    timestamp: int
    """Timestamp at which the ballot encryption is generated in tick"""

    crypto_hash: ElementModQ
    """The hash of the encrypted ballot representation"""

    nonce: Optional[ElementModQ]
    """The nonce used to encrypt this ballot. Sensitive & should be treated as a secret"""

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, CiphertextBallot)
            and self.object_id == other.object_id
            and self.style_id == other.style_id
            and self.manifest_hash == other.manifest_hash
            and self.code_seed == other.code_seed
            and list_eq(self.contests, other.contests)
            and self.code == other.code
            and self.timestamp == other.timestamp
            and self.crypto_hash == other.crypto_hash
            and self.nonce == other.nonce
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    @staticmethod
    def nonce_seed(
        manifest_hash: ElementModQ, object_id: str, nonce: ElementModQ
    ) -> ElementModQ:
        """
        :return: a representation of the election and the external Id in the nonce's used
        to derive other nonce values on the ballot
        """
        return hash_elems(manifest_hash, object_id, nonce)

    def hashed_ballot_nonce(self) -> Optional[ElementModQ]:
        """
        :return: a hash value derived from the description hash, the object id, and the nonce value
                suitable for deriving other nonce values on the ballot
        """

        if self.nonce is None:
            log_warning(
                f"missing nonce for ballot {self.object_id} could not derive from null nonce"
            )
            return None

        return self.nonce_seed(self.manifest_hash, self.object_id, self.nonce)

    def crypto_hash_with(self, encryption_seed: ElementModQ) -> ElementModQ:
        """
        Given an encrypted Ballot, generates a hash, suitable for rolling up
        into a hash for an entire ballot / ballot code. Of note, this particular hash examines
        the `manifest_hash` and `ballot_selections`, but not the proof.
        This is deliberate, allowing for the possibility of ElectionGuard variants running on
        much more limited hardware, wherein the Chaum-Pedersen proofs might be computed
        later on.
        """
        if len(self.contests) == 0:
            log_warning(
                f"mismatching contests state: {self.object_id} expected(some), actual(none)"
            )
            return ZERO_MOD_Q

        contest_hashes = [contest.crypto_hash for contest in self.contests]
        return hash_elems(self.object_id, encryption_seed, *contest_hashes)

    def is_valid_encryption(
        self,
        encryption_seed: ElementModQ,
        elgamal_public_key: ElGamalPublicKey,
        crypto_extended_base_hash: ElementModQ,
    ) -> bool:
        """
        Given an encrypted Ballot, validates the encryption state against a specific seed and public key
        by verifying the states of this ballot's children (BallotContest's and BallotSelection's).
        Calling this function expects that the object is in a well-formed encrypted state
        with the `contests` populated with valid encrypted ballot selections,
        and the ElementModQ `manifest_hash` also populated.
        Specifically, the seed in this context is the hash of the Election Manifest,
        or whatever `ElementModQ` was used to populate the `manifest_hash` field.
        """

        if encryption_seed != self.manifest_hash:
            log_warning(
                (
                    f"mismatching ballot hash: {self.object_id} expected({str(encryption_seed)}), "
                    f"actual({str(self.manifest_hash)})"
                )
            )
            return False

        recalculated_crypto_hash = self.crypto_hash_with(encryption_seed)
        if self.crypto_hash != recalculated_crypto_hash:
            log_warning(
                (
                    f"mismatching crypto hash: {self.object_id} expected({str(recalculated_crypto_hash)}), "
                    f"actual({str(self.crypto_hash)})"
                )
            )
            return False

        # Check the proofs on the ballot
        valid_proofs: List[bool] = []

        for contest in self.contests:
            for selection in contest.ballot_selections:
                valid_proofs.append(
                    selection.is_valid_encryption(
                        selection.description_hash,
                        elgamal_public_key,
                        crypto_extended_base_hash,
                    )
                )
            valid_proofs.append(
                contest.is_valid_encryption(
                    contest.description_hash,
                    elgamal_public_key,
                    crypto_extended_base_hash,
                )
            )
        return all(valid_proofs)


class BallotBoxState(Enum):
    """
    Enumeration used when marking a ballot as cast or spoiled
    """

    CAST = 1
    """
    A ballot that has been explicitly cast
    """
    SPOILED = 2
    """
    A ballot that has been explicitly spoiled
    """
    UNKNOWN = 999
    """
    A ballot whose state is unknown to ElectionGuard and will not be included in any election results
    """


@dataclass(unsafe_hash=True)
class SubmittedBallot(CiphertextBallot):
    """
    A `SubmittedBallot` represents a ballot that is submitted for inclusion in election results.
    A submitted ballot is or is about to be either cast or spoiled.
    The state supports the `BallotBoxState.UNKNOWN` enumeration to indicate that this object is mutable
    and has not yet been explicitly assigned a specific state.

    Note, additionally, this ballot includes all proofs but no nonces.

    Do not make this class directly. Use `make_ciphertext_submitted_ballot` instead.
    """

    state: BallotBoxState

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, SubmittedBallot)
            and super().__eq__(other)
            and self.state == other.state
        )

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


def make_ciphertext_ballot(
    object_id: str,
    style_id: str,
    manifest_hash: ElementModQ,
    code_seed: Optional[ElementModQ],
    contests: List[CiphertextBallotContest],
    nonce: Optional[ElementModQ] = None,
    timestamp: Optional[int] = None,
    ballot_code: Optional[ElementModQ] = None,
) -> CiphertextBallot:
    """
    Makes a `CiphertextBallot`, initially in the state where it's neither been cast nor spoiled.

    :param object_id: the object_id of this specific ballot
    :param style_id: The `object_id` of the `BallotStyle` in the `Election` Manifest
    :param manifest_hash: Hash of the election manifest
    :param crypto_base_hash: Hash of the cryptographic election context
    :param contests: List of contests for this ballot
    :param timestamp: Timestamp at which the ballot encryption is generated in tick
    :param code_seed: Seed for ballot code
    :param nonce: optional nonce used as part of the encryption process
    """

    if len(contests) == 0:
        log_warning("ciphertext ballot with no contests")

    contest_hash = create_ballot_hash(object_id, manifest_hash, contests)

    timestamp = to_ticks(datetime.now()) if timestamp is None else timestamp
    if code_seed is None:
        code_seed = manifest_hash
    if ballot_code is None:
        ballot_code = get_ballot_code(code_seed, timestamp, contest_hash)

    return CiphertextBallot(
        object_id,
        style_id,
        manifest_hash,
        code_seed,
        contests,
        ballot_code,
        timestamp,
        contest_hash,
        nonce,
    )


def create_ballot_hash(
    ballot_id: str,
    description_hash: ElementModQ,
    contests: List[CiphertextBallotContest],
) -> ElementModQ:
    """Create the hash of the ballot contests"""

    contest_hashes = [contest.crypto_hash for contest in sequence_order_sort(contests)]
    return hash_elems(ballot_id, description_hash, *contest_hashes)


def make_ciphertext_submitted_ballot(
    object_id: str,
    style_id: str,
    manifest_hash: ElementModQ,
    code_seed: Optional[ElementModQ],
    contests: List[CiphertextBallotContest],
    ballot_code: Optional[ElementModQ],
    timestamp: Optional[int] = None,
    state: BallotBoxState = BallotBoxState.UNKNOWN,
) -> SubmittedBallot:
    """
    Makes a `SubmittedBallot`, ensuring that no nonces are part of the contests.

    :param object_id: the object_id of this specific ballot
    :param style_id: The `object_id` of the `BallotStyle` in the `Election` Manifest
    :param manifest_hash: Hash of the election manifest
    :param code_seed: Seed for ballot code
    :param contests: List of contests for this ballot
    :param timestamp: Timestamp at which the ballot encryption is generated in tick
    :param state: ballot box state
    """

    if len(contests) == 0:
        log_warning("ciphertext ballot with no contests")

    contest_hashes = [contest.crypto_hash for contest in sequence_order_sort(contests)]
    contest_hash = hash_elems(object_id, manifest_hash, *contest_hashes)

    timestamp = to_ticks(datetime.utcnow()) if timestamp is None else timestamp
    if code_seed is None:
        code_seed = manifest_hash
    if ballot_code is None:
        ballot_code = get_ballot_code(code_seed, timestamp, contest_hash)

    # copy the contests and selections, removing all nonces
    new_contests: List[CiphertextBallotContest] = []
    for contest in contests:
        new_selections = [
            replace(selection, nonce=None) for selection in contest.ballot_selections
        ]
        new_contest = replace(contest, nonce=None, ballot_selections=new_selections)
        new_contests.append(new_contest)

    return SubmittedBallot(
        object_id,
        style_id,
        manifest_hash,
        code_seed,
        new_contests,
        ballot_code,
        timestamp,
        contest_hash,
        None,
        state,
    )
