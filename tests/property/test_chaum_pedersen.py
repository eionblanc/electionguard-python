from datetime import timedelta
from hypothesis import given, settings, HealthCheck, Phase
from hypothesis.strategies import integers


from tests.base_test_case import BaseTestCase

from electionguard.chaum_pedersen import (
    ConstantChaumPedersenProof,
    make_disjunctive_chaum_pedersen_zero,
    make_disjunctive_chaum_pedersen_one,
    make_chaum_pedersen,
    make_constant_chaum_pedersen,
    make_disjunctive_chaum_pedersen,
    make_range_chaum_pedersen,
)
from electionguard.elgamal import (
    ElGamalKeyPair,
    elgamal_encrypt,
    elgamal_keypair_from_secret,
)
from electionguard.group import ElementModQ, TWO_MOD_Q, ONE_MOD_Q, int_to_p, TWO_MOD_P
from electionguard.utils import get_optional
from electionguard_tools.strategies.elgamal import elgamal_keypairs
from electionguard_tools.strategies.group import elements_mod_q_no_zero, elements_mod_q


class TestRangeChaumPedersen(BaseTestCase):
    """Range Chaum-Pedersen tests"""

    def test_rcp_proofs_simple(self):
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q

        # Encode 0; able to prove within range 0 - L for any L >= 0 (default 1)
        message0 = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        proof00 = make_range_chaum_pedersen(
            message0, nonce, keypair.public_key, ONE_MOD_Q, seed, 0, 0
        )
        self.assertTrue(proof00.is_valid(message0, keypair.public_key, ONE_MOD_Q))
        proof01 = make_range_chaum_pedersen(
            message0, nonce, keypair.public_key, ONE_MOD_Q, seed, 0
        )
        self.assertTrue(proof01.is_valid(message0, keypair.public_key, ONE_MOD_Q))
        proof02 = make_range_chaum_pedersen(
            message0, nonce, keypair.public_key, ONE_MOD_Q, seed, 0, 2
        )
        self.assertTrue(proof02.is_valid(message0, keypair.public_key, ONE_MOD_Q))

        # Encode 1; able to prove within range 0 - L for any L >= 1 (default 1)
        message1 = get_optional(elgamal_encrypt(1, nonce, keypair.public_key))
        proof11 = make_range_chaum_pedersen(
            message1, nonce, keypair.public_key, ONE_MOD_Q, seed, 1
        )
        self.assertTrue(proof11.is_valid(message1, keypair.public_key, ONE_MOD_Q))
        proof12 = make_range_chaum_pedersen(
            message1, nonce, keypair.public_key, ONE_MOD_Q, seed, 1, 2
        )
        self.assertTrue(proof12.is_valid(message1, keypair.public_key, ONE_MOD_Q))

        # Encode 2; able to prove within range 0 - L for any L >= 2
        message2 = get_optional(elgamal_encrypt(2, nonce, keypair.public_key))
        proof22 = make_range_chaum_pedersen(
            message2, nonce, keypair.public_key, ONE_MOD_Q, seed, 2, 2
        )
        self.assertTrue(proof22.is_valid(message2, keypair.public_key, ONE_MOD_Q))
        proof23 = make_range_chaum_pedersen(
            message2, nonce, keypair.public_key, ONE_MOD_Q, seed, 2, 5
        )
        self.assertTrue(proof23.is_valid(message2, keypair.public_key, ONE_MOD_Q))

    def test_rcp_proofs_invalid_input(self):
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q

        # Encode 2; cannot construct range proof for range not including plaintext
        message2 = get_optional(elgamal_encrypt(2, nonce, keypair.public_key))
        self.assertRaises(
            AssertionError,
            make_range_chaum_pedersen,
            message2,
            nonce,
            keypair.public_key,
            ONE_MOD_Q,
            seed,
            2,
            1,
        )
        # Encode 0; proof with incorrect plaintext runs but is invalid, even for valid range/encryption
        message0 = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        proof03bad = make_range_chaum_pedersen(
            message0, nonce, keypair.public_key, ONE_MOD_Q, seed, 3, 10
        )
        self.assertFalse(proof03bad.is_valid(message0, keypair.public_key, ONE_MOD_Q))
        # Encode 2; proof is invalid when issued wrong encryption for validation
        proof24 = make_range_chaum_pedersen(
            message2, nonce, keypair.public_key, ONE_MOD_Q, seed, 2, 4
        )
        self.assertFalse(proof24.is_valid(message0, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(elgamal_keypairs(), elements_mod_q_no_zero(), elements_mod_q())
    def test_rcp_proof_zero(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        message = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        proof = make_range_chaum_pedersen(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed, 0
        )
        proof_bad = make_range_chaum_pedersen(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed, 1
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof_bad.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(elgamal_keypairs(), elements_mod_q_no_zero(), elements_mod_q())
    def test_rcp_proof_one(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        message = get_optional(elgamal_encrypt(1, nonce, keypair.public_key))
        proof = make_range_chaum_pedersen(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed, 1
        )
        proof_bad = make_range_chaum_pedersen(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed, 0
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof_bad.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(elgamal_keypairs(), elements_mod_q_no_zero(), elements_mod_q())
    def test_rcp_proof_broken(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        # Verify two different ways to generate an invalid range C-P proof
        message = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        message_bad = get_optional(elgamal_encrypt(2, nonce, keypair.public_key))
        proof = make_range_chaum_pedersen(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed, 0
        )
        proof_bad = make_range_chaum_pedersen(
            message_bad, nonce, keypair.public_key, ONE_MOD_Q, seed, 0
        )
        self.assertFalse(proof_bad.is_valid(message_bad, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof.is_valid(message_bad, keypair.public_key, ONE_MOD_Q))


class TestDisjunctiveChaumPedersen(BaseTestCase):
    """Disjunctive Chaum-Pedersen tests"""

    def test_djcp_proofs_simple(self):
        # doesn't get any simpler than this
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message0 = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        proof0 = make_disjunctive_chaum_pedersen_zero(
            message0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof0bad = make_disjunctive_chaum_pedersen_one(
            message0, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof0.is_valid(message0, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof0bad.is_valid(message0, keypair.public_key, ONE_MOD_Q))

        message1 = get_optional(elgamal_encrypt(1, nonce, keypair.public_key))
        proof1 = make_disjunctive_chaum_pedersen_one(
            message1, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof1bad = make_disjunctive_chaum_pedersen_zero(
            message1, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof1.is_valid(message1, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof1bad.is_valid(message1, keypair.public_key, ONE_MOD_Q))

    def test_djcp_proof_invalid_inputs(self):
        # this is here to push up our coverage
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message0 = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        self.assertRaises(
            Exception,
            make_disjunctive_chaum_pedersen,
            message0,
            nonce,
            keypair.public_key,
            seed,
            3,
        )

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(elgamal_keypairs(), elements_mod_q_no_zero(), elements_mod_q())
    def test_djcp_proof_zero(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        message = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        proof = make_disjunctive_chaum_pedersen_zero(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof_bad = make_disjunctive_chaum_pedersen_one(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof_bad.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(elgamal_keypairs(), elements_mod_q_no_zero(), elements_mod_q())
    def test_djcp_proof_one(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        message = get_optional(elgamal_encrypt(1, nonce, keypair.public_key))
        proof = make_disjunctive_chaum_pedersen_one(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof_bad = make_disjunctive_chaum_pedersen_zero(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof_bad.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(elgamal_keypairs(), elements_mod_q_no_zero(), elements_mod_q())
    def test_djcp_proof_broken(
        self, keypair: ElGamalKeyPair, nonce: ElementModQ, seed: ElementModQ
    ):
        # verify two different ways to generate an invalid C-P proof.
        message = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        message_bad = get_optional(elgamal_encrypt(2, nonce, keypair.public_key))
        proof = make_disjunctive_chaum_pedersen_zero(
            message, nonce, keypair.public_key, ONE_MOD_Q, seed
        )
        proof_bad = make_disjunctive_chaum_pedersen_zero(
            message_bad, nonce, keypair.public_key, ONE_MOD_Q, seed
        )

        self.assertFalse(proof_bad.is_valid(message_bad, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(proof.is_valid(message_bad, keypair.public_key, ONE_MOD_Q))


class TestChaumPedersen(BaseTestCase):
    """Chaum-Pedersen tests"""

    def test_cp_proofs_simple(self):
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        decryption = message.partial_decrypt(keypair.secret_key)
        proof = make_chaum_pedersen(
            message, keypair.secret_key, decryption, seed, ONE_MOD_Q
        )
        bad_proof = make_chaum_pedersen(
            message, keypair.secret_key, TWO_MOD_P, seed, ONE_MOD_Q
        )
        self.assertTrue(
            proof.is_valid(message, keypair.public_key, decryption, ONE_MOD_Q)
        )
        self.assertFalse(
            bad_proof.is_valid(message, keypair.public_key, decryption, ONE_MOD_Q)
        )

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
        phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target],
    )
    @given(
        elgamal_keypairs(),
        elements_mod_q_no_zero(),
        elements_mod_q(),
        integers(0, 100),
        integers(0, 100),
    )
    def test_cp_proof(
        self,
        keypair: ElGamalKeyPair,
        nonce: ElementModQ,
        seed: ElementModQ,
        constant: int,
        bad_constant: int,
    ):
        if constant == bad_constant:
            bad_constant = constant + 1

        message = get_optional(elgamal_encrypt(constant, nonce, keypair.public_key))
        decryption = message.partial_decrypt(keypair.secret_key)
        proof = make_chaum_pedersen(
            message, keypair.secret_key, decryption, seed, ONE_MOD_Q
        )
        bad_proof = make_chaum_pedersen(
            message, keypair.secret_key, int_to_p(bad_constant), seed, ONE_MOD_Q
        )
        self.assertTrue(
            proof.is_valid(message, keypair.public_key, decryption, ONE_MOD_Q)
        )
        self.assertFalse(
            bad_proof.is_valid(message, keypair.public_key, decryption, ONE_MOD_Q)
        )


class TestConstantChaumPedersen(BaseTestCase):
    """Constant Chaum-Pedersen tests"""

    def test_ccp_proofs_simple_encryption_of_zero(self):
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message = get_optional(elgamal_encrypt(0, nonce, keypair.public_key))
        proof = make_constant_chaum_pedersen(
            message, 0, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        bad_proof = make_constant_chaum_pedersen(
            message, 1, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(bad_proof.is_valid(message, keypair.public_key, ONE_MOD_Q))

    def test_ccp_proofs_simple_encryption_of_one(self):
        keypair = elgamal_keypair_from_secret(TWO_MOD_Q)
        nonce = ONE_MOD_Q
        seed = TWO_MOD_Q
        message = get_optional(elgamal_encrypt(1, nonce, keypair.public_key))
        proof = make_constant_chaum_pedersen(
            message, 1, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        bad_proof = make_constant_chaum_pedersen(
            message, 0, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))
        self.assertFalse(bad_proof.is_valid(message, keypair.public_key, ONE_MOD_Q))

    @settings(
        deadline=timedelta(milliseconds=2000),
        suppress_health_check=[HealthCheck.too_slow],
        max_examples=10,
    )
    @given(
        elgamal_keypairs(),
        elements_mod_q_no_zero(),
        elements_mod_q(),
        integers(0, 100),
        integers(0, 100),
    )
    def test_ccp_proof(
        self,
        keypair: ElGamalKeyPair,
        nonce: ElementModQ,
        seed: ElementModQ,
        constant: int,
        bad_constant: int,
    ):
        # assume() slows down the test-case generation
        # so assume(constant != bad_constant)
        if constant == bad_constant:
            bad_constant = constant + 1

        message = get_optional(elgamal_encrypt(constant, nonce, keypair.public_key))
        message_bad = get_optional(
            elgamal_encrypt(bad_constant, nonce, keypair.public_key)
        )

        proof = make_constant_chaum_pedersen(
            message, constant, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertTrue(proof.is_valid(message, keypair.public_key, ONE_MOD_Q))

        proof_bad1 = make_constant_chaum_pedersen(
            message_bad, constant, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertFalse(
            proof_bad1.is_valid(message_bad, keypair.public_key, ONE_MOD_Q)
        )

        proof_bad2 = make_constant_chaum_pedersen(
            message, bad_constant, nonce, keypair.public_key, seed, ONE_MOD_Q
        )
        self.assertFalse(proof_bad2.is_valid(message, keypair.public_key, ONE_MOD_Q))

        proof_bad3 = ConstantChaumPedersenProof(
            proof.pad, proof.data, proof.challenge, proof.response, -1
        )
        self.assertFalse(proof_bad3.is_valid(message, keypair.public_key, ONE_MOD_Q))
