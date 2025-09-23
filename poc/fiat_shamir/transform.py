"""
Pure Python implementation of Fiat-Shamir transformation.
Converts interactive Sigma protocols to non-interactive zero-knowledge proofs.
"""

from .duplex_sponge import DuplexSpongeInterface


class NonInteractiveProof:
    """
    Fiat-Shamir transcript for non-interactive proofs.
    """

    def __init__(self, protocol, codec, hash_state):
        self.protocol = protocol
        self.codec = codec
        self.hash_state = hash_state

    def prove(self, witness, rng):
        """Generate non-interactive proof."""
        prover_state, commitment = self.protocol.prover_commit(witness, rng)

        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        response = self.protocol.prover_response(prover_state, challenge)

        # Serialize proof
        proof = (
            self.protocol.serialize_commitment(commitment) +
            self.protocol.serialize_response(response)
        )

        return proof

    def verify(self, proof):
        """Verify non-interactive proof."""
        # Parse proof
        commitment_size = len(self.protocol.serialize_commitment(
            [self.protocol.instance.Image.identity()] * self.protocol.instance.linear_map.num_constraints
        ))

        commitment_bytes = proof[:commitment_size]
        response_bytes = proof[commitment_size:]

        # Deserialize
        commitment = self.protocol.deserialize_commitment(commitment_bytes)
        response = self.protocol.deserialize_response(response_bytes)

        # Reconstruct challenge
        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)

        # Verify
        return self.protocol.verifier(commitment, challenge, response)


class FiatShamirNIZK:
    """
    Non-interactive zero-knowledge proof via Fiat-Shamir.
    """

    def __init__(self, protocol, codec, sponge):
        self.Protocol = protocol
        self.Codec = codec
        self.Sponge = sponge

    def __call__(self, session_id, instance):
        """Create a proof interface for the given instance."""
        # Initialize hash state
        initial_state = self.Codec().init(session_id, instance.get_label())
        hash_state = self.Sponge(initial_state)
        protocol = self.Protocol(instance)
        return NonInteractiveProof(protocol, self.Codec(), hash_state)