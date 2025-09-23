"""
Composition of Sigma protocols (AND and OR proofs).
"""

from .sigma_protocols import SchnorrProof
from fiat_shamir import P256Codec, FiatShamirNIZK, Keccak256DuplexSponge


class AndProof(SchnorrProof):
    """
    AND composition of multiple Sigma protocols.
    Proves knowledge of witnesses for ALL instances.
    """

    def __init__(self, instances):
        self.protocols = [SchnorrProof(instance) for instance in instances]
        self.instance = self  # For compatibility with fiat_shamir

    @property
    def commit_bytes_len(self):
        """Total bytes needed for all commitments."""
        return sum(
            len(protocol.serialize_commitment(
                [protocol.instance.Image.identity()] * protocol.instance.linear_map.num_constraints
            ))
            for protocol in self.protocols
        )

    @property
    def response_bytes_len(self):
        """Total bytes needed for all responses."""
        return sum(
            len(protocol.serialize_response(
                [protocol.instance.Domain.field(0)] * protocol.instance.linear_map.num_scalars
            ))
            for protocol in self.protocols
        )

    def prover_commit(self, witnesses, rng):
        """Generate commitments for all subproofs."""
        prover_states = []
        commitments = []

        for protocol, witness in zip(self.protocols, witnesses):
            prover_state, commitment = protocol.prover_commit(witness, rng)
            commitments.append(commitment)
            prover_states.append(prover_state)

        return (prover_states, commitments)

    def prover_response(self, prover_states, challenge):
        """Generate responses for all subproofs."""
        responses = []
        for prover_state, protocol in zip(prover_states, self.protocols):
            response = protocol.prover_response(prover_state, challenge)
            responses.append(response)
        return responses

    def verifier(self, commitments, challenge, responses):
        """Verify all subproofs."""
        assert len(commitments) == len(responses)

        for protocol, commitment, response in zip(self.protocols, commitments, responses):
            if not protocol.verifier(commitment, challenge, response):
                return False
        return True

    def serialize_commitment(self, commitments):
        """Serialize all commitments."""
        return b''.join([
            protocol.serialize_commitment(commitment)
            for protocol, commitment in zip(self.protocols, commitments)
        ])

    def serialize_response(self, responses):
        """Serialize all responses."""
        return b''.join([
            protocol.serialize_response(response)
            for protocol, response in zip(self.protocols, responses)
        ])

    def deserialize_commitment(self, data):
        """Deserialize commitments for all subproofs."""
        commitments = []
        offset = 0

        for protocol in self.protocols:
            # Calculate commitment length for this protocol
            dummy_commitment = [protocol.instance.Image.identity()] * protocol.instance.linear_map.num_constraints
            commit_len = len(protocol.serialize_commitment(dummy_commitment))

            commitment = protocol.deserialize_commitment(data[offset:offset + commit_len])
            commitments.append(commitment)
            offset += commit_len

        return commitments

    def deserialize_response(self, data):
        """Deserialize responses for all subproofs."""
        responses = []
        offset = 0

        for protocol in self.protocols:
            # Calculate response length for this protocol
            dummy_response = [protocol.instance.Domain.field(0)] * protocol.instance.linear_map.num_scalars
            response_len = len(protocol.serialize_response(dummy_response))

            response = protocol.deserialize_response(data[offset:offset + response_len])
            responses.append(response)
            offset += response_len

        return responses

    def get_instance_label(self):
        """Get combined instance label."""
        import hashlib
        h = hashlib.sha256()
        h.update(b"AND_PROOF")
        for protocol in self.protocols:
            h.update(protocol.get_instance_label())
        return h.digest()

    def get_label(self):
        """Alias for get_instance_label for compatibility."""
        return self.get_instance_label()

    @staticmethod
    def get_protocol_id():
        """Protocol identifier for AND proofs."""
        return b'ietf sigma proof and composition' + b'\0' * 32


class P256AndCodec(P256Codec):
    """Codec for AND proofs over P-256."""

    def prover_message(self, hash_state, elements):
        """Flatten nested commitment list and absorb."""
        flat_elements = []
        for element_list in elements:
            flat_elements.extend(element_list)
        return super().prover_message(hash_state, flat_elements)


class OrProof(SchnorrProof):
    """
    OR composition of multiple Sigma protocols.
    Proves knowledge of witness for AT LEAST ONE instance.
    """

    def __init__(self, instances):
        self.protocols = [SchnorrProof(instance) for instance in instances]
        self.instance = self  # For compatibility with fiat_shamir

    def prover_commit(self, witness_index, witness, rng):
        """
        Generate commitment for OR proof.
        witness_index: index of the instance we have a witness for
        witness: the actual witness for that instance
        """
        prover_states = []
        commitments = []

        for i, protocol in enumerate(self.protocols):
            if i == witness_index:
                # Real proof for the instance we have witness for
                prover_state, commitment = protocol.prover_commit(witness, rng)
                prover_states.append(prover_state)
                commitments.append(commitment)
            else:
                # Simulated proof for other instances
                simulated_response = protocol.simulate_response(rng)
                # We'll need the challenge to compute simulated commitment
                prover_states.append(None)  # Placeholder
                commitments.append(None)    # Will be filled after challenge

        return (prover_states, commitments, witness_index)

    def prover_response(self, prover_state, challenge):
        """Generate response for OR proof after receiving challenge."""
        prover_states, commitments, witness_index = prover_state
        responses = []

        for i, protocol in enumerate(self.protocols):
            if i == witness_index:
                # Real response
                real_prover_state = prover_states[i]
                response = protocol.prover_response(real_prover_state, challenge)
                responses.append(response)
            else:
                # Simulated response
                simulated_response = protocol.simulate_response(rng=None)  # Use deterministic sim
                responses.append(simulated_response)

        return responses

    def verifier(self, commitments, challenge, responses):
        """Verify OR proof - at least one subproof must be valid."""
        valid_count = 0

        for protocol, commitment, response in zip(self.protocols, commitments, responses):
            try:
                if protocol.verifier(commitment, challenge, response):
                    valid_count += 1
            except:
                # Verification failed for this subproof
                pass

        return valid_count >= 1  # At least one must be valid

    def serialize_commitment(self, commitments):
        """Serialize OR proof commitments."""
        return b''.join([
            protocol.serialize_commitment(commitment)
            for protocol, commitment in zip(self.protocols, commitments)
        ])

    def serialize_response(self, responses):
        """Serialize OR proof responses."""
        return b''.join([
            protocol.serialize_response(response)
            for protocol, response in zip(self.protocols, responses)
        ])

    def get_instance_label(self):
        """Get combined instance label for OR proof."""
        import hashlib
        h = hashlib.sha256()
        h.update(b"OR_PROOF")
        for protocol in self.protocols:
            h.update(protocol.get_instance_label())
        return h.digest()

    @staticmethod
    def get_protocol_id():
        """Protocol identifier for OR proofs."""
        return b'ietf sigma proof or composition' + b'\0' * 33


# NIZK wrapper for AND proofs
class NIAndProof(FiatShamirNIZK):
    """Non-interactive AND proof using Fiat-Shamir."""

    def __init__(self):
        super().__init__(AndProof, P256AndCodec, Keccak256DuplexSponge)