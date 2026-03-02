from sagelib.codec import Codec
from sagelib.groups import Group
from sagelib.sigma_protocols import SigmaProtocol, CSRNG
from sagelib.duplex_sponge import DuplexSpongeInterface


class NISigmaProtocol:
    """
    The generic Fiat-Shamir transformation of a Sigma protocol.
    Puts together 3 components:
    - a Sigma protocol that implements `SigmaProtocol`;
    - a codec that implements `Codec`;
    - a duplex sponge that implements `DuplexSpongeInterface`.
    """
    Protocol: SigmaProtocol = None
    Codec: Codec = None
    DuplexSponge: DuplexSpongeInterface = None

    def __init__(self, session_id, instance):
        protocol_id = self.get_protocol_id()
        assert len(protocol_id) == 64, f"Invalid protocol ID length: {len(protocol_id)} for {protocol_id}"

        self.sigma_protocol = self.Protocol(instance)
        self.codec = self.Codec()
        instance_label = self.sigma_protocol.get_instance_label()

        duplex_sponge_cls = self.DuplexSponge
        self.sponge_state = duplex_sponge_cls(protocol_id)
        self.sponge_state.absorb(self.codec.init(session_id, instance_label))

    def _prove(self, witness, rng: CSRNG):
        """
        Core proving logic that returns commitment, challenge, and response.
        The challenge is generated via the duplex sponge.
        """
        (prover_state, commitment) = self.sigma_protocol.prover_commit(witness, rng)
        self.codec.prover_message(self.sponge_state, commitment)
        challenge = self.codec.verifier_challenge(self.sponge_state)
        response = self.sigma_protocol.prover_response(prover_state, challenge)
        return (commitment, challenge, response)

    def prove(self, witness, rng: CSRNG):
        """
        Proving method using challenge-response format.
        """
        (commitment, challenge, response) = self._prove(witness, rng)
        # running the verifier here is just a sanity check
        assert self.sigma_protocol.verifier(commitment, challenge, response)
        return self.sigma_protocol.serialize_challenge(challenge) + self.sigma_protocol.serialize_response(response)

    def verify(self, proof):
        """
        Verification method using challenge-response format.
        """
        # Before running the sigma protocol verifier, one must also check that:
        # - the proof length is exactly challenge_bytes_len + response_bytes_len
        challenge_bytes_len = self.sigma_protocol.challenge_length()
        assert len(proof) == challenge_bytes_len + self.sigma_protocol.instance.response_bytes_len, f"Invalid proof length: {len(proof)} != {challenge_bytes_len + self.sigma_protocol.instance.response_bytes_len}"

        # - proof deserialization successfully produces a valid challenge and a valid response
        response_bytes, challenge_bytes = next(proof, challenge_bytes_len)
        challenge = self.sigma_protocol.deserialize_challenge(challenge_bytes)
        response = self.sigma_protocol.deserialize_response(response_bytes)
        commitment = self.sigma_protocol.simulate_commitment(response, challenge)

        # - the re-computed challenge equals the serialized challenge.
        self.codec.prover_message(self.sponge_state, commitment)
        expected_challenge = self.codec.verifier_challenge(self.sponge_state)
        if challenge != expected_challenge:
            return False

        return self.sigma_protocol.verifier(commitment, challenge, response)

    def prove_batchable(self, witness, rng: CSRNG):
        """
        Proving method using commitment-response format.

        Allows for batching.
        """
        (commitment, challenge, response) = self._prove(witness, rng)
        # running the verifier here is just a sanity check
        assert self.sigma_protocol.verifier(commitment, challenge, response)
        return self.sigma_protocol.serialize_commitment(commitment) + self.sigma_protocol.serialize_response(response)

    def verify_batchable(self, proof):
        # Before running the sigma protocol verifier, one must also check that:
        # - the proof length is exactly commit_bytes_len + response_bytes_len
        assert len(proof) == self.sigma_protocol.instance.commit_bytes_len + self.sigma_protocol.instance.response_bytes_len, f"Invalid proof length: {len(proof)} != {self.sigma_protocol.instance.commit_bytes_len + self.sigma_protocol.instance.response_bytes_len}"

        # - proof deserialization successfully produces a valid commitment and a valid response
        response_bytes, commitment_bytes = next(proof, self.sigma_protocol.instance.commit_bytes_len)
        commitment = self.sigma_protocol.deserialize_commitment(commitment_bytes)
        response = self.sigma_protocol.deserialize_response(response_bytes)

        self.codec.prover_message(self.sponge_state, commitment)
        challenge = self.codec.verifier_challenge(self.sponge_state)
        return self.sigma_protocol.verifier(commitment, challenge, response)

def next(b, l):
    return b[l:], b[:l]
