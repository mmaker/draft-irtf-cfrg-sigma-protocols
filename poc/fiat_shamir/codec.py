"""
Pure Python implementation of codecs for Sigma protocols.
"""

from abc import ABC, abstractmethod
from groups import GroupP256


def I2OSP(n, length):
    """Convert integer to octet string."""
    if n < 0 or n >= 256**length:
        raise ValueError("Integer too large for length")
    return n.to_bytes(length, 'big')


def OS2IP(octets):
    """Convert octet string to integer."""
    return int.from_bytes(octets, 'big')


class Codec(ABC):
    """
    Abstract codec for mapping between prover messages and hash domains.
    """

    def init(self, session_id, instance_label):
        """Initialize hash state with session ID and instance label."""
        return b''.join([
            I2OSP(len(session_id), 4),
            session_id,
            I2OSP(len(instance_label), 4),
            instance_label
        ])

    @abstractmethod
    def prover_message(self, hash_state, elements):
        raise NotImplementedError

    @abstractmethod
    def verifier_challenge(self, hash_state):
        raise NotImplementedError


class ByteSchnorrCodec(Codec):
    """Byte-oriented codec for Schnorr-type proofs."""

    GG = None  # Group to be set by subclasses

    def prover_message(self, hash_state, elements):
        """Encode prover message into hash state."""
        hash_state.absorb(self.GG.serialize(elements))

    def verifier_challenge(self, hash_state):
        """Generate verifier challenge from hash state."""
        # Following the specification in Appendix C
        uniform_bytes = hash_state.squeeze(
            self.GG.ScalarField.scalar_byte_length() + 16
        )
        scalar = OS2IP(uniform_bytes) % self.GG.ScalarField.order
        return scalar


class P256Codec(ByteSchnorrCodec):
    """Codec for P-256 group."""
    GG = GroupP256


