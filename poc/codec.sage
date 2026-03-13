
from abc import ABC, abstractmethod
from sagelib import groups
from sagelib.hash_to_field import OS2IP


class Codec(ABC):
    """
    This is the abstract API of a codec.

    A codec is a collection of:
    - functions that map prover messages into the hash function domain,
    - functions that map hash outputs into verifier messages (of the desired distribution).
    """

    @abstractmethod
    def prover_message(self, hash_state, elements: list):
        raise NotImplementedError

    @abstractmethod
    def verifier_challenge(self, hash_state):
        raise NotImplementedError


def decode_scalar(scalar_cls: type[groups.Scalar], uniform_bytes: bytes):
    scalar = OS2IP(uniform_bytes) % scalar_cls.order
    return scalar_cls.field(scalar)


def decode_scalar_from_hash(hash_state, scalar_cls: type[groups.Scalar]):
    uniform_bytes = hash_state.squeeze(scalar_cls.scalar_byte_length() + 32)
    return decode_scalar(scalar_cls, uniform_bytes)


class ByteSchnorrCodec(Codec):
    GG: groups.Group = None

    def prover_message(self, hash_state, elements: list):
        hash_state.absorb(self.GG.serialize(elements))

    def verifier_challenge(self, hash_state):
        # see https://eprint.iacr.org/2025/536.pdf, Appendix C.
        return decode_scalar_from_hash(hash_state, self.GG.ScalarField)


class Bls12381Codec(ByteSchnorrCodec):
    GG = groups.BLS12_381_G1


class P256Codec(ByteSchnorrCodec):
    GG = groups.GroupP256()
