#!/usr/bin/sage
# vim: syntax=python

from sagelib.duplex_sponge import SHAKE128
from sagelib.codec import decode_scalar
from sagelib.hash_to_field import OS2IP
from sagelib.sigma_protocols import CSRNG
from sagelib import groups


class TestDRNG(CSRNG):
    def __init__(self, seed: bytes, scalar_cls: type[groups.Scalar], /):
        assert len(seed) == 32, "seed must be exactly 32 bytes"
        self.scalar_cls = scalar_cls
        self.hash_state = SHAKE128(b"sigma-proofs/TestDRNG/SHAKE128".ljust(64, b"\x00"))
        self.hash_state.absorb(seed)
        self.squeeze_offset = 0

    def _squeeze(self, length: int) -> bytes:
        end = self.squeeze_offset + length
        out = self.hash_state.squeeze(end)[self.squeeze_offset:end]
        self.squeeze_offset = end
        return out

    def getrandom(self, length: int) -> bytes:
        return self._squeeze(length)

    def random_scalar(self) -> groups.Scalar:
        uniform_bytes = self.getrandom(self.scalar_cls.scalar_byte_length() + 32)
        return decode_scalar(self.scalar_cls, uniform_bytes)

    def randint(self, l: int, h: int) -> int:
        assert l < h
        rand_range = h - l
        Ns = (int(rand_range).bit_length() + 7) // 8
        random_int = OS2IP(self.getrandom(Ns + 32)) % rand_range
        return l + random_int
