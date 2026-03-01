#!/usr/bin/sage
# vim: syntax=python

from sagelib.duplex_sponge import SHAKE128
from sagelib.hash_to_field import OS2IP


class TestDRNG(object):
    def __init__(self, seed):
        assert len(seed) == 32
        self.hash_state = SHAKE128(b"\x00" * 64)
        self.hash_state.absorb(seed)
        self.squeeze_offset = 0

    def _squeeze(self, length):
        end = self.squeeze_offset + length
        out = self.hash_state.squeeze(end)[self.squeeze_offset:end]
        self.squeeze_offset = end
        return out

    def random_scalar(self, order):
        Ns = (int(order).bit_length() + 7) // 8
        scalar_bytes = self._squeeze(Ns + 16)
        return OS2IP(scalar_bytes) % order

    def randint(self, l, h):
        assert l < h
        return l + self.random_scalar(h - l)
