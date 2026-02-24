#!/usr/bin/sage
# vim: syntax=python

import sys
import hashlib

from cryptography.hazmat.primitives.hashes import SHAKE128, XOFHash # cryptography >= 46.0.5

from sagelib import groups
from sagelib.hash_to_field import OS2IP
from sagelib.sigma_protocols import CSRNG


class TestDRNG(object):
    def __init__(self, seed):
        self.seed = hashlib.sha256(seed).digest()

    def next_u32(self):
        val = int.from_bytes([self.seed[0], self.seed[1], self.seed[2], self.seed[3]], byteorder = 'big')
        self.seed = hashlib.sha256(val.to_bytes(4, 'big')).digest()
        return val

    def randint(self, l, h):
        rand_range = h - l
        num_bits = len(bin(rand_range)) - 2
        num_bytes = (num_bits + 7) // 8
        while True:
            i = 0
            ret_bytes = []
            while i < num_bytes:
                rand = self.next_u32()
                for b in rand.to_bytes(4, 'big'):
                    if i < num_bytes:
                        ret_bytes.append(b)
                        i += 1
                    else:
                        break
            potential_res = int.from_bytes(ret_bytes, byteorder = 'big')
            if (len(bin(potential_res)) - 2) <= num_bits:
                return l + (potential_res % rand_range)


class SeededPRNG(CSRNG):
    def __init__(self, seed: bytes, scalar_cls: type[groups.Scalar], /, tracing_enabled=False):
        assert len(seed) >= 32, "seed must be at least 32 bytes"
        self.xof = XOFHash(SHAKE128(digest_size=sys.maxsize))
        self.xof.update(seed)
        self.scalar_cls = scalar_cls
        self.tracing_enabled = tracing_enabled
        self.sampled_scalars = []

    def random_scalar(self) -> groups.Scalar:
        while True:
            b = self.xof.squeeze(self.scalar_cls.field_bytes_length)
            scalar_int = OS2IP(b)
            if 0 < scalar_int < self.scalar_cls.order:
                scalar = self.scalar_cls.field(scalar_int)
                if self.tracing_enabled:
                    self.sampled_scalars.append(scalar)
                return scalar


