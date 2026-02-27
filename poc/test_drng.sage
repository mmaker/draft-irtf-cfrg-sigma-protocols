#!/usr/bin/sage
# vim: syntax=python

import sys

from cryptography.hazmat.primitives.hashes import SHAKE128, XOFHash # cryptography >= 46.0.5

from sagelib import groups
from sagelib.hash_to_field import OS2IP
from sagelib.sigma_protocols import CSRNG


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


