#!/usr/bin/sage
# vim: syntax=python

import hashlib

def I2OSP(val, length):
    """Integer to Octet String Primitive - RFC 8017"""
    return val.to_bytes(length, byteorder='big')

def OS2IP(octets):
    """Octet String to Integer Primitive - RFC 8017"""
    return int.from_bytes(octets, byteorder='big')


class Xof:
    """Abstract XOF interface"""
    SEED_SIZE = 32

    def __init__(self, seed, dst):
        raise NotImplementedError

    def next(self, length):
        raise NotImplementedError

    @classmethod
    def expand_into_vec(cls, seed, dst, scalar_field_order, count):
        """
        Expand seed into count uniform scalars in [1, scalar_field_order - 1].

        Uses rejection sampling to ensure uniform distribution over the
        scalar field, excluding zero.
        """
        xof = cls(seed, dst)
        scalars = []
        scalar_bytes_len = (scalar_field_order.bit_length() + 7) // 8 + 16

        while len(scalars) < count:
            candidate_bytes = xof.next(scalar_bytes_len)
            candidate = OS2IP(candidate_bytes) % scalar_field_order
            if 1 <= candidate < scalar_field_order:
                scalars.append(candidate)

        return scalars


class XofShake128(Xof):
    """XOF wrapper for SHAKE128."""

    SEED_SIZE = 32

    def __init__(self, seed, dst):
        if len(seed) != self.SEED_SIZE:
            raise ValueError("seed length must be SEED_SIZE")
        if isinstance(dst, str):
            dst = dst.encode('utf-8')
        if len(dst) > 65535:
            raise ValueError("dst too long")

        self.l = 0
        # Encode: len(dst) || dst || seed
        self.prefix = I2OSP(len(dst), 2) + dst + seed

    def next(self, length):
        # Compute SHAKE128(prefix || counter, length)
        # where counter tracks how many bytes we've output
        shake = hashlib.shake_128()
        shake.update(self.prefix + I2OSP(self.l, 4))
        output = shake.digest(length)
        self.l += length
        return output


def test_xof():
    """Test XofShake128 implementation"""
    print("Testing XofShake128...")

    # Test basic functionality
    seed = b"test_seed_32_bytes_long_here"
    seed = seed + b"\x00" * (32 - len(seed))
    dst = "test-dst"

    xof = XofShake128(seed, dst)
    output1 = xof.next(16)
    output2 = xof.next(16)
    print(f"Output 1: {output1.hex()}")
    print(f"Output 2: {output2.hex()}")

    # Test expand_into_vec
    order = 2^255 - 19  # Example field order
    scalars = XofShake128.expand_into_vec(seed, dst, order, 5)
    print(f"Generated {len(scalars)} scalars")
    for i, s in enumerate(scalars):
        print(f"  Scalar {i}: {s}")
        assert 1 <= s < order, "Scalar out of range"

    print("All tests passed!")


if __name__ == "__main__":
    test_xof()
