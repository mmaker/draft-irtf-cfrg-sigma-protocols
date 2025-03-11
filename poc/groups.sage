#!/usr/bin/sage
# vim: syntax=python

import sys
import hashlib
import struct
from abc import ABC, abstractmethod

from hash_to_field import I2OSP, OS2IP, expand_message_xmd, expand_message_xof, XMDExpander, hash_to_field

try:
    from sagelib.suite_p256 import p256_sswu_ro, p256_order, p256_p, p256_F, p256_A, p256_B
    from sagelib.suite_p384 import p384_sswu_ro, p384_order, p384_p, p384_F, p384_A, p384_B
    from sagelib.suite_p521 import p521_sswu_ro, p521_order, p521_p, p521_F, p521_A, p521_B
    from sagelib.common import sgn0
    from sagelib.ristretto_decaf import Ed25519Point, Ed448GoldilocksPoint
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

# little-endian version of I2OSP
def I2OSP_le(val, length):
    val = int(val)
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = [0] * length
    val_ = val
    for idx in range(0, length):
        ret[idx] = val_ & 0xff
        val_ = val_ >> 8
    ret = struct.pack("=" + "B" * length, *ret)
    assert OS2IP_le(ret, True) == val
    return ret

# little-endian version of OS2IP
def OS2IP_le(octets, skip_assert=False):
    ret = 0
    for octet in reversed(struct.unpack("=" + "B" * len(octets), octets)):
        ret = ret << 8
        ret += octet
    if not skip_assert:
        assert octets == I2OSP_le(ret, len(octets))
    return ret

class Scalar(ABC):
    def __new__(cls, order, *args, **kwargs):
        cls.field = GF(order)  # Delegate field operations to GF instance
        cls.order = order
        cls.field_bytes_length = (order.bit_length() + 7) // 8
        return cls

    def __getattr__(self, name):
        return getattr(self.field, name)  # Delegate missing attributes

    @classmethod
    def scalar_byte_length(cls):
        return int(cls.field_bytes_length)

    @classmethod
    def random(cls, rng):
        return cls.field(rng.randint(1, cls.order - 1))

    @classmethod
    @abstractmethod
    def serialize_scalar(cls, scalar):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def deserialize_scalar(cls, encoded):
        raise NotImplementedError


class NISTCurveScalar(Scalar):
    def __init__(self, order, F, L, H, expander, k):
        Scalar.__init__(self, order)
        self.m = F.degree()
        self.L = L
        self.k = k
        self.H = H
        self.expander = expander

    @classmethod
    def _serialize(cls, scalar):
        assert(0 <= int(scalar) < cls.order)
        return I2OSP(scalar, cls.scalar_byte_length())

    @classmethod
    def _deserialize(cls, encoded):
        return OS2IP(encoded)

    @classmethod
    def serialize(cls, scalars):
        return b"".join([cls._serialize(scalar) for scalar in scalars])

    @classmethod
    def deserialize(cls, encoded):
        encoded_len = len(encoded)
        scalar_len = cls.scalar_byte_length()
        num_scalars, remainder = divmod(encoded_len, scalar_len)
        if remainder != 0:
            raise ValueError("invalid scalar length")
        return [
            cls._deserialize(encoded[i: i + scalar_len])
            for i in range(0, encoded_len, scalar_len)
        ]

    @classmethod
    def hash_to_scalar(cls, msg, dst):
        expander = cls.expander(dst, cls.H, cls.k)
        return hash_to_field(msg, 1, cls.order, cls.m, cls.L, expander)[0][0]



class Group(ABC):
    ScalarField = None
    name = None

    @classmethod
    @abstractmethod
    def generator(cls):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def identity(cls):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def order(cls):
        raise NotImplementedError

    @abstractmethod
    def _serialize(self, element):
        raise NotImplementedError

    @abstractmethod
    def _deserialize(self, element):
        raise NotImplementedError

    @classmethod
    def serialize(cls, elements):
        return b"".join([cls._serialize(element) for element in elements])

    @classmethod
    def deserialize(cls, encoded: bytes):
        encoded_len = len(encoded)
        element_len = cls.element_byte_length()
        num_elements, remainder = divmod(encoded_len, element_len)
        if remainder != 0:
            raise ValueError("invalid element length")
        return [
            cls._deserialize(encoded[i: i + element_len])
            for i in range(0, encoded_len, element_len)
        ]

    @classmethod
    @abstractmethod
    def element_byte_length(self):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def hash_to_group(cls, x):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def scalar_mult(cls, x, y):
        raise NotImplementedError

    @classmethod
    def random(cls, rng):
        return cls.generator() * cls.ScalarField.random(rng)

    @classmethod
    def msm(cls, scalars, points):
        return sum(cls.scalar_mult(scalars[i], points[i]) for i in range(len(scalars)))

    def __str__(self):
        return self.name

class GroupNISTCurve(Group):
    def __new__(cls, name, suite, F, A, B, p, order, gx, gy, L, H, expander, k):
        cls.F = F
        EC = EllipticCurve(F, [F(A), F(B)])
        cls.curve = EC
        cls.gx = gx
        cls.gy = gy
        cls.p = p
        cls.a = A
        cls.b = B
        cls.group_order = order
        cls.h2c_suite = suite
        cls.G = EC(F(gx), F(gy))
        cls.field_bytes_length = int(ceil(len(cls.p.bits()) / 8))
        cls.ScalarField = NISTCurveScalar(order, F, L, H, expander, k)
        cls.name = name
        return super(GroupNISTCurve, cls).__new__(cls)

    @classmethod
    def generator(cls):
        return cls.G

    @classmethod
    def order(cls):
        return cls.group_order

    @classmethod
    def identity(cls):
        return cls.curve(0)

    @classmethod
    def _serialize(cls, element):
        x, y = element[0], element[1]
        sgn = sgn0(y)
        byte = 2 if sgn == 0 else 3
        return I2OSP(byte, 1) + I2OSP(x, cls.field_bytes_length)

   # this is using point compression
    @classmethod
    def _deserialize(cls, encoded):
        # 0x02 | 0x03 || x
        pve = encoded[0] == 0x02
        nve = encoded[0] == 0x03
        assert(pve or nve)
        assert(len(encoded) % 2 != 0)
        element_length = (len(encoded) - 1) / 2
        x = OS2IP(encoded[1:])
        y2 = x^3 + cls.a*x + cls.b
        y = y2.sqrt()
        parity = 0 if pve else 1
        if sgn0(y) != parity:
            y = -y
        return cls.curve(cls.F(x), cls.F(y))

    @classmethod
    def element_byte_length(cls):
        return int(1 + cls.field_bytes_length)

    @classmethod
    def hash_to_group(cls, msg, dst):
        cls.h2c_suite.expand._dst = dst
        return cls.h2c_suite(msg)

    @classmethod
    def scalar_mult(cls, x, y):
        return x * y

    def vec_scalar_mult(self, scalar, points):
        return [point * scalar for point in points]

class GroupP256(GroupNISTCurve):
    def __new__(cls):
        # See FIPS 186-3, section D.2.3
        gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
        gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        return GroupNISTCurve.__new__(cls, "P256_XMD:SHA-256_SSWU_RO_", p256_sswu_ro, p256_F, p256_A, p256_B, p256_p, p256_order, gx, gy, 48, hashlib.sha256, XMDExpander, 128)

class GroupP384(GroupNISTCurve):
    def __new__(cls):
        # See FIPS 186-3, section D.2.4
        gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
        gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
        return GroupNISTCurve.__new__(cls, "P384_XMD:SHA-384_SSWU_RO_", p384_sswu_ro, p384_F, p384_A, p384_B, p384_p, p384_order, gx, gy, 72, hashlib.sha384, XMDExpander, 192)

class GroupP521(GroupNISTCurve):
    def __new__(cls):
        # See FIPS 186-3, section D.2.5
        gx = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
        gy = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
        return GroupNISTCurve.__new__(cls, "P521_XMD:SHA-512_SSWU_RO_", p521_sswu_ro, p521_F, p521_A, p521_B, p521_p, p521_order, gx, gy, 98, hashlib.sha512, XMDExpander, 256)

class Ristretto255ScalarField(Scalar):
    def __init__(self, order):
        Scalar.__init__(self, order)
        self.k = 128

    @classmethod
    def serialize(cls, scalar):
        return I2OSP(scalar % cls.order, cls.scalar_byte_length())[::-1]

    def hash_to_scalar(self, msg, dst):
        uniform_bytes = expand_message_xmd(msg, dst, 64, hashlib.sha512, self.k)
        return OS2IP_le(uniform_bytes) % self.order


class GroupRistretto255(Group):
    def __new__(cls):
        cls.L = 48
        cls.field_bytes_length = 32
        cls.ScalarField = Ristretto255ScalarField(Ed25519Point.order)
        return Group.__new__(cls, "ristretto255")

    def generator(self):
        return Ed25519Point.base()

    def order(self):
        return Ed25519Point.order

    def identity(self):
        return Ed25519Point.identity()

    def _serialize(self, element):
        return element.encode()

    def _deserialize(self, encoded):
        return Ed25519Point.decode(encoded)

    def element_byte_length(self):
        return self.field_bytes_length

    @classmethod
    def hash_to_group(cls, msg, dst):
        return Ed25519Point.hash_to_group(msg, dst)

    def scalar_mult(self, x, y):
        return x * y

class Decaf448ScalarField(Scalar):
    def __init__(self, order):
        Scalar.__init__(self, order)
        self.k = 224

    def serialize_scalar(self, scalar):
        return I2OSP(scalar % self.order, self.scalar_byte_length())[::-1]

    def hash_to_scalar(self, msg, dst):
        uniform_bytes = expand_message_xof(msg, dst, int(64), hashlib.shake_256, self.k)
        return OS2IP_le(uniform_bytes) % self.order()

class GroupDecaf448(Group):
    def __new__(cls):
        cls.L = 84
        cls.field_bytes_length = 56
        cls.ScalarField = Decaf448ScalarField(Ed448GoldilocksPoint.order)
        return Group.__new__(cls, "decaf448")

    @classmethod
    def generator(cls):
        return Ed448GoldilocksPoint.base()

    @classmethod
    def order(cls):
        return Ed448GoldilocksPoint.order

    @classmethod
    def identity(cls):
        return Ed448GoldilocksPoint.identity()

    def _serialize(self, element):
        return element.encode()

    def _deserialize(self, encoded):
        return Ed448GoldilocksPoint.decode(encoded)

    def element_byte_length(self):
        return self.field_bytes_length

    def hash_to_group(self, msg, dst):
        return Ed448GoldilocksPoint.hash_to_group(msg, dst)

    def scalar_mult(self, x, y):
        return x * y
