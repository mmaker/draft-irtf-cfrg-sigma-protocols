"""
P-256 (secp256r1) elliptic curve group implementation.
"""

from .field import GF
from .elliptic_curve import EllipticCurve
from .base import Group, ScalarField


# P-256 scalar field with order n
class P256ScalarField(ScalarField, order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551):
    """Scalar field for P-256 group."""
    pass


class GroupP256(Group):
    """NIST P-256 (secp256r1) elliptic curve group."""

    name = "P-256"

    # P-256 parameters
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    a = p - 3
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

    # Generator point
    Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

    # Initialize field and curve
    field = GF(p)
    curve = EllipticCurve(field, [a, b])
    ScalarField = P256ScalarField

    _generator = None
    _identity = None

    @classmethod
    def generator(cls):
        if cls._generator is None:
            cls._generator = cls.curve(cls.Gx, cls.Gy)
        return cls._generator

    @classmethod
    def identity(cls):
        if cls._identity is None:
            cls._identity = cls.curve.infinity()
        return cls._identity

    @classmethod
    def element_byte_length(cls):
        return 33  # Compressed point format

    @classmethod
    def serialize(cls, elements):
        """Serialize list of elements to bytes (compressed format)."""
        result = b""
        for element in elements:
            if element.is_infinity:
                result += b'\x00' + b'\x00' * 32
            else:
                x_bytes = element.x.value.to_bytes(32, 'big')
                # Compressed format
                if element.y.value % 2 == 0:
                    result += b'\x02' + x_bytes
                else:
                    result += b'\x03' + x_bytes
        return result

    @classmethod
    def deserialize(cls, data):
        """Deserialize bytes to list of elements."""
        if len(data) % 33 != 0:
            raise ValueError("Invalid data length")

        elements = []
        for i in range(0, len(data), 33):
            point_data = data[i:i+33]

            if point_data[0] == 0x00:
                elements.append(cls.identity())
                continue

            flag = point_data[0]
            x_value = int.from_bytes(point_data[1:], 'big')
            x = cls.field(x_value)

            # Compute y^2 = x^3 + ax + b
            y_squared = x * x * x + cls.field(cls.a) * x + cls.field(cls.b)
            y = y_squared.sqrt()

            if y is None:
                raise ValueError("Invalid point")

            # Choose correct y based on parity
            if (flag == 0x02 and y.value % 2 == 1) or (flag == 0x03 and y.value % 2 == 0):
                y = -y

            elements.append(cls.curve(x.value, y.value))

        return elements