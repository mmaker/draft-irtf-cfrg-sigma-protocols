"""
Elliptic curves over finite fields.
"""

from .field import PrimeFieldElement


class EllipticCurvePoint:
    """Point on an elliptic curve."""

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.is_infinity = (x is None and y is None)

    def __add__(self, other):
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self

        if self.x == other.x:
            if self.y == other.y:
                # Point doubling
                if self.y.value == 0:
                    return self.curve.infinity()

                s = (3 * self.x * self.x + self.curve.a) / (2 * self.y)
                x3 = s * s - 2 * self.x
                y3 = s * (self.x - x3) - self.y
                return EllipticCurvePoint(self.curve, x3, y3)
            else:
                # Points are inverses
                return self.curve.infinity()
        else:
            # Point addition
            s = (other.y - self.y) / (other.x - self.x)
            x3 = s * s - self.x - other.x
            y3 = s * (self.x - x3) - self.y
            return EllipticCurvePoint(self.curve, x3, y3)

    def __mul__(self, scalar):
        """Scalar multiplication using double-and-add."""
        if isinstance(scalar, PrimeFieldElement):
            scalar = scalar.value

        if scalar == 0:
            return self.curve.infinity()

        if scalar < 0:
            return (-self) * (-scalar)

        result = self.curve.infinity()
        addend = self

        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1

        return result

    def __rmul__(self, scalar):
        return self.__mul__(scalar)

    def __neg__(self):
        if self.is_infinity:
            return self
        return EllipticCurvePoint(self.curve, self.x, -self.y)

    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity:
            return "Point at infinity"
        return f"({self.x.value}, {self.y.value})"

    def serialize(self):
        """Serialize point to bytes (compressed format)."""
        if self.is_infinity:
            return b'\x00'

        x_bytes = self.x.value.to_bytes((self.curve.field.p.bit_length() + 7) // 8, 'big')

        # Compressed format: 0x02 if y is even, 0x03 if y is odd
        if self.y.value % 2 == 0:
            return b'\x02' + x_bytes
        else:
            return b'\x03' + x_bytes

    @classmethod
    def deserialize(cls, curve, data):
        """Deserialize point from bytes."""
        if data == b'\x00':
            return curve.infinity()

        flag = data[0]
        x_bytes = data[1:]
        x_value = int.from_bytes(x_bytes, 'big')
        x = curve.field(x_value)

        # Compute y from x
        y_squared = x * x * x + curve.a * x + curve.b
        y = y_squared.sqrt()

        if y is None:
            raise ValueError("Invalid point")

        # Choose correct y based on parity
        if (flag == 0x02 and y.value % 2 == 1) or (flag == 0x03 and y.value % 2 == 0):
            y = -y

        return cls(curve, x, y)


class EllipticCurve:
    """Elliptic curve y^2 = x^3 + ax + b over a finite field."""

    def __init__(self, field, coefficients):
        self.field = field
        if len(coefficients) == 2:
            self.a = field(coefficients[0])
            self.b = field(coefficients[1])
        else:
            raise ValueError("Only Weierstrass form y^2 = x^3 + ax + b supported")

        # Check discriminant
        discriminant = -16 * (4 * self.a * self.a * self.a + 27 * self.b * self.b)
        if discriminant.value == 0:
            raise ValueError("Singular curve")

    def __call__(self, x, y):
        """Create a point on the curve."""
        if x is None and y is None:
            return self.infinity()

        x = self.field(x)
        y = self.field(y)

        # Verify point is on curve
        y_squared = y * y
        x_cubed_plus = x * x * x + self.a * x + self.b

        if y_squared != x_cubed_plus:
            raise ValueError(f"Point ({x.value}, {y.value}) not on curve")

        return EllipticCurvePoint(self, x, y)

    def infinity(self):
        """Return the point at infinity."""
        return EllipticCurvePoint(self, None, None)

    def random_point(self, rng):
        """Generate a random point on the curve."""
        while True:
            x = self.field.random(rng)
            y_squared = x * x * x + self.a * x + self.b

            if y_squared.is_square():
                y = y_squared.sqrt()
                # Randomly choose positive or negative y
                if rng.randint(0, 1):
                    y = -y
                return EllipticCurvePoint(self, x, y)

    def __repr__(self):
        return f"EllipticCurve(GF({self.field.p}), [${self.a.value}, {self.b.value}])"