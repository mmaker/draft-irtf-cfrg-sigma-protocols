"""
Pure Python implementation of finite field arithmetic.
Replaces SAGE's GF() functionality.
"""

class PrimeFieldElement:
    """Element of a finite field GF(p)."""

    def __init__(self, value, field):
        self.field = field
        self.value = value % field.p

    def __add__(self, other):
        if isinstance(other, int):
            return PrimeFieldElement((self.value + other) % self.field.p, self.field)
        return PrimeFieldElement((self.value + other.value) % self.field.p, self.field)

    def __sub__(self, other):
        if isinstance(other, int):
            return PrimeFieldElement((self.value - other) % self.field.p, self.field)
        return PrimeFieldElement((self.value - other.value) % self.field.p, self.field)

    def __mul__(self, other):
        if isinstance(other, int):
            return PrimeFieldElement((self.value * other) % self.field.p, self.field)
        return PrimeFieldElement((self.value * other.value) % self.field.p, self.field)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __truediv__(self, other):
        if isinstance(other, int):
            other_inv = pow(other, self.field.p - 2, self.field.p)
        else:
            other_inv = pow(other.value, self.field.p - 2, self.field.p)
        return PrimeFieldElement((self.value * other_inv) % self.field.p, self.field)

    def __pow__(self, exp):
        return PrimeFieldElement(pow(self.value, exp, self.field.p), self.field)

    def __neg__(self):
        return PrimeFieldElement((-self.value) % self.field.p, self.field)

    def __eq__(self, other):
        if isinstance(other, int):
            return self.value == (other % self.field.p)
        return self.value == other.value

    def __hash__(self):
        return hash(self.value)

    def __int__(self):
        """Allow automatic conversion to int."""
        return self.value

    def __repr__(self):
        return f"PrimeFieldElement({self.value}, GF({self.field.p}))"

    def __int__(self):
        return self.value

    def sqrt(self):
        """Compute square root if it exists (for p ≡ 3 mod 4)."""
        if self.field.p % 4 != 3:
            raise NotImplementedError("sqrt only implemented for p ≡ 3 mod 4")

        # Check if square root exists
        if pow(self.value, (self.field.p - 1) // 2, self.field.p) != 1:
            return None

        return PrimeFieldElement(pow(self.value, (self.field.p + 1) // 4, self.field.p), self.field)

    def is_square(self):
        """Check if element is a quadratic residue."""
        if self.value == 0:
            return True
        return pow(self.value, (self.field.p - 1) // 2, self.field.p) == 1


class FiniteField:
    """Finite field GF(p) for prime p."""

    def __init__(self, p):
        self.p = p
        self.order = p
        self.characteristic = p

    def __call__(self, value):
        """Create a field element."""
        if isinstance(value, PrimeFieldElement):
            return PrimeFieldElement(value.value, self)
        return PrimeFieldElement(value, self)

    def zero(self):
        return PrimeFieldElement(0, self)

    def one(self):
        return PrimeFieldElement(1, self)

    def random(self, rng):
        """Generate random field element."""
        value = rng.randint(0, self.p - 1)
        return PrimeFieldElement(value, self)

    def __repr__(self):
        return f"GF({self.p})"


def GF(p):
    """Factory function to create finite fields, mimicking SAGE's GF()."""
    return FiniteField(p)