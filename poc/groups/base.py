"""
Base classes for cryptographic groups.
"""

from abc import ABC, abstractmethod
from .field import GF, PrimeFieldElement


class Field(ABC):
    """Abstract base class for fields."""

    # Class attributes to be defined by concrete implementations
    order = None
    field = None
    field_bytes_length = None

    @classmethod
    @abstractmethod
    def scalar_byte_length(cls):
        """Return the byte length of a scalar."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def random(cls, rng):
        """Generate a random field element."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def serialize(cls, scalars):
        """Serialize a list of field elements to bytes."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def deserialize(cls, data):
        """Deserialize bytes to a list of field elements."""
        raise NotImplementedError


class ScalarField(Field):
    """Base scalar field implementation - to be subclassed with specific order."""

    def __init_subclass__(cls, order=None, **kwargs):
        """Initialize subclass with a specific field order."""
        super().__init_subclass__(**kwargs)
        if order is not None:
            cls.order = order
            cls.field = GF(order)
            cls.field_bytes_length = (order.bit_length() + 7) // 8

    @classmethod
    def scalar_byte_length(cls):
        return cls.field_bytes_length

    @classmethod
    def random(cls, rng):
        """Generate random scalar."""
        value = rng.randint(1, cls.order - 1)
        return cls.field(value)

    @classmethod
    def serialize(cls, scalars):
        """Serialize list of scalars to bytes."""
        result = b""
        for scalar in scalars:
            if isinstance(scalar, PrimeFieldElement):
                value = scalar.value
            else:
                value = scalar
            result += value.to_bytes(cls.field_bytes_length, 'little')
        return result

    @classmethod
    def deserialize(cls, data):
        """Deserialize bytes to list of scalars."""
        scalar_len = cls.field_bytes_length
        if len(data) % scalar_len != 0:
            raise ValueError("Invalid data length")

        scalars = []
        for i in range(0, len(data), scalar_len):
            value = int.from_bytes(data[i:i+scalar_len], 'little')
            scalars.append(cls.field(value))
        return scalars


class Group(ABC):
    """Abstract base class for cryptographic groups."""

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
    def serialize(cls, elements):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def deserialize(cls, data):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def element_byte_length(cls):
        raise NotImplementedError

    @classmethod
    def random(cls, rng):
        """Generate random group element."""
        scalar = cls.ScalarField.random(rng)
        return cls.scalar_mult(scalar, cls.generator())

    @classmethod
    def scalar_mult(cls, scalar, element):
        """Scalar multiplication."""
        if isinstance(scalar, PrimeFieldElement):
            scalar = scalar.value
        return element * scalar

    @classmethod
    def msm(cls, scalars, elements):
        """Multi-scalar multiplication."""
        if len(scalars) != len(elements):
            raise ValueError("Scalars and elements must have same length")

        result = cls.identity()
        for scalar, element in zip(scalars, elements):
            result = result + element * scalar
        return result