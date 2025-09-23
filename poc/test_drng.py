#!/usr/bin/env python3
"""
Deterministic random number generator for testing.
"""

class TestDRNG:
    """Deterministic random number generator for consistent test results."""

    def __init__(self, seed):
        """Initialize with a seed."""
        if isinstance(seed, bytes):
            seed = int.from_bytes(seed, 'big')
        self.state = seed

    def _next(self):
        """Generate next random value using linear congruential generator."""
        # Using parameters from Numerical Recipes
        self.state = (1664525 * self.state + 1013904223) & 0xFFFFFFFF
        return self.state

    def randint(self, a, b):
        """Generate random integer in range [a, b] inclusive."""
        if a > b:
            raise ValueError("a must be <= b")
        range_size = b - a + 1
        return a + (self._next() % range_size)

    def randbytes(self, n):
        """Generate n random bytes."""
        result = b''
        for _ in range(n):
            result += bytes([self._next() & 0xFF])
        return result