"""
Pure Python implementation of duplex sponge construction.
Used for Fiat-Shamir transformation.
"""

import hashlib


class DuplexSpongeInterface:
    """Interface for duplex sponge operations."""

    def __init__(self, initial_state=None):
        """Initialize with optional initial state."""
        self.state = initial_state or b''
        self.hasher = hashlib.shake_128()
        if initial_state:
            self.hasher.update(initial_state)

    def absorb(self, data):
        """Absorb data into the sponge."""
        self.hasher.update(data)
        self.state += data

    def squeeze(self, length):
        """Squeeze output from the sponge."""
        # Create a new hasher with current state for squeeze
        temp_hasher = hashlib.shake_128(self.state)
        output = temp_hasher.digest(length)

        # Update internal state
        self.state += output
        self.hasher.update(output)

        return output

    def clone(self):
        """Clone the current sponge state."""
        new_sponge = DuplexSpongeInterface()
        new_sponge.state = self.state
        new_sponge.hasher = hashlib.shake_128(self.state)
        return new_sponge


class Shake128DuplexSponge(DuplexSpongeInterface):
    """SHAKE128-based duplex sponge."""

    def __init__(self, initial_state=None):
        super().__init__(initial_state)
        self.hasher = hashlib.shake_128()
        if initial_state:
            self.hasher.update(initial_state)


class Keccak256DuplexSponge(DuplexSpongeInterface):
    """Keccak256-based duplex sponge (simplified)."""

    def __init__(self, initial_state=None):
        self.state = initial_state or b''
        self.buffer = b''

    def absorb(self, data):
        """Absorb data into the sponge."""
        self.buffer += data

    def squeeze(self, length):
        """Squeeze output from the sponge."""
        # Simplified Keccak-like behavior
        h = hashlib.sha3_256(self.state + self.buffer)
        output = b''

        while len(output) < length:
            output += h.digest()
            h = hashlib.sha3_256(h.digest())

        output = output[:length]
        self.state = hashlib.sha3_256(self.state + self.buffer + output).digest()
        self.buffer = b''

        return output

    def clone(self):
        """Clone the current sponge state."""
        new_sponge = Keccak256DuplexSponge()
        new_sponge.state = self.state
        new_sponge.buffer = self.buffer
        return new_sponge