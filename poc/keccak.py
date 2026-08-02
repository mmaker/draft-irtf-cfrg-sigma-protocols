"""TurboSHAKE128 over Keccak-p[1600, 12] (RFC 9861).

The standard library has no TurboSHAKE128, so it is implemented here as a
minimal drop-in for `hashlib.shake_128`, exposing the update / copy /
digest(n) surface the duplex sponge of the Fiat-Shamir draft needs.
TurboSHAKE128(M, D=0x1F, L) absorbs M at a rate of 168 bytes, applies
pad10*1 padding with domain byte D, then squeezes L bytes. It coincides
with SHAKE128 (whose padding suffix equals the default domain byte 0x1F)
except that the permutation runs the last 12 of the 24 Keccak rounds
(Keccak-p[1600, 12]); the round count is the only difference, which the
self-test below exploits: the same sponge with all 24 rounds must match
`hashlib.shake_128`.

Standard library only; not constant-time; not intended for production.
"""

import hashlib

RATE = 168  # rate in bytes at 256-bit capacity; shared with SHAKE128

_MASK64 = (1 << 64) - 1
_RC = [  # the 24 Keccak-f round constants; TurboSHAKE uses rounds 12..23
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_RHO = [  # rotation offsets, indexed [x][y] with lane index x + 5*y
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol64(v, n):
    return v if n == 0 else ((v << n) | (v >> (64 - n))) & _MASK64


def _keccak_p1600(state, first_round):
    """Keccak-p[1600, 24 - first_round]: the last rounds of Keccak-f[1600].
    `state` is a 200-byte bytearray; returns the permuted 200 bytes."""
    a = [int.from_bytes(state[8 * i: 8 * i + 8], "little") for i in range(25)]
    for rnd in range(first_round, 24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(a[x + 5 * y], _RHO[x][y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= _RC[rnd]
    out = bytearray(200)
    for i in range(25):
        out[8 * i: 8 * i + 8] = (a[i] & _MASK64).to_bytes(8, "little")
    return out


def _xof(message, length, domain, first_round):
    """One-shot sponge: absorb at RATE, pad10*1 with `domain`, squeeze."""
    state = bytearray(200)
    i = 0
    while len(message) - i >= RATE:  # absorb full rate blocks
        for j in range(RATE):
            state[j] ^= message[i + j]
        state = _keccak_p1600(state, first_round)
        i += RATE
    for j in range(len(message) - i):  # absorb the final partial block
        state[j] ^= message[i + j]
    state[len(message) - i] ^= domain  # domain byte, then pad10*1 ...
    state[RATE - 1] ^= 0x80  # ... with the final padding bit
    state = _keccak_p1600(state, first_round)
    out = bytearray()
    while len(out) < length:  # squeeze, permuting between rate blocks
        out += state[:RATE]
        if len(out) < length:
            state = _keccak_p1600(state, first_round)
    return bytes(out[:length])


class TurboSHAKE128:
    """Minimal hashlib-compatible TurboSHAKE128 (D = 0x1F) XOF context."""

    _D = 0x1F  # domain-separation byte; the RFC 9861 default

    def __init__(self):
        self._buf = bytearray()

    def update(self, x):
        self._buf += x

    def copy(self):
        clone = TurboSHAKE128()
        clone._buf = bytearray(self._buf)
        return clone

    def digest(self, length):  # non-destructive: absorb, pad, then squeeze
        return _xof(self._buf, length, self._D, 12)


if __name__ == "__main__":
    # With all 24 rounds the sponge above is exactly SHAKE128 (same rate,
    # same padding byte), so hashlib validates the permutation, the absorb
    # loop, the padding, and the squeeze loop in one comparison. The lengths
    # cross rate-block boundaries in both directions.
    for n in (0, 1, 167, 168, 169, 400):
        m = bytes(range(256)) * 2
        assert _xof(m[:n], 500, 0x1F, 0) == hashlib.shake_128(m[:n]).digest(500)
    ctx = TurboSHAKE128()
    ctx.update(b"turbo")
    assert ctx.digest(64) == ctx.copy().digest(64)
    print("keccak: ok")
