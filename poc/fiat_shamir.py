"""The Fiat-Shamir transform of draft-irtf-cfrg-fiat-shamir.

The duplex sponge interface ({{duplex-sponge}}) with its two hash
instantiations -- SHAKE128 ({{suite-shake128}}, via hashlib) and
TurboSHAKE128 ({{suite-turboshake128}}, via keccak.py) -- session-id
derivation ({{session-id}}), and the codecs of the NARG serialization
section: variable-length byte strings, unsigned integers, and prime-field
elements, with the big-endian carve-out for fields whose defining
standards fix a big-endian serialization ({{serialize-field}}).

Serialization is total on canonical inputs; deserialization is the strict
inverse and raises `Reject` on anything else -- a non-canonical value, a
truncated buffer, an overflowing length prefix. Decoding ({{decoding-uint}})
is the distinct, infallible operation that turns squeezed bytes into a
scalar: the bytes are read little-endian for every modulus and reduced.

Standard library only. This code is for specification discussion and
test-vector verification; it is not constant-time and not intended for
production.
"""

import hashlib

RATE = 168  # duplex sponge rate in bytes; the capacity is 32

# DecodeUint oversamples by k/8 extra bytes for a k-bit security level;
# SHAKE128 targets 128 bits, so 16 extra bytes bound the reduction bias
# to 2^-128 (matching RFC 9380, Section 5).
EXTRA = 16


class Reject(Exception):
    """A NARG string failed to parse; the verifier rejects."""


class DuplexSponge:
    """Squeeze(n) yields the next n bytes of XOF(session_id || zeros ||
    absorbed) for the chosen hash suite. Consecutive squeezes continue one
    stream; a non-empty absorb after a squeeze restarts it. An empty absorb
    is a no-op (it never restarts the stream). Squeezed bytes are never fed
    back into the state."""

    def __init__(self, session_id, new_ctx=hashlib.shake_128):
        assert len(session_id) == 32
        self._ctx = new_ctx()
        self._ctx.update(session_id + bytes(RATE - 32))  # pad to the rate
        self._reader = None

    def absorb(self, x):
        if len(x) == 0:  # Absorb("") is the identity: leave the state untouched
            return
        self._reader = None
        self._ctx.update(x)

    def squeeze(self, n):
        if self._reader is None:
            self._reader = (self._ctx.copy(), 0)
        ctx, off = self._reader
        out = ctx.digest(off + n)[off:]
        self._reader = (ctx, off + n)
        return out


def derive_session_id(tag, new_ctx=hashlib.shake_128):
    """DeriveSessionID ({{session-id}}): absorb the application tag under a
    32-byte domain-separation label, squeeze the 32-byte session id."""
    sponge = DuplexSponge(b"irtf-cfrg-fiat-shamir/session-id", new_ctx)
    sponge.absorb(tag)
    return sponge.squeeze(32)


# --- Codecs -----------------------------------------------------------------

def field_width(p):
    """Ns, the fixed serialization width of the field of characteristic p."""
    return ((p - 1).bit_length() + 7) // 8


def serialize_varlen(s):
    """SerializeVarLenString: 4-byte little-endian length || bytes."""
    return len(s).to_bytes(4, "little") + s


def deserialize_varlen(buf):
    """DeserializeVarLenString: a 4-byte length N, then N payload bytes."""
    if len(buf) < 4:
        raise Reject
    n = int.from_bytes(buf[:4], "little")
    if len(buf) - 4 < n:  # not 4 + n <= len(buf): that sum can overflow
        raise Reject
    return buf[4: 4 + n]


def serialize_uint(x, p):
    """SerializeUint: fixed-width little-endian integer mod p."""
    assert 0 <= x < p
    return x.to_bytes(field_width(p), "little")


def deserialize_uint(buf, p):
    """DeserializeUint: exactly Ns canonical little-endian bytes, x < p."""
    ns = field_width(p)
    if len(buf) < ns:
        raise Reject
    x = int.from_bytes(buf[:ns], "little")
    if x >= p:
        raise Reject
    return x


def serialize_field(coordinates, p, m):
    """SerializeField: concatenate the fixed-width little-endian encodings
    of the m coordinates of a degree-m field element (the default path)."""
    if len(coordinates) != m:
        raise ValueError("wrong number of field coordinates")
    if any(x < 0 or x >= p for x in coordinates):
        raise ValueError("field coordinate out of range")
    ns = field_width(p)
    return b"".join(x.to_bytes(ns, "little") for x in coordinates)


def serialize_field_be(coordinates, p, m):
    """The big-endian carve-out of the field codec: I2OSP per coordinate,
    mandated when the field's standard fixes a big-endian serialization
    (P-256 per SEC1, BLS12-381)."""
    if len(coordinates) != m:
        raise ValueError("wrong number of field coordinates")
    if any(x < 0 or x >= p for x in coordinates):
        raise ValueError("field coordinate out of range")
    ns = field_width(p)
    return b"".join(x.to_bytes(ns, "big") for x in coordinates)


def deserialize_field(buf, off, p, m):
    """DeserializeField: parse m canonical fixed-width coordinates modulo p
    starting at `off`; return (coordinates, new offset)."""
    ns = field_width(p)
    coordinates = []
    for i in range(m):
        start = off + i * ns
        if len(buf) - start < ns:
            raise Reject
        x = int.from_bytes(buf[start: start + ns], "little")
        if x >= p:
            raise Reject
        coordinates.append(x)
    return tuple(coordinates), off + m * ns


def decode_uint(buf, p):
    """DecodeUint ({{decoding-uint}}): reduce squeezed bytes modulo p. The
    bytes are interpreted little-endian for every modulus, byte-order
    carve-out or not; infallible and, with EXTRA oversampled bytes,
    distribution-preserving."""
    return int.from_bytes(buf, "little") % p


if __name__ == "__main__":
    from keccak import TurboSHAKE128

    for new_ctx in (hashlib.shake_128, TurboSHAKE128):
        # The stream laws: split absorbs and split squeezes change nothing,
        # and a non-empty absorb restarts the output stream.
        one = DuplexSponge(bytes(32), new_ctx)
        one.absorb(b"ab")
        one.absorb(b"c")
        two = DuplexSponge(bytes(32), new_ctx)
        two.absorb(b"abc")
        assert one.squeeze(16) + one.squeeze(16) == two.squeeze(32)
        assert len(derive_session_id(b"tag", new_ctx)) == 32

    p = 2 ** 255 - 19
    assert deserialize_uint(serialize_uint(p - 1, p), p) == p - 1
    assert deserialize_varlen(serialize_varlen(b"proof")) == b"proof"
    assert deserialize_field(serialize_field((1, p - 1), p, 2), 0, p, 2) \
        == ((1, p - 1), 2 * field_width(p))
    for bad in (serialize_uint(p - 1, p)[:-1],           # short
                (p).to_bytes(field_width(p), "little"),  # non-canonical
                ):
        try:
            deserialize_uint(bad, p)
            raise AssertionError("must reject")
        except Reject:
            pass
    assert decode_uint(p.to_bytes(48, "little"), p) == 0
    print("fiat_shamir: ok")
