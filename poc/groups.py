"""Prime-order elliptic-curve groups for draft-irtf-cfrg-sigma-protocols.

The two groups fixed by the ciphersuites ({{ciphersuites}}): P-256
(secp256r1, NIST SP 800-186) and the G1 subgroup of BLS12-381, both as
short-Weierstrass curves in affine coordinates. A point is an `(x, y)`
tuple of integers; the identity is `None`.

Element and scalar codecs follow the ciphersuite table: compressed SEC1
for P-256 (Ne = 33) and the ZCash compressed encoding for BLS12-381 G1
(Ne = 48); scalars serialize big-endian via I2OSP in both suites, the
byte-order carve-out of the Fiat-Shamir draft's {{serialize-field}} for
fields whose defining standards fix a big-endian encoding. Deserialization
accepts only canonical encodings and rejects the identity, off-curve and
out-of-subgroup points ({{group-abstraction}}).

Standard library only. This code is for specification discussion and
test-vector verification; it is not constant-time and not intended for
production.
"""


def I2OSP(n, w):
    """Integer to big-endian octet string of width w ({{bytes-and-integers}})."""
    assert 0 <= n < 256 ** w
    return n.to_bytes(w, "big")


def OS2IP(x):
    """Big-endian octet string to integer ({{bytes-and-integers}})."""
    return int.from_bytes(x, "big")


class DeserializeError(Exception):
    """A group element or scalar failed to deserialize; the verifier rejects."""


class PrimeOrderGroup:
    """A prime-order group of order `order` on y^2 = x^3 + a*x + b over GF(p)."""

    name = None
    p = a = b = order = None
    Ne = None      # element byte length
    Ns = None      # scalar byte length

    def rhs(self, x):
        """The curve equation's right-hand side, x^3 + a*x + b mod p."""
        return (x * x * x + self.a * x + self.b) % self.p

    def add(self, P, Q):
        p = self.p
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return None
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, p - 2, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def neg(self, P):
        if P is None:
            return None
        x, y = P
        return (x, (-y) % self.p)

    def mul(self, k, P):
        assert k >= 0
        R, Q = None, P
        while k:
            if k & 1:
                R = self.add(R, Q)
            Q = self.add(Q, Q)
            k >>= 1
        return R

    def sqrt(self, v):
        """Square root mod p for p = 3 mod 4; None if v is not a QR."""
        assert self.p % 4 == 3
        r = pow(v, (self.p + 1) // 4, self.p)
        if r * r % self.p != v % self.p:
            return None
        return r

    def generator(self):
        return self.gen

    def identity(self):
        return None

    # -- element codec ({{group-abstraction}}) ------------------------------

    def serialize(self, elements):
        """Group.serialize: fixed-width canonical encodings, concatenated.
        Undefined on the identity, which is invalid in prover messages."""
        out = b""
        for P in elements:
            if P is None:
                raise ValueError("Group.serialize is undefined for the identity")
            out += self.serialize_element(P)
        return out

    def deserialize(self, buffer):
        """Group.deserialize: the inverse of serialize; rejects anything but
        a sequence of canonical encodings of non-identity subgroup points."""
        if len(buffer) % self.Ne != 0:
            raise DeserializeError("buffer length not a multiple of Ne")
        return [self.deserialize_element(buffer[i:i + self.Ne])
                for i in range(0, len(buffer), self.Ne)]

    # -- scalar codec (ciphersuites; the big-endian carve-out) ---------------

    def scalar_serialize(self, scalars):
        out = b""
        for s in scalars:
            assert 0 <= s < self.order
            out += I2OSP(s, self.Ns)
        return out

    def scalar_deserialize(self, buffer):
        if len(buffer) % self.Ns != 0:
            raise DeserializeError("buffer length not a multiple of Ns")
        out = []
        for i in range(0, len(buffer), self.Ns):
            v = OS2IP(buffer[i:i + self.Ns])
            if v >= self.order:
                raise DeserializeError("scalar not in canonical range [0, p)")
            out.append(v)
        return out


class P256Group(PrimeOrderGroup):
    """P-256 (secp256r1), NIST SP 800-186. Compressed SEC1 encoding, Ne = 33."""

    name = "P256"
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = p - 3
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    cofactor = 1
    Ne = 33
    Ns = 32

    def __init__(self):
        self.gen = self.deserialize_element(bytes.fromhex(
            "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"))

    def serialize_element(self, P):
        x, y = P
        return bytes([0x02 | (y & 1)]) + I2OSP(x, 32)

    def deserialize_element(self, buf):
        if len(buf) != self.Ne:
            raise DeserializeError("bad element length")
        prefix = buf[0]
        if prefix not in (0x02, 0x03):
            raise DeserializeError("only compressed SEC1 encodings are valid")
        x = OS2IP(buf[1:])
        if x >= self.p:
            raise DeserializeError("x coordinate out of range")
        y = self.sqrt(self.rhs(x))
        if y is None:
            raise DeserializeError("point not on curve")
        if (y & 1) != (prefix & 1):
            y = self.p - y
        return (x, y)


class BLSG1Group(PrimeOrderGroup):
    """BLS12-381 G1, RFC 9380 / pairing-friendly-curves. Compressed, Ne = 48.

    The curve order is `cofactor * order`; deserialization checks membership
    in the prime-order subgroup, so the abstraction stays prime-order."""

    name = "BLS12381G1"
    p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
    a = 0
    b = 4
    order = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    cofactor = 0x396C8C005555E1568C00AAAB0000AAAB
    Ne = 48
    Ns = 32

    def __init__(self):
        self.gen = self.deserialize_element(bytes.fromhex(
            "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac58"
            "6c55e83ff97a1aeffb3af00adb22c6bb"))

    def _y_is_larger(self, y):
        return y > (self.p - 1) // 2

    def serialize_element(self, P):
        x, y = P
        flags = 0x80 | (0x20 if self._y_is_larger(y) else 0x00)
        body = bytearray(I2OSP(x, 48))
        body[0] |= flags
        return bytes(body)

    def deserialize_element(self, buf):
        if len(buf) != self.Ne:
            raise DeserializeError("bad element length")
        c_bit = buf[0] & 0x80
        i_bit = buf[0] & 0x40
        s_bit = buf[0] & 0x20
        if not c_bit:
            raise DeserializeError("compression bit unset")
        if i_bit:
            raise DeserializeError("point at infinity rejected")
        x = OS2IP(bytes([buf[0] & 0x1F]) + buf[1:])
        if x >= self.p:
            raise DeserializeError("non-canonical x coordinate")
        y = self.sqrt(self.rhs(x))
        if y is None:
            raise DeserializeError("point not on curve")
        if self._y_is_larger(y) != bool(s_bit):
            y = self.p - y
        P = (x, y)
        if self.mul(self.order, P) is not None:
            raise DeserializeError("point not in the prime-order subgroup")
        return P


if __name__ == "__main__":
    for g in (P256Group(), BLSG1Group()):
        G = g.generator()
        assert g.mul(g.order, G) is None, g.name
        assert g.add(G, g.neg(G)) is None, g.name
        two_G = g.add(G, G)
        assert two_G == g.mul(2, G), g.name
        assert g.deserialize(g.serialize([G, two_G])) == [G, two_G], g.name
        assert len(g.serialize([G])) == g.Ne, g.name
        assert g.scalar_deserialize(g.scalar_serialize([0, g.order - 1])) \
            == [0, g.order - 1], g.name
        print(f"{g.name}: ok")
