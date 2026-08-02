"""Pure-Python reference generator for draft-irtf-cfrg-sigma-protocols vectors.

Standard library only (hashlib): no Sage, no `cryptography`. It implements the
current draft faithfully -- the implicit generator at `elements[0]`, the
coefficient-carrying sparse serialization of {{serialize-linear-relations}},
and the Fiat-Shamir challenge of {{challenge-derivation}} (DeriveSessionID ->
DS.Init -> absorb SerializeLinearRelation -> absorb commitment ->
DecodeField(Squeeze(Ns + 16))). It regenerates the two happy-path vector files
included by the draft's "Test Vectors" appendix:

    vectors/sigma-proofs_Shake128_P256.{json,txt}
    vectors/sigma-proofs_Shake128_BLS12381.{json,txt}

The seven relations are those catalogued in TESTS.md. Everything the draft body
leaves unpinned is pinned here and mirrored in the draft's "Test Vectors"
appendix: each proof's tag is `{name}-{flavor}-with-{ciphersuite}` with the
flavor marker `DSFS` (batchable) or `CMPT` (compact), as {{sigma-proofs-tag}}
requires; each vector draws three PRNG streams, each a SHAKE128 duplex sponge
initialized with `DeriveSessionID` of a US-ASCII PRNG tag: the instance and
witness scalars (in the order documented per relation) come from
`TestDRNG-SIGMA-PROOFS-{ciphersuite}-{name}`, and each flavor's commitment
nonces from `TestDRNG-SIGMA-PROOFS-{DSFS|CMPT}-{ciphersuite}-{name}`; a
scalar is `DecodeField(Squeeze(Ns + 16), p, 1)`;
auxiliary generators are `h * G` for an `h` drawn the same way (test-only: the
discrete logarithm is known, which does not affect proof validity).

This code is for specification discussion and test-vector generation; it is not
constant-time and not intended for production.
"""

import hashlib
import json
import os
import textwrap

# --------------------------------------------------------------------------
# Bytes and integers ({{bytes-and-integers}} of both drafts).
# --------------------------------------------------------------------------

def I2OSP(n, w):
    assert 0 <= n < 256 ** w
    return n.to_bytes(w, "big")

def OS2IP(x):
    return int.from_bytes(x, "big")

def LE(n, w):
    assert 0 <= n < 256 ** w
    return n.to_bytes(w, "little")

def LE2IP(x):
    return int.from_bytes(x, "little")


# --------------------------------------------------------------------------
# Error taxonomy. Each rejection carries the error class of TESTS.md, so the
# adversarial vectors can pin *why* a NARG string is rejected, not merely that
# it is. `verify` is the catch-all for a well-formed proof whose challenge
# recomputation or verification equation fails.
# --------------------------------------------------------------------------

class SigmaError(Exception):
    cls = "error"

class GroupDeserializeError(SigmaError):
    cls = "deserialize-group"

class ScalarDeserializeError(SigmaError):
    cls = "deserialize-scalar"

class ProofLengthError(SigmaError):
    cls = "length"

class InstanceError(SigmaError):
    cls = "instance"

class VerifyError(SigmaError):
    cls = "verify"


# --------------------------------------------------------------------------
# SHAKE128 duplex sponge (fiat-shamir draft, {{suite-shake128}}).
# Rate R = 168; Init absorbs session_id || zeros(R - 32); Squeeze finalizes a
# copy of the absorbing context and continues one XOF stream across squeezes.
# --------------------------------------------------------------------------

SHAKE128_RATE = 168

class DuplexSpongeShake128:
    def __init__(self, session_id):
        assert len(session_id) == 32
        self.ctx = hashlib.shake_128()
        self.ctx.update(session_id + bytes(SHAKE128_RATE - 32))
        self._reader = None

    def absorb(self, x):
        self.ctx.update(x)
        if len(x) != 0:
            self._reader = None

    def squeeze(self, n):
        if self._reader is None:
            self._reader = (self.ctx.copy(), 0)
        ctx, off = self._reader
        out = ctx.digest(off + n)[off:off + n]
        self._reader = (ctx, off + n)
        return out


def derive_session_id(tag):
    """DeriveSessionID of {{session-id}} (SHAKE128 instantiation)."""
    ds = DuplexSpongeShake128(b"irtf-cfrg-fiat-shamir/session-id")
    ds.absorb(tag)
    return ds.squeeze(32)


# --------------------------------------------------------------------------
# Prime-order groups over short-Weierstrass curves, affine coordinates.
# Identity is None; points are (x, y) integer tuples.
# --------------------------------------------------------------------------

class PrimeOrderGroup:
    name = None
    p = a = b = order = None
    Ne = None
    Ns = 32

    def is_on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

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

    def serialize(self, elements):
        out = b""
        for P in elements:
            if P is None:
                raise ValueError("Group.serialize is undefined for the identity")
            out += self.serialize_element(P)
        return out

    def deserialize(self, buffer):
        if len(buffer) % self.Ne != 0:
            raise GroupDeserializeError("buffer length not a multiple of Ne")
        return [self.deserialize_element(buffer[i:i + self.Ne])
                for i in range(0, len(buffer), self.Ne)]


class P256Group(PrimeOrderGroup):
    """P-256 (secp256r1), NIST SP 800-186. Compressed SEC1 encoding, Ne = 33."""
    name = "P256"
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = p - 3
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    cofactor = 1
    Ne = 33

    def __init__(self):
        self.gen = self.deserialize_element(bytes.fromhex(
            "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"))

    def serialize_element(self, P):
        x, y = P
        return bytes([0x02 | (y & 1)]) + I2OSP(x, 32)

    def deserialize_element(self, buf):
        if len(buf) != self.Ne:
            raise GroupDeserializeError("bad element length")
        prefix = buf[0]
        if prefix not in (0x02, 0x03):
            raise GroupDeserializeError("only compressed SEC1 encodings are valid")
        x = OS2IP(buf[1:])
        if x >= self.p:
            raise GroupDeserializeError("x coordinate out of range")
        y = self.sqrt((x * x * x + self.a * x + self.b) % self.p)
        if y is None:
            raise GroupDeserializeError("point not on curve")
        if (y & 1) != (prefix & 1):
            y = self.p - y
        return (x, y)


class BLSG1Group(PrimeOrderGroup):
    """BLS12-381 G1, RFC 9380 / pairing-friendly-curves. Compressed, Ne = 48."""
    name = "BLS12381G1"
    p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
    a = 0
    b = 4
    order = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    cofactor = 0x396C8C005555E1568C00AAAB0000AAAB
    Ne = 48

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
            raise GroupDeserializeError("bad element length")
        c_bit = buf[0] & 0x80
        i_bit = buf[0] & 0x40
        s_bit = buf[0] & 0x20
        if not c_bit:
            raise GroupDeserializeError("compression bit unset")
        if i_bit:
            raise GroupDeserializeError("point at infinity rejected")
        x = OS2IP(bytes([buf[0] & 0x1F]) + buf[1:])
        if x >= self.p:
            raise GroupDeserializeError("non-canonical x coordinate")
        y = self.sqrt((x * x * x + self.b) % self.p)
        if y is None:
            raise GroupDeserializeError("point not on curve")
        if self._y_is_larger(y) != bool(s_bit):
            y = self.p - y
        P = (x, y)
        if self.mul(self.order, P) is not None:
            raise GroupDeserializeError("point not in the prime-order subgroup")
        return P


# --------------------------------------------------------------------------
# Scalar codec ({{scalar}}, ciphersuites): big-endian I2OSP, canonical range.
# --------------------------------------------------------------------------

def scalar_serialize(group, scalars):
    out = b""
    for s in scalars:
        assert 0 <= s < group.order
        out += I2OSP(s, group.Ns)
    return out

def scalar_deserialize(group, buffer):
    if len(buffer) % group.Ns != 0:
        raise ScalarDeserializeError("buffer length not a multiple of Ns")
    out = []
    for i in range(0, len(buffer), group.Ns):
        v = OS2IP(buffer[i:i + group.Ns])
        if v >= group.order:
            raise ScalarDeserializeError("scalar not in canonical range [0, p)")
        out.append(v)
    return out


# --------------------------------------------------------------------------
# LinearRelation ({{representation}}): coefficient-carrying image and terms.
#   image: list[(element_index, coeff)]
#   terms: list[(scalar_index, element_index, coeff)]
# --------------------------------------------------------------------------

class Equation:
    def __init__(self, image, terms):
        self.image = [tuple(t) for t in image]   # (element_index, coeff)
        self.terms = [tuple(t) for t in terms]   # (scalar_index, element_index, coeff)

class LinearRelation:
    def __init__(self, group, elements, equations):
        self.group = group
        self.elements = list(elements)           # elements[0] == generator()
        self.equations = list(equations)

def num_elements(inst):
    return len(inst.elements)

def num_equations(inst):
    return len(inst.equations)

def num_scalars(inst):
    return 1 + max(s for eq in inst.equations for (s, _, _) in eq.terms)


def sp_map(inst, scalars):
    """map(instance, scalars) of {{map-evaluation}}."""
    g = inst.group
    out = []
    for eq in inst.equations:
        acc = g.identity()
        for (si, ei, coeff) in eq.terms:
            acc = g.add(acc, g.mul((coeff * scalars[si]) % g.order,
                                   inst.elements[ei]))
        out.append(acc)
    return out

def image(inst):
    """image(instance): the left-hand side of each equation."""
    g = inst.group
    out = []
    for eq in inst.equations:
        acc = g.identity()
        for (ei, coeff) in eq.image:
            acc = g.add(acc, g.mul(coeff % g.order, inst.elements[ei]))
        out.append(acc)
    return out


# --------------------------------------------------------------------------
# Instance validation ({{instance-validation}}), checks 1-10.
# --------------------------------------------------------------------------

def validate_instance(inst):
    g = inst.group
    eqs = inst.equations
    if len(eqs) == 0:                                            # 1
        return False
    if any(len(eq.terms) == 0 or len(eq.image) == 0 for eq in eqs):  # 2
        return False
    bound = 2 ** 32                                              # 3
    if len(eqs) >= bound:
        return False
    for eq in eqs:
        if len(eq.terms) >= bound or len(eq.image) >= bound:
            return False
        if any(not (0 <= ei < bound) for (ei, _) in eq.image):
            return False
        if any(not (0 <= si < bound) or not (0 <= ei < bound)
               for (si, ei, _) in eq.terms):
            return False
    n_el = num_elements(inst)                                   # 4
    referenced = set()
    for eq in eqs:
        for (ei, _) in eq.image:
            if ei >= n_el:
                return False
            referenced.add(ei)
        for (_, ei, _) in eq.terms:
            if ei >= n_el:
                return False
            referenced.add(ei)
    if any(i not in referenced for i in range(1, n_el)):        # 5
        return False
    used_scalars = {si for eq in eqs for (si, _, _) in eq.terms}  # 6
    if any(j not in used_scalars for j in range(num_scalars(inst))):
        return False
    if inst.elements[0] != g.generator():                      # 7
        return False
    if any(P is None for P in inst.elements):                  # 8
        return False
    if any(P is None for P in image(inst)):                    # 9
        return False
    for si in range(num_scalars(inst)):                        # 10
        for eq in eqs:
            acc = g.identity()
            hit = False
            for (s, ei, coeff) in eq.terms:
                if s == si:
                    hit = True
                    acc = g.add(acc, g.mul(coeff % g.order, inst.elements[ei]))
            if hit and acc is not None:
                break
        else:
            return False
    return True


# --------------------------------------------------------------------------
# Serialization ({{serialize-linear-relations}}), with coefficients.
# --------------------------------------------------------------------------

def serialize_linear_relation(inst):
    g = inst.group
    out = LE(num_equations(inst), 4)
    for eq in inst.equations:
        out += LE(len(eq.image), 4)
        for (ei, coeff) in eq.image:
            out += LE(ei, 4) + scalar_serialize(g, [coeff % g.order])
        out += LE(len(eq.terms), 4)
        for (si, ei, coeff) in eq.terms:
            out += LE(si, 4) + LE(ei, 4) + scalar_serialize(g, [coeff % g.order])
    return out + g.serialize(inst.elements[1:num_elements(inst)])


# --------------------------------------------------------------------------
# Interactive protocol and Fiat-Shamir NARG strings ({{non-interactive}}).
# --------------------------------------------------------------------------

def prover_commitment(inst, witness, rng):
    if len(witness) != num_scalars(inst):
        raise ValueError("witness length does not match num_scalars")
    nonces = [rng.random_scalar() for _ in range(num_scalars(inst))]
    commitment = sp_map(inst, nonces)
    return commitment, (witness, nonces)

def prover_response(state, challenge):
    witness, nonces = state
    return [(nonces[i] + witness[i] * challenge) for i in range(len(nonces))]

def verifier(inst, commitment, challenge, response):
    if not validate_instance(inst):
        raise ValueError("instance validation failed")
    if (len(commitment) != num_equations(inst)
            or len(response) != num_scalars(inst)):
        raise ValueError("transcript shape mismatch")
    g = inst.group
    expected = sp_map(inst, response)
    img = image(inst)
    got = [g.add(commitment[i], g.mul(challenge % g.order, img[i]))
           for i in range(num_equations(inst))]
    return got == expected

def simulate_commitment(inst, response, challenge):
    g = inst.group
    expected = sp_map(inst, response)
    img = image(inst)
    return [g.add(expected[i], g.neg(g.mul(challenge % g.order, img[i])))
            for i in range(num_equations(inst))]


def fs_challenge(group, session_id, statement_bytes, commitment_bytes):
    """DeriveChallenge steps 2-5: DS.Init(session_id), absorb the serialized
    instance then the serialized commitment, DecodeField(Squeeze(Ns + 16))."""
    ds = DuplexSpongeShake128(session_id)
    ds.absorb(statement_bytes)
    ds.absorb(commitment_bytes)
    return LE2IP(ds.squeeze(group.Ns + 16)) % group.order

def prove_batchable(tag, inst, witness, rng):
    g = inst.group
    commitment, state = prover_commitment(inst, witness, rng)
    commitment_bytes = g.serialize(commitment)
    challenge = fs_challenge(g, derive_session_id(tag),
                             serialize_linear_relation(inst), commitment_bytes)
    response = [r % g.order for r in prover_response(state, challenge)]
    return commitment_bytes + scalar_serialize(g, response)

def prove_compact(tag, inst, witness, rng):
    g = inst.group
    commitment, state = prover_commitment(inst, witness, rng)
    commitment_bytes = g.serialize(commitment)
    challenge = fs_challenge(g, derive_session_id(tag),
                             serialize_linear_relation(inst), commitment_bytes)
    response = [r % g.order for r in prover_response(state, challenge)]
    return scalar_serialize(g, [challenge]) + scalar_serialize(g, response)

def verify_batchable(tag, inst, proof):
    """VerifyBatchable ({{narg-string-batchable}}). Raises a typed SigmaError
    on any rejection except a failed verification equation, for which it
    returns False; returns True on acceptance."""
    g = inst.group
    if not validate_instance(inst):
        raise InstanceError("instance validation failed")
    nc = g.Ne * num_equations(inst)
    nr = g.Ns * num_scalars(inst)
    if len(proof) != nc + nr:
        raise ProofLengthError("batchable NARG string has wrong length")
    commitment = g.deserialize(proof[0:nc])
    response = scalar_deserialize(g, proof[nc:nc + nr])
    challenge = fs_challenge(g, derive_session_id(tag),
                             serialize_linear_relation(inst), proof[0:nc])
    return verifier(inst, commitment, challenge, response)

def verify_compact(tag, inst, proof):
    """VerifyCompact ({{narg-string-compact}}). Same convention as above."""
    g = inst.group
    if not validate_instance(inst):
        raise InstanceError("instance validation failed")
    nr = num_scalars(inst) * g.Ns
    if len(proof) != g.Ns + nr:
        raise ProofLengthError("compact NARG string has wrong length")
    challenge = scalar_deserialize(g, proof[0:g.Ns])[0]
    response = scalar_deserialize(g, proof[g.Ns:g.Ns + nr])
    commitment = simulate_commitment(inst, response, challenge)
    if any(P is None for P in commitment):
        raise VerifyError("simulated commitment contains the identity")
    expected = fs_challenge(g, derive_session_id(tag),
                            serialize_linear_relation(inst),
                            g.serialize(commitment))
    return challenge == expected


def parse_statement(group, buf):
    """Inverse of SerializeLinearRelation, used only to transport instances in
    the vector files (each party normally builds the instance locally). Header
    errors are classified `instance`, element-decoding errors `deserialize-
    group`."""
    pos = 0
    def read_u32():
        nonlocal pos
        if pos + 4 > len(buf):
            raise InstanceError("truncated statement header")
        v = LE2IP(buf[pos:pos + 4]); pos += 4
        return v
    def read_coeff():
        nonlocal pos
        if pos + group.Ns > len(buf):
            raise InstanceError("truncated coefficient")
        v = OS2IP(buf[pos:pos + group.Ns]); pos += group.Ns
        if v >= group.order:
            raise InstanceError("non-canonical coefficient")
        return v

    n_eq = read_u32()
    if n_eq == 0:
        raise InstanceError("no equations")
    equations = []
    max_index = 0
    for _ in range(n_eq):
        n_img = read_u32()
        if n_img == 0:
            raise InstanceError("empty image")
        img = []
        for _ in range(n_img):
            ei = read_u32(); c = read_coeff(); img.append((ei, c))
            max_index = max(max_index, ei)
        n_terms = read_u32()
        if n_terms == 0:
            raise InstanceError("empty terms")
        terms = []
        for _ in range(n_terms):
            si = read_u32(); ei = read_u32(); c = read_coeff()
            terms.append((si, ei, c)); max_index = max(max_index, ei)
        equations.append(Equation(img, terms))
    n_el = 1 + max_index
    if len(buf) - pos != (n_el - 1) * group.Ne:
        raise InstanceError("statement length does not match header")
    elements = [group.generator()] + group.deserialize(buf[pos:])
    return LinearRelation(group, elements, equations)


def classified_verify(flavor, group, tag, statement, proof):
    """Verify a serialized (statement, proof); return None on acceptance or the
    TESTS.md error class on rejection."""
    try:
        inst = parse_statement(group, statement)
        ok = (verify_batchable(tag, inst, proof) if flavor == "batchable"
              else verify_compact(tag, inst, proof))
        return None if ok else "verify"
    except SigmaError as e:
        return e.cls


# --------------------------------------------------------------------------
# Batch verification of batchable NARG strings ({{batch-verification}}).
# --------------------------------------------------------------------------

BATCH_TAG = b"irtf-cfrg-sigma-protocols/batch-verify"

def batch_verify(group, session_ids, instances, narg_strings, return_debug=False):
    """Deterministic batch verification: one squeeze of 16 bytes per batched
    equation, read little-endian as `batching_randomness`, then a single random
    linear combination of every verification equation."""
    nt = len(instances)
    if nt >= 2 ** 32:
        raise SigmaError("batch too large")
    parsed = []
    challenges = []
    for i in range(nt):
        inst = instances[i]
        if not validate_instance(inst):
            raise InstanceError("instance validation failed")
        nc = group.Ne * num_equations(inst)
        nr = group.Ns * num_scalars(inst)
        if len(narg_strings[i]) != nc + nr:
            raise ProofLengthError("batchable NARG string has wrong length")
        commitment = group.deserialize(narg_strings[i][0:nc])
        response = scalar_deserialize(group, narg_strings[i][nc:nc + nr])
        challenge = fs_challenge(group, session_ids[i],
                                 serialize_linear_relation(inst),
                                 narg_strings[i][0:nc])
        parsed.append((commitment, response, challenge))
        challenges.append(challenge)

    ds = DuplexSpongeShake128(derive_session_id(BATCH_TAG))
    for i in range(nt):
        ds.absorb(session_ids[i])
        ds.absorb(serialize_linear_relation(instances[i]))
        ds.absorb(narg_strings[i])
    k_total = sum(num_equations(inst) for inst in instances)
    randomness_bytes = ds.squeeze(16 * k_total)

    coeffs = []
    k = 0
    for i in range(nt):
        row = []
        for _ in range(num_equations(instances[i])):
            row.append(LE2IP(randomness_bytes[16 * k:16 * (k + 1)]))
            k += 1
        coeffs.append(row)

    acc = group.identity()
    for i in range(nt):
        inst = instances[i]
        commitment, response, challenge = parsed[i]
        img = image(inst)
        mapped = sp_map(inst, response)
        for j in range(num_equations(inst)):
            c = coeffs[i][j]
            term = group.add(group.mul(c % group.order, commitment[j]),
                             group.mul((c * challenge) % group.order, img[j]))
            term = group.add(term, group.neg(group.mul(c % group.order, mapped[j])))
            acc = group.add(acc, term)
    ok = acc is None
    if return_debug:
        return ok, {"randomness_bytes": randomness_bytes,
                    "coefficients": coeffs, "challenges": challenges}
    return ok


# --------------------------------------------------------------------------
# Seeded PRNG for vector generation ({{seeded-prng}} of the appendix).
# --------------------------------------------------------------------------

def testdrng_tag(suite, name, flavor=None):
    """The PRNG tag of one of a vector's streams ({{seeded-prng}}): the
    instance/witness stream has no flavor component; each flavor's nonce
    stream carries its flavor marker."""
    marker = f"{FLAVOR_MARKERS[flavor]}-" if flavor else ""
    return f"TestDRNG-SIGMA-PROOFS-{marker}{suite}-{name}".encode("ascii")


class TestDRNG:
    """random_scalar() = DecodeField(Squeeze(Ns + 16), p, 1) on a SHAKE128
    duplex sponge initialized with DeriveSessionID of the stream's PRNG tag
    ({{seeded-prng}}). Test-only: applications MUST NOT use a deterministic
    RNG; prover randomness MUST be seeded from OS entropy."""
    def __init__(self, group, suite, name, flavor=None):
        self.group = group
        self.ds = DuplexSpongeShake128(
            derive_session_id(testdrng_tag(suite, name, flavor)))

    def random_scalar(self):
        return LE2IP(self.ds.squeeze(self.group.Ns + 16)) % self.group.order


def aux_generator(g, rng):
    """Auxiliary (NUMS-style) generator for the vectors: h * G for an h drawn
    from the same generation stream. Test-only -- the discrete logarithm is
    known -- but statistically independent bases, which is all the proofs need.
    """
    return g.mul(rng.random_scalar(), g.generator())


# --------------------------------------------------------------------------
# The seven relations of TESTS.md. Each builder draws instance/witness scalars
# from `rng` in the documented order and returns (instance, witness). The
# generator is always elements[0], even where no equation references it.
# --------------------------------------------------------------------------

def rel_discrete_logarithm(g, rng):
    # DL(X): X = x * G
    x = rng.random_scalar()
    X = g.mul(x, g.generator())
    inst = LinearRelation(g, [g.generator(), X],
                          [Equation([(1, 1)], [(0, 0, 1)])])
    return inst, [x]

def rel_dleq(g, rng):
    # DLEQ(H, X, Y): X = x * G, Y = x * H       elements = [G, X, H, Y]
    H = aux_generator(g, rng)
    x = rng.random_scalar()
    X = g.mul(x, g.generator())
    Y = g.mul(x, H)
    inst = LinearRelation(g, [g.generator(), X, H, Y],
                          [Equation([(1, 1)], [(0, 0, 1)]),
                           Equation([(3, 1)], [(0, 2, 1)])])
    return inst, [x]

def rel_pedersen_commitment(g, rng):
    # PEDERSEN(H, C): C = x * G + r * H          elements = [G, H, C]
    H = aux_generator(g, rng)
    x = rng.random_scalar()
    r = rng.random_scalar()
    C = g.add(g.mul(x, g.generator()), g.mul(r, H))
    inst = LinearRelation(g, [g.generator(), H, C],
                          [Equation([(2, 1)], [(0, 0, 1), (1, 1, 1)])])
    return inst, [x, r]

def rel_pedersen_commitment_dleq(g, rng):
    # PEDERSEN_DLEQ(G0, G1, G2, G3, X, Y):
    #   X = x0 * G0 + x1 * G1, Y = x0 * G2 + x1 * G3
    # elements = [G, G0, G1, X, G2, G3, Y]  (generator unused, index 0)
    gens = [aux_generator(g, rng) for _ in range(4)]
    x0 = rng.random_scalar()
    x1 = rng.random_scalar()
    X = g.add(g.mul(x0, gens[0]), g.mul(x1, gens[1]))
    Y = g.add(g.mul(x0, gens[2]), g.mul(x1, gens[3]))
    inst = LinearRelation(
        g, [g.generator(), gens[0], gens[1], X, gens[2], gens[3], Y],
        [Equation([(3, 1)], [(0, 1, 1), (1, 2, 1)]),
         Equation([(6, 1)], [(0, 4, 1), (1, 5, 1)])])
    return inst, [x0, x1]

def rel_bbs_blind_commitment_computation(g, rng):
    # BBS_BLIND(Q2, J1, J2, J3, C):
    #   C = blind * Q2 + msg_1 * J1 + msg_2 * J2 + msg_3 * J3
    # elements = [G, Q2, J1, J2, J3, C]  (generator unused, index 0)
    Q2, J1, J2, J3 = [aux_generator(g, rng) for _ in range(4)]
    msgs = [rng.random_scalar() for _ in range(3)]
    blind = rng.random_scalar()
    C = g.identity()
    for k, P in ((blind, Q2), (msgs[0], J1), (msgs[1], J2), (msgs[2], J3)):
        C = g.add(C, g.mul(k, P))
    inst = LinearRelation(
        g, [g.generator(), Q2, J1, J2, J3, C],
        [Equation([(5, 1)], [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 4, 1)])])
    return inst, [blind, msgs[0], msgs[1], msgs[2]]

def rel_elgamal_decryption(g, rng):
    # ELGAMAL_DECRYPTION(X, E0, E1, M): X = x * G, M + E1 = x * E0
    # elements = [G, X, E0, E1, M]; E1 = r * X - M is prover-derived.
    x = rng.random_scalar()
    r = rng.random_scalar()
    m = rng.random_scalar()
    G = g.generator()
    X = g.mul(x, G)
    E0 = g.mul(r, G)
    M = g.mul(m, G)
    E1 = g.add(g.mul(r, X), g.neg(M))
    inst = LinearRelation(g, [G, X, E0, E1, M],
                          [Equation([(1, 1)], [(0, 0, 1)]),
                           Equation([(4, 1), (3, 1)], [(0, 2, 1)])])
    return inst, [x]

def rel_dleq_derived_element(g, rng):
    # Same compiled shape as dleq; Y = x * H is derived by the prover from its
    # witness rather than supplied with the statement. The distinct tag makes
    # the challenge -- and thus the proof bytes -- differ from `dleq`.
    return rel_dleq(g, rng)


RELATIONS = [
    ("discrete_logarithm", rel_discrete_logarithm),
    ("dleq", rel_dleq),
    ("pedersen_commitment", rel_pedersen_commitment),
    ("pedersen_commitment_dleq", rel_pedersen_commitment_dleq),
    ("bbs_blind_commitment_computation", rel_bbs_blind_commitment_computation),
    ("elgamal_decryption", rel_elgamal_decryption),
    ("dleq_derived_element", rel_dleq_derived_element),
]

# Prose written above each valid vector in the .txt include: what the relation
# proves and where the draft (or a citable document) describes it. The {{...}}
# references resolve when kramdown-rfc processes the included file.
RELATION_DOCS = {
    "discrete_logarithm":
        "Knowledge of a discrete logarithm, `X = x * G`: the Schnorr "
        "relation given as example in {{linear-map}}.",
    "dleq":
        "Discrete-logarithm equality, `X = x * G` and `Y = x * H` "
        "({{relation-notation}}).",
    "pedersen_commitment":
        "Knowledge of the opening of a Pedersen commitment, "
        "`C = x * G + r * H` ({{relation-notation}}).",
    "pedersen_commitment_dleq":
        "Two Pedersen-form equations sharing both witness scalars, "
        "`X = x0 * G0 + x1 * G1` and `Y = x0 * G2 + x1 * G3` "
        "({{relation-notation}}).",
    "bbs_blind_commitment_computation":
        "The blind commitment computation of {{BBSBlind}}, "
        "`C = blind * Q2 + msg_1 * J1 + msg_2 * J2 + msg_3 * J3`.",
    "elgamal_decryption":
        "Correct ElGamal decryption, `X = x * G` and `M = x * E0 - E1` ({{relation-notation}}).",
    "dleq_derived_element":
        "The `ChaumPedersen` relation of {{relation-notation}} again, with "
        "`Y = x * H` derived by the prover from its witness rather than "
        "received: the compiled instance matches `dleq`, and only the tag "
        "(hence the proof bytes) differs.",
}

SUITES = [
    ("sigma-proofs_Shake128_P256", P256Group()),
    ("sigma-proofs_Shake128_BLS12381", BLSG1Group()),
]


# --------------------------------------------------------------------------
# Vector generation.
# --------------------------------------------------------------------------

FLAVOR_MARKERS = {"batchable": "DSFS", "compact": "CMPT"}

def vector_tag(name, flavor, suite):
    """The tag of a vector's proof: contains the flavor marker and the
    ciphersuite identifier verbatim, as {{sigma-proofs-tag}} requires."""
    return f"{name}-{FLAVOR_MARKERS[flavor]}-with-{suite}".encode("ascii")


def prove_relation(g, suite, name):
    """Deterministically build the instance, witness, and both NARG flavors for
    `name`. Three PRNG streams are drawn per vector: the flavor-less stream
    yields the instance and witness scalars, and each flavor's commitment
    nonces come from its own flavor-marked stream, so either proof is
    reproducible without generating the other. The proof tags also differ per
    flavor, so the two NARG strings are independent transcripts over the same
    instance and witness."""
    inst, witness = dict(RELATIONS)[name](g, TestDRNG(g, suite, name))
    assert validate_instance(inst), name
    assert sp_map(inst, witness) == image(inst), name
    batchable_tag = vector_tag(name, "batchable", suite)
    compact_tag = vector_tag(name, "compact", suite)
    batchable = prove_batchable(batchable_tag, inst, witness,
                                TestDRNG(g, suite, name, "batchable"))
    compact = prove_compact(compact_tag, inst, witness,
                            TestDRNG(g, suite, name, "compact"))
    assert len(batchable) == g.Ne * num_equations(inst) + g.Ns * num_scalars(inst)
    assert len(compact) == g.Ns * (num_scalars(inst) + 1)
    assert verify_batchable(batchable_tag, inst, batchable), name
    assert verify_compact(compact_tag, inst, compact), name
    return {"name": name, "inst": inst, "witness": witness,
            "batchable_tag": batchable_tag, "batchable": batchable,
            "compact_tag": compact_tag, "compact": compact}


def make_batchable(g, tag, inst, witness, rng):
    """Produce (narg_string, challenge, response) for an arbitrary (possibly
    invalid) instance and witness, drawing nonces from `rng`."""
    commitment, state = prover_commitment(inst, witness, rng)
    commitment_bytes = g.serialize(commitment)
    challenge = fs_challenge(g, derive_session_id(tag),
                             serialize_linear_relation(inst), commitment_bytes)
    response = [r % g.order for r in prover_response(state, challenge)]
    return commitment_bytes + scalar_serialize(g, response), challenge, response


def happy_json(g, rec, suite):
    """The internal record: both flavors together, as the self-tests want
    them. `emit_happy` splits it into the one-vector-per-flavor form that
    is written out."""
    return {
        "Relation": rec["name"],
        "Ciphersuite": suite,
        "Instance": serialize_linear_relation(rec["inst"]).hex(),
        "Witness": scalar_serialize(g, rec["witness"]).hex(),
        "BatchableTag": rec["batchable_tag"].decode(),
        "BatchableSessionId": derive_session_id(rec["batchable_tag"]).hex(),
        "BatchableProof": rec["batchable"].hex(),
        "CompactTag": rec["compact_tag"].decode(),
        "CompactSessionId": derive_session_id(rec["compact_tag"]).hex(),
        "CompactProof": rec["compact"].hex(),
    }


# The suite component of a vector `Id`.
SUITE_SHORT = {
    "sigma-proofs_Shake128_P256": "p256",
    "sigma-proofs_Shake128_BLS12381": "bls12381",
}


def happy_id(suite, relation, flavor):
    return f"sigma-protocols/{SUITE_SHORT[suite]}/{relation}/{flavor}"


def emit_happy(vectors, suite):
    """One vector per (relation, flavor). Carrying both flavors in a single
    record fused two independent test cases, and forced the flavor into the
    key names; naming it as a value lets a reject vector target one flavor
    on its own, and lets the valid and adversarial files share a schema."""
    out = []
    for v in vectors:
        for flavor, pre in (("batchable", "Batchable"), ("compact", "Compact")):
            out.append({
                "Id": happy_id(suite, v["Relation"], flavor),
                "Function": "SigmaProof",
                "Ciphersuite": suite,
                "Relation": v["Relation"],
                "Flavor": flavor,
                "Tag": v[pre + "Tag"],
                "SessionId": v[pre + "SessionId"],
                "Instance": v["Instance"],
                "Witness": v["Witness"],
                "NargString": v[pre + "Proof"],
                "Expected": "accept",
            })
    return out


# ---- deterministic curve-point searches for set A -------------------------

def _rhs(g, x):
    return (x * x * x + g.a * x + g.b) % g.p

def smallest_x_on_curve(g, headroom):
    limit = 256 ** headroom - g.p
    x = 1
    while True:
        assert x < limit
        if g.sqrt(_rhs(g, x)) is not None:
            return x
        x += 1

def smallest_x_off_curve(g):
    x = 1
    while True:
        if _rhs(g, x) != 0 and g.sqrt(_rhs(g, x)) is None:
            return x
        x += 1

def smallest_point_not_in_subgroup(g):
    x = 0
    while True:
        y = g.sqrt(_rhs(g, x))
        if y is not None:
            P = (x, min(y, g.p - y))
            if g.mul(g.order, P) is not None:
                return P
        x += 1


# ---- adversarial sets A-F, H ----------------------------------------------

def gen_invalid(suite, g, happy):
    """Reject vectors (with the accept members of the F pairs). Base vector:
    relation 0 (discrete_logarithm), except where a set builds its own
    instance."""
    rec0 = happy[0]
    inst0 = rec0["inst"]
    btag0, ctag0 = rec0["batchable_tag"], rec0["compact_tag"]
    batchable0, compact0 = rec0["batchable"], rec0["compact"]
    statement0 = serialize_linear_relation(inst0)
    ne, ns = g.Ne, g.Ns
    entries = []

    def entry(id_, flavor, proof, err, comment,
              tag=None, statement=statement0, expected="reject",
              acceptable=None):
        if tag is None:
            tag = btag0 if flavor == "batchable" else ctag0
        # Every adversarial vector is a mutation of one valid vector, and
        # `BaseId` names it. That makes the pairing checkable rather than
        # conventional: a harness can assert that each reject has an accept
        # baseline, so a verifier that rejects everything fails the suite
        # instead of passing most of it. The accept entries are baselines
        # themselves, and carry no BaseId.
        base = happy_id(suite, rec0["name"], flavor)
        entries.append({
            "Id": f"{base}/{id_}",
            **({} if expected == "accept" else {"BaseId": base}),
            "Function": "SigmaProof",
            "Ciphersuite": suite, "Flavor": flavor,
            "Tag": tag.decode(), "Instance": statement.hex(),
            "NargString": proof.hex(), "Expected": expected, "Comment": comment,
            # Acceptable rejection classes; more than one when the rejection
            # step depends on the implementation's check order. Self-test
            # only; stripped from the emitted vectors in main().
            "_errors": acceptable or ([err] if err else []),
        })

    # A. Point deserialization (batchable; commitment slice) ----------------
    if g.name == "P256":
        p = bytearray(batchable0); p[0] = 0x04
        entry("A1", "batchable", bytes(p), "deserialize-group",
              "Deserialization fails on the SEC1 uncompressed prefix 0x04.")
        p = bytearray(batchable0); p[0] = 0x06
        entry("A2", "batchable", bytes(p), "deserialize-group",
              "Deserialization fails on the SEC1 hybrid prefix 0x06.")
        p = bytearray(batchable0); p[0] = 0x07
        entry("A2b", "batchable", bytes(p), "deserialize-group",
              "Deserialization fails on the SEC1 hybrid prefix 0x07.")
        x = smallest_x_on_curve(g, 32)
        slice_ = bytes([0x02]) + I2OSP(x + g.p, 32)
        entry("A3", "batchable", slice_ + batchable0[ne:], "deserialize-group",
              f"Deserialization fails if the x-coordinate is lifted by the "
              f"field characteristic (x = {x}, encoded as x + p): the "
              f"coordinate is non-canonical.")
        entry("A4", "batchable", bytes(ne) + batchable0[ne:],
              "deserialize-group",
              "Deserialization fails on 0x00 padded to Ne bytes.")
        x = smallest_x_off_curve(g)
        slice_ = bytes([0x02]) + I2OSP(x, 32)
        entry("A6", "batchable", slice_ + batchable0[ne:], "deserialize-group",
              f"Deserialization fails on x = {x}, which has no square root "
              f"for y.")
    else:
        p = bytearray(batchable0); p[0] &= 0x7F
        entry("A1", "batchable", bytes(p), "deserialize-group",
              "Deserialization fails if the compression bit is cleared.")
        x = smallest_x_on_curve(g, 48)
        body = bytearray(I2OSP(x + g.p, 48)); body[0] |= 0x80
        entry("A3", "batchable", bytes(body) + batchable0[ne:],
              "deserialize-group",
              f"Deserialization fails if the x-coordinate is lifted by the "
              f"field characteristic (x = {x}, encoded as x + p).")
        infinity = bytes([0xC0]) + bytes(47)
        entry("A4", "batchable", infinity + batchable0[ne:],
              "deserialize-group",
              "Deserialization fails on the canonical compressed encoding of "
              "the point at infinity: the identity is invalid in prover "
              "messages.")
        P = smallest_point_not_in_subgroup(g)
        entry("A5", "batchable", g.serialize_element(P) + batchable0[ne:],
              "deserialize-group",
              f"Deserialization fails on a point (x = {P[0]}) on the curve "
              "but outside the prime-order subgroup G1.")
        x = smallest_x_off_curve(g)
        body = bytearray(I2OSP(x, 48)); body[0] |= 0x80
        entry("A6", "batchable", bytes(body) + batchable0[ne:],
              "deserialize-group",
              f"Deserialization fails on x = {x}, which is not on the curve "
              "(x^3 + 4 is a non-residue).")

    # B. Scalar deserialization ---------------------------------------------
    s0 = OS2IP(batchable0[ne:ne + ns])
    if s0 + g.order < 256 ** ns:
        b1_slice = I2OSP(s0 + g.order, ns)
        b1_comment = ("Deserialization fails if `response[0]` is re-encoded "
                      "as s + order: same value mod p, non-canonical bytes. "
                      "Reducing instead of rejecting yields malleability.")
    else:
        b1_slice = I2OSP(g.order + 1, ns)
        b1_comment = ("Deserialization fails if `response[0]` is set to "
                      "order + 1.")
    entry("B1", "batchable", batchable0[:ne] + b1_slice + batchable0[ne + ns:],
          "deserialize-scalar", b1_comment)

    c0 = OS2IP(compact0[0:ns])
    if c0 + g.order < 256 ** ns:
        b2_slice = I2OSP(c0 + g.order, ns)
        b2_comment = ("Deserialization fails if `challenge` is re-encoded as "
                      "c + order (non-canonical bytes).")
    else:
        b2_slice = I2OSP(g.order + 1, ns)
        b2_comment = ("Deserialization fails if `challenge` is set to "
                      "order + 1.")
    entry("B2", "compact", b2_slice + compact0[ns:], "deserialize-scalar",
          b2_comment)

    # C. Proof framing ------------------------------------------------------
    for flavor, base in (("batchable", batchable0), ("compact", compact0)):
        entry("C1", flavor, base + b"\x00", "length",
              "Verification fails if one trailing 0x00 byte is appended to a "
              "valid proof.")
        entry("C2", flavor, base[:-1], "length",
              "Verification fails if a valid proof is truncated by one byte.")

    # D. Simulator edge case (compact only) ---------------------------------
    zero = bytes(ns * (1 + num_scalars(inst0)))
    entry("D1", "compact", zero, "verify",
          "Verification fails on the all-zero compact proof: challenge and "
          "response are zero.")

    # E. Instance validation ------------------------------------------------
    # E1: scalar index 1 appears in no equation (check 6).
    rng = TestDRNG(g, suite, "instance_unconstrained_scalar")
    H = aux_generator(g, rng)
    x0, x1, x2 = (rng.random_scalar() for _ in range(3))
    X = g.add(g.mul(x0, g.generator()), g.mul(x2, H))
    inst_e1 = LinearRelation(g, [g.generator(), H, X],
                             [Equation([(2, 1)], [(0, 0, 1), (2, 1, 1)])])
    assert not validate_instance(inst_e1)
    st_e1 = serialize_linear_relation(inst_e1)
    tag_e1 = vector_tag("instance_unconstrained_scalar", "batchable", suite)
    b_e1, _, resp_e1 = make_batchable(
        g, tag_e1, inst_e1, [x0, x1, x2],
        TestDRNG(g, suite, "instance_unconstrained_scalar", "batchable"))
    entry("E1", "batchable", b_e1, "instance",
          "Instance validation fails if scalar index 1 appears in no "
          "equation (check 6); the proof satisfies the verification "
          "equations, so rejection must come from instance validation.",
          tag=tag_e1, statement=st_e1)
    off = g.Ne * 1 + ns          # response scalar index 1
    mut = bytearray(b_e1)
    mut[off:off + ns] = I2OSP((resp_e1[1] + 1) % g.order, ns)
    entry("E1b", "batchable", bytes(mut), "instance",
          "Instance validation fails on the same instance, here with the "
          "unconstrained `response[1]` perturbed.",
          tag=tag_e1, statement=st_e1)

    # E2: an equation whose image terms sum to the identity (check 9).
    rng = TestDRNG(g, suite, "instance_trivial_equation")
    x = rng.random_scalar()
    X = g.mul(x, g.generator())
    inst_e2 = LinearRelation(g, [g.generator(), X, g.neg(X)],
                             [Equation([(1, 1), (2, 1)], [(0, 0, 1)])])
    assert not validate_instance(inst_e2)
    tag_e2 = vector_tag("instance_trivial_equation", "batchable", suite)
    b_e2, _, _ = make_batchable(
        g, tag_e2, inst_e2, [0],
        TestDRNG(g, suite, "instance_trivial_equation", "batchable"))
    entry("E2", "batchable", b_e2, "instance",
          "Instance validation fails if the image terms X + (-X) sum to the "
          "identity (check 9).",
          tag=tag_e2, statement=serialize_linear_relation(inst_e2))

    # E3: instance containing the identity as a statement element (check 8).
    rng = TestDRNG(g, suite, "instance_identity_element")
    x = rng.random_scalar(); t = rng.random_scalar()
    X = g.mul(x, g.generator())
    inst_e3 = LinearRelation(g, [g.generator(), g.identity(), X],
                             [Equation([(2, 1)], [(0, 0, 1), (1, 1, 1)])])
    assert not validate_instance(inst_e3)
    tag_e3 = vector_tag("instance_identity_element", "batchable", suite)
    # Group.serialize is undefined on the identity, so craft the statement
    # bytes: reuse a valid header (with X in place of the identity), then
    # overwrite the first serialized element with an identity encoding.
    header = serialize_linear_relation(
        LinearRelation(g, [g.generator(), X, X],
                       [Equation([(2, 1)], [(0, 0, 1), (1, 1, 1)])]))[:-2 * ne]
    if g.name == "P256":
        identity_bytes = bytes(ne)
        id_comment = ("stand-in bytes (P-256 has no identity encoding)")
    else:
        identity_bytes = bytes([0xC0]) + bytes(47)
        id_comment = "the canonical compressed encoding of infinity"
    st_e3 = header + identity_bytes + g.serialize_element(X)
    commitment, state = prover_commitment(
        inst_e3, [x, t],
        TestDRNG(g, suite, "instance_identity_element", "batchable"))
    ch_e3 = fs_challenge(g, derive_session_id(tag_e3), st_e3,
                         g.serialize(commitment))
    resp_e3 = [r % g.order for r in prover_response(state, ch_e3)]
    b_e3 = g.serialize(commitment) + scalar_serialize(g, resp_e3)
    entry("E3", "batchable", b_e3, "instance",
          f"Instance validation fails if a statement element is the identity "
          f"(check 8), here at index 1, encoded as {id_comment}; parsers may "
          f"instead reject at group deserialization.",
          tag=tag_e3, statement=st_e3,
          acceptable=["instance", "deserialize-group"])

    # E4: header references an element index with no element supplied.
    st_e4 = (LE(1, 4) + LE(1, 4) + LE(1, 4) + scalar_serialize(g, [1])
             + LE(1, 4) + LE(0, 4) + LE(2, 4) + scalar_serialize(g, [1])
             + statement0[len(statement0) - ne:])   # only one element follows
    entry("E4", "batchable", batchable0, "instance",
          "Instance validation fails if a term references element index 2 "
          "while a single element follows; parsers may instead reject on "
          "length.",
          tag=vector_tag("instance_index_out_of_bounds", "batchable", suite),
          statement=st_e4, acceptable=["instance", "length"])

    # F. Transcript and flavor binding (accept/reject pairs) ----------------
    for flavor, base in (("batchable", batchable0), ("compact", compact0)):
        entry("F1", flavor, base, None,
              "A valid NARG string verifies under the tag it was produced "
              "for.",
              expected="accept")
        entry("F1b", flavor, base, "verify",
              "Verification fails under a different tag.",
              tag=vector_tag("discrete_logarithm/wrong-session", flavor,
                             suite))

    rec1 = happy[1]
    inst1 = rec1["inst"]
    st1 = serialize_linear_relation(inst1)
    inst1_swapped = LinearRelation(g, inst1.elements,
                                   [inst1.equations[1], inst1.equations[0]])
    assert validate_instance(inst1_swapped)
    st1_swapped = serialize_linear_relation(inst1_swapped)
    for flavor, base, tag1 in (
            ("batchable", rec1["batchable"], rec1["batchable_tag"]),
            ("compact", rec1["compact"], rec1["compact_tag"])):
        entry("F2", flavor, base, None,
              "A valid NARG string verifies against the statement it was "
              "produced for.",
              tag=tag1, statement=st1, expected="accept")
        entry("F2b", flavor, base, "verify",
              "Verification fails if the statement's two equations are "
              "swapped.",
              tag=tag1, statement=st1_swapped)

    # F3: statement-element binding. One statement element is changed and the
    # proof verified against the modified statement (CVE-2022-29566 class).
    st_f3 = statement0[:-ne] + g.serialize_element(g.mul(999, g.generator()))
    assert validate_instance(parse_statement(g, st_f3))
    for flavor, base in (("batchable", batchable0), ("compact", compact0)):
        entry("F3", flavor, base, "verify",
              "Verification fails if a statement element is changed after "
              "proving.",
              statement=st_f3)

    # F4/F4b: a transcript re-encoded in the other flavor. The flavor marker
    # is a mandatory tag component, so the re-derived challenge differs.
    nc0 = g.Ne * num_equations(inst0)
    ch0 = fs_challenge(g, derive_session_id(btag0), statement0,
                       batchable0[:nc0])
    entry("F4", "compact", scalar_serialize(g, [ch0]) + batchable0[nc0:],
          "verify",
          "Verification fails if the batchable proof's transcript is "
          "re-encoded as a compact NARG string.")
    ch = scalar_deserialize(g, compact0[:ns])[0]
    resp = scalar_deserialize(g, compact0[ns:])
    comm = simulate_commitment(inst0, resp, ch)
    entry("F4b", "batchable", g.serialize(comm) + compact0[ns:],
          "verify",
          "Verification fails if the compact proof's transcript is "
          "re-encoded as a batchable NARG string: the challenge derived "
          "under the batchable tag differs.")

    # H. Well-formed proof tampering (deserialization succeeds) -------------
    s = OS2IP(batchable0[ne:ne + ns])
    h1 = batchable0[:ne] + I2OSP((s + 1) % g.order, ns) + batchable0[ne + ns:]
    entry("H1", "batchable", h1, "verify",
          "Verification fails if `response[0]` is increased by 1.")
    alt = g.generator()
    if g.serialize([alt]) == batchable0[:ne]:
        alt = g.mul(2, g.generator())
    h2 = g.serialize([alt]) + batchable0[ne:]
    entry("H2", "batchable", h2, "verify",
          "Verification fails if `commitment[0]` is replaced by a different "
          "valid group element.")
    c = OS2IP(compact0[0:ns])
    h3 = I2OSP((c + 1) % g.order, ns) + compact0[ns:]
    entry("H3", "compact", h3, "verify",
          "Verification fails if `challenge` is replaced by a different "
          "scalar.")

    return entries


# --------------------------------------------------------------------------
# Output writers.
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Vector rendering. The grammar is the one specified in the Test Vectors
# appendix of draft-irtf-cfrg-fiat-shamir, so that one harness reads the
# vectors of both drafts:
#
#   1. A value is written inline after `Key = ` when it fits the document
#      width; otherwise it is written on the following lines, indented by
#      two spaces, and those lines are joined with no separator.
#   2. A sequence-valued field always uses the indented block form, one
#      item per line, each introduced by `- `.
#
# No key repeats within a vector, so each fenced block is one JSON object.
# --------------------------------------------------------------------------

WIDTH = 72
INDENT = "  "

# Byte strings wrap at a whole 32 bytes per line, so a reader counts bytes
# by counting lines. Byte strings longer than HEX_INLINE_MAX_BYTES always
# take the block form, so that whether a value wraps does not depend on how
# long its key happens to be.
HEX_BYTES_PER_LINE = 32
HEX_INLINE_MAX_BYTES = 16


def _is_hex(s):
    return (
        isinstance(s, str)
        and len(s) > 0
        and len(s) % 2 == 0
        and all(c in "0123456789abcdef" for c in s)
    )


def _emit(fh, key, payload):
    lhs = f"{key} = "
    long_bytes = _is_hex(payload) and len(payload) > 2 * HEX_INLINE_MAX_BYTES
    if not long_bytes and len(lhs) + len(payload) <= WIDTH:
        fh.write(lhs + payload + "\n")
        return
    fh.write(f"{key} =\n")
    step = 2 * HEX_BYTES_PER_LINE if _is_hex(payload) else WIDTH - len(INDENT)
    for i in range(0, len(payload), step):
        fh.write(INDENT + payload[i:i + step] + "\n")


def _emit_seq(fh, key, items):
    fh.write(f"{key} =\n")
    room = WIDTH - len(INDENT) - 2
    for item in items:
        if len(item) <= room:
            fh.write(f"{INDENT}- {item}\n")
            continue
        step = 2 * HEX_BYTES_PER_LINE if _is_hex(item) else room
        fh.write(f"{INDENT}- {item[:step]}\n")
        for i in range(step, len(item), step):
            fh.write(INDENT + INDENT + item[i:i + step] + "\n")


def write_comment(fh, text):
    """Comments are prose for the reader, not data for the harness: they go
    before the fence, word-wrapped, so xml2rfc can reflow them instead of
    hard-breaking mid-word like the hex fields."""
    print(textwrap.fill(text, width=WIDTH, break_on_hyphens=False),
          file=fh, end="\n\n")


def write_txt(path, records, comment_for):
    """One vector per fenced block, each preceded by its prose. `Id` leads,
    so a vector can be referred to before it is parsed."""
    with open(path, "w") as fh:
        for r in records:
            write_comment(fh, comment_for(r))
            print("~~~", file=fh)
            _emit(fh, "Id", r["Id"])
            for key, value in r.items():
                if key in ("Id", "Comment"):
                    continue
                if isinstance(value, list):
                    _emit_seq(fh, key, [str(x) for x in value])
                else:
                    _emit(fh, key, str(value))
            print("~~~", file=fh, end="\n\n")


# --------------------------------------------------------------------------
# Self-test: every reject vector rejects with an acceptable class; accept
# vectors accept.
# --------------------------------------------------------------------------

def self_test(g, happy, invalid):
    for v in happy:
        assert classified_verify("compact", g, v["CompactTag"].encode(),
            bytes.fromhex(v["Instance"]),
            bytes.fromhex(v["CompactProof"])) is None, v
        assert classified_verify("batchable", g, v["BatchableTag"].encode(),
            bytes.fromhex(v["Instance"]),
            bytes.fromhex(v["BatchableProof"])) is None, v
    for e in invalid:
        got = classified_verify(e["Flavor"], g, e["Tag"].encode(),
            bytes.fromhex(e["Instance"]), bytes.fromhex(e["NargString"]))
        if e["Expected"] == "accept":
            assert got is None, (e["Id"], got)
        else:
            assert got in e["_errors"], (e["Id"], got, e["_errors"])
    # The appendix claim on batch verification: any subset of the valid
    # batchable proofs verifies as a batch, and a batch containing an invalid
    # batchable proof is rejected -- whether by the random linear combination
    # or by a deserialization/validation error.
    sids = [derive_session_id(v["BatchableTag"].encode()) for v in happy]
    insts = [parse_statement(g, bytes.fromhex(v["Instance"])) for v in happy]
    nargs = [bytes.fromhex(v["BatchableProof"]) for v in happy]
    n = len(happy)
    subsets = ([[]] + [[i] for i in range(n)]
               + [[i, j] for i in range(n) for j in range(i + 1, n)]
               + [list(range(n))])
    for idx in subsets:
        assert batch_verify(g, [sids[i] for i in idx],
                            [insts[i] for i in idx],
                            [nargs[i] for i in idx]), idx
    for e in invalid:
        if e["Flavor"] != "batchable" or e["Expected"] != "reject":
            continue
        try:
            rejected = not batch_verify(
                g, sids[:1] + [derive_session_id(e["Tag"].encode())],
                insts[:1] + [parse_statement(g, bytes.fromhex(e["Instance"]))],
                nargs[:1] + [bytes.fromhex(e["NargString"])])
        except SigmaError:
            rejected = True
        assert rejected, e["Id"]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = os.path.join(here, "vectors")
    os.makedirs(outdir, exist_ok=True)
    for suite, g in SUITES:
        happy = [prove_relation(g, suite, name) for name, _ in RELATIONS]
        happy_vectors = [happy_json(g, r, suite) for r in happy]
        invalid = gen_invalid(suite, g, happy)
        self_test(g, happy_vectors, invalid)
        invalid_out = [{k: v for k, v in e.items() if not k.startswith("_")}
                       for e in invalid]

        happy_out = emit_happy(happy_vectors, suite)

        # Every reject names a baseline that exists and is an accept. This
        # is the invariant that stops a reject-everything verifier passing.
        ids = {r["Id"] for r in happy_out}
        for e in invalid_out:
            if e["Expected"] == "reject":
                assert e["BaseId"] in ids, e["Id"]

        short = suite.replace("sigma-proofs_", "")
        def dump(stem, obj):
            path = os.path.join(outdir, stem + ".json")
            with open(path, "w") as f:
                json.dump(obj, f, indent=2)
                f.write("\n")
        dump(suite, happy_out)
        dump(f"sigma-proofs-invalid_{short}", invalid_out)
        write_txt(os.path.join(outdir, suite + ".txt"), happy_out,
                  lambda r: RELATION_DOCS[r["Relation"]])
        write_txt(os.path.join(outdir, f"sigma-proofs-invalid_{short}.txt"),
                  invalid_out, lambda e: e["Comment"])

        rejects = sum(1 for e in invalid if e["Expected"] == "reject")
        accepts = sum(1 for e in invalid if e["Expected"] == "accept")
        print(f"{suite}: {len(happy_vectors)} happy, "
              f"{rejects} reject + {accepts} accept adversarial. "
              f"self-tests pass.")


# --------------------------------------------------------------------------
# Import-time self-checks against values printed in the draft body.
# --------------------------------------------------------------------------

_P256 = SUITES[0][1]
_BLS = SUITES[1][1]
assert _P256.order == 115792089210356248762697446949407573529996955224135760342422259061068512044369
assert _BLS.order == 52435875175126190479447740508185965837690552500527637822603658699938581184513
assert _P256.mul(_P256.order, _P256.gen) is None
assert _BLS.mul(_BLS.order, _BLS.gen) is None

# The ChaumPedersen serialization example of {{serialize-linear-relations}},
# WITH the per-term coefficients (all 1). Elements [G, H, X, Y].
_one = I2OSP(1, 32)
_cp = LinearRelation(_P256, [_P256.gen] * 4,
                     [Equation([(2, 1)], [(0, 0, 1)]),
                      Equation([(3, 1)], [(0, 1, 1)])])
_hdr = serialize_linear_relation(_cp)[:len(serialize_linear_relation(_cp)) - 3 * _P256.Ne]
_expected = (LE(2, 4)
             + LE(1, 4) + LE(2, 4) + _one
             + LE(1, 4) + LE(0, 4) + LE(0, 4) + _one
             + LE(1, 4) + LE(3, 4) + _one
             + LE(1, 4) + LE(0, 4) + LE(1, 4) + _one)
assert _hdr == _expected, _hdr.hex()
del _cp, _hdr, _expected, _one


if __name__ == "__main__":
    main()
