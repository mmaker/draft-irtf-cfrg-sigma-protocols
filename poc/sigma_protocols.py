"""Sigma protocols for linear relations, draft-irtf-cfrg-sigma-protocols.

The linear-relation representation ({{representation}}) with its
coefficient-carrying sparse serialization ({{serialize-linear-relations}}),
instance validation ({{instance-validation}}, checks 1-10), the interactive
Sigma Protocol ({{sigma-protocol-group}}), the Fiat-Shamir challenge of
{{challenge-derivation}} (DeriveSessionID -> DS.Init -> absorb
SerializeLinearRelation -> absorb commitment -> DecodeField(Squeeze(Ns +
16))), the batchable and compact NARG strings ({{non-interactive}}), and
batch verification ({{batch-verification}}). The generator is the implicit
`elements[0]` and is never serialized.

An instance is a `LinearRelation`: the group, the statement elements
(`elements[0]` is the group generator), and a list of `Equation`s, each a
sparse row of `(element_index, coeff)` image entries and
`(scalar_index, element_index, coeff)` terms.

Verification raises on malformed input -- `groups.DeserializeError` for a
non-canonical element or scalar, `InstanceError` and `ProofLengthError`
(both `SigmaError`s) for the rest -- and returns False when a well-formed
proof fails the verification equation. Where the draft leaves the
rejection step open to check order, any of them is conformant.

Standard library only; not constant-time; not intended for production.
Prover randomness MUST come from a cryptographically secure RNG; the
`rng` argument (an object with `random_scalar()`) exists so the test
vectors can pin it.
"""

from fiat_shamir import EXTRA, DuplexSponge, decode_uint, derive_session_id
from groups import DeserializeError


class SigmaError(Exception):
    """The verifier rejects before reaching the verification equation."""


class InstanceError(SigmaError):
    """The instance (or its serialization) fails validation."""


class ProofLengthError(SigmaError):
    """The NARG string has the wrong length for its instance."""


class VerifyError(SigmaError):
    """A well-formed NARG string is rejected during verification."""


def LE(n, w):
    """Fixed-width little-endian integer, for the serialization headers."""
    if not 0 <= n < 256 ** w:
        raise ValueError("integer out of range for the given width")
    return n.to_bytes(w, "little")


# --- Linear relations ({{representation}}) ---------------------------------

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


def linear_map(inst, scalars):
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


# --- Instance validation ({{instance-validation}}), checks 1-10 ------------

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
    if inst.elements[0] != g.generator():                       # 7
        return False
    if any(P is None for P in inst.elements):                   # 8
        return False
    if any(P is None for P in image(inst)):                     # 9
        return False
    for si in range(num_scalars(inst)):                         # 10
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


# --- Serialization ({{serialize-linear-relations}}) ------------------------

def serialize_linear_relation(inst):
    g = inst.group
    out = LE(num_equations(inst), 4)
    for eq in inst.equations:
        out += LE(len(eq.image), 4)
        for (ei, coeff) in eq.image:
            out += LE(ei, 4) + g.scalar_serialize([coeff % g.order])
        out += LE(len(eq.terms), 4)
        for (si, ei, coeff) in eq.terms:
            out += LE(si, 4) + LE(ei, 4) + g.scalar_serialize([coeff % g.order])
    return out + g.serialize(inst.elements[1:num_elements(inst)])


def parse_statement(group, buf):
    """Inverse of SerializeLinearRelation, used only to transport instances
    in the vector files (each party normally builds the instance locally).
    Header errors are `InstanceError`, element-decoding errors
    `groups.DeserializeError`."""
    pos = 0

    def read_u32():
        nonlocal pos
        if pos + 4 > len(buf):
            raise InstanceError("truncated statement header")
        v = int.from_bytes(buf[pos:pos + 4], "little")
        pos += 4
        return v

    def read_coeff():
        nonlocal pos
        if pos + group.Ns > len(buf):
            raise InstanceError("truncated coefficient")
        try:
            (v,) = group.scalar_deserialize(buf[pos:pos + group.Ns])
        except DeserializeError:
            raise InstanceError("non-canonical coefficient")
        pos += group.Ns
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
            ei = read_u32()
            c = read_coeff()
            img.append((ei, c))
            max_index = max(max_index, ei)
        n_terms = read_u32()
        if n_terms == 0:
            raise InstanceError("empty terms")
        terms = []
        for _ in range(n_terms):
            si = read_u32()
            ei = read_u32()
            c = read_coeff()
            terms.append((si, ei, c))
            max_index = max(max_index, ei)
        equations.append(Equation(img, terms))
    n_el = 1 + max_index
    if len(buf) - pos != (n_el - 1) * group.Ne:
        raise InstanceError("statement length does not match header")
    elements = [group.generator()] + group.deserialize(buf[pos:])
    return LinearRelation(group, elements, equations)


# --- The interactive Sigma Protocol ({{sigma-protocol-group}}) -------------

def prover_commitment(inst, witness, rng):
    if len(witness) != num_scalars(inst):
        raise ValueError("witness length does not match num_scalars")
    nonces = [rng.random_scalar() for _ in range(num_scalars(inst))]
    commitment = linear_map(inst, nonces)
    return commitment, (inst, witness, nonces)


def prover_response(state, challenge):
    inst, witness, nonces = state
    if len(witness) != len(nonces):
        raise ValueError("witness and nonces lengths mismatch")
    order = inst.group.order
    return [(nonces[i] + witness[i] * challenge) % order
            for i in range(len(nonces))]


def verifier(inst, commitment, challenge, response):
    if not validate_instance(inst):
        raise InstanceError("instance validation failed")
    if (len(commitment) != num_equations(inst)
            or len(response) != num_scalars(inst)):
        raise ProofLengthError("transcript shape mismatch")
    g = inst.group
    expected = linear_map(inst, response)
    img = image(inst)
    got = [g.add(commitment[i], g.mul(challenge % g.order, img[i]))
           for i in range(num_equations(inst))]
    return got == expected


def simulate_commitment(inst, response, challenge):
    """The simulator's commitment, map(instance, response) - challenge *
    image(instance): what the compact verifier recomputes."""
    g = inst.group
    expected = linear_map(inst, response)
    img = image(inst)
    return [g.add(expected[i], g.neg(g.mul(challenge % g.order, img[i])))
            for i in range(num_equations(inst))]


# --- Fiat-Shamir NARG strings ({{non-interactive}}) ------------------------

def derive_challenge(group, session_id, statement_bytes, commitment_bytes):
    """DeriveChallenge steps 2-5 ({{challenge-derivation}}): DS.Init with the
    session id, absorb the serialized instance then the serialized
    commitment, DecodeField(Squeeze(Ns + 16), p, 1)."""
    ds = DuplexSponge(session_id)
    ds.absorb(statement_bytes)
    ds.absorb(commitment_bytes)
    return decode_uint(ds.squeeze(group.Ns + EXTRA), group.order)


def prove_batchable(tag, inst, witness, rng):
    g = inst.group
    if not validate_instance(inst):
        raise InstanceError("instance validation failed")
    commitment, state = prover_commitment(inst, witness, rng)
    commitment_bytes = g.serialize(commitment)
    challenge = derive_challenge(g, derive_session_id(tag),
                                 serialize_linear_relation(inst),
                                 commitment_bytes)
    response = prover_response(state, challenge)
    return commitment_bytes + g.scalar_serialize(response)


def prove_compact(tag, inst, witness, rng):
    g = inst.group
    if not validate_instance(inst):
        raise InstanceError("instance validation failed")
    commitment, state = prover_commitment(inst, witness, rng)
    commitment_bytes = g.serialize(commitment)
    challenge = derive_challenge(g, derive_session_id(tag),
                                 serialize_linear_relation(inst),
                                 commitment_bytes)
    response = prover_response(state, challenge)
    return g.scalar_serialize([challenge]) + g.scalar_serialize(response)


def verify_batchable(tag, inst, proof):
    """VerifyBatchable ({{narg-string-batchable}}), checks 1-3. Raises a
    typed error on any rejection except a failed verification equation,
    for which it returns False; returns True on acceptance."""
    g = inst.group
    nc = g.Ne * num_equations(inst)
    nr = g.Ns * num_scalars(inst)
    if len(proof) != nc + nr:                                    # 1
        raise ProofLengthError("batchable NARG string has wrong length")
    commitment = g.deserialize(proof[0:nc])                      # 2
    response = g.scalar_deserialize(proof[nc:nc + nr])
    challenge = derive_challenge(g, derive_session_id(tag),
                                 serialize_linear_relation(inst), proof[0:nc])
    return verifier(inst, commitment, challenge, response)       # 3


def verify_compact(tag, inst, proof):
    """VerifyCompact ({{narg-string-compact}}). Same convention as above."""
    g = inst.group
    if not validate_instance(inst):
        raise InstanceError("instance validation failed")
    nr = num_scalars(inst) * g.Ns
    if len(proof) != g.Ns + nr:
        raise ProofLengthError("compact NARG string has wrong length")
    challenge = g.scalar_deserialize(proof[0:g.Ns])[0]
    response = g.scalar_deserialize(proof[g.Ns:g.Ns + nr])
    commitment = simulate_commitment(inst, response, challenge)
    if any(P is None for P in commitment):
        raise VerifyError("simulated commitment contains the identity")
    expected = derive_challenge(g, derive_session_id(tag),
                                serialize_linear_relation(inst),
                                g.serialize(commitment))
    return challenge == expected


# --- Batch verification ({{batch-verification}}) ---------------------------

BATCH_TAG = b"irtf-cfrg-sigma-protocols/batch-verify"


def batch_verify(group, session_ids, instances, narg_strings):
    """Deterministic batch verification of batchable NARG strings: absorb
    every (session id, statement, NARG string) in the batch, squeeze 16
    bytes of `batching_randomness` per batched equation, then check a
    single random linear combination of every verification equation."""
    nt = len(instances)
    if not len(session_ids) == nt == len(narg_strings):
        raise SigmaError("batch input lists must have equal length")
    if nt >= 2 ** 32:
        raise SigmaError("batch too large")
    parsed = []
    for i in range(nt):
        inst = instances[i]
        if not validate_instance(inst):
            raise InstanceError("instance validation failed")
        nc = group.Ne * num_equations(inst)
        nr = group.Ns * num_scalars(inst)
        if len(narg_strings[i]) != nc + nr:
            raise ProofLengthError("batchable NARG string has wrong length")
        commitment = group.deserialize(narg_strings[i][0:nc])
        response = group.scalar_deserialize(narg_strings[i][nc:nc + nr])
        challenge = derive_challenge(group, session_ids[i],
                                     serialize_linear_relation(inst),
                                     narg_strings[i][0:nc])
        parsed.append((commitment, response, challenge))

    ds = DuplexSponge(derive_session_id(BATCH_TAG))
    for i in range(nt):
        ds.absorb(session_ids[i])
        ds.absorb(serialize_linear_relation(instances[i]))
        ds.absorb(narg_strings[i])
    k_total = sum(num_equations(inst) for inst in instances)
    randomness_bytes = ds.squeeze(16 * k_total)

    acc = group.identity()
    k = 0
    for i in range(nt):
        inst = instances[i]
        commitment, response, challenge = parsed[i]
        img = image(inst)
        mapped = linear_map(inst, response)
        for j in range(num_equations(inst)):
            c = int.from_bytes(randomness_bytes[16 * k:16 * (k + 1)], "little")
            k += 1
            term = group.add(group.mul(c % group.order, commitment[j]),
                             group.mul((c * challenge) % group.order, img[j]))
            term = group.add(term, group.neg(group.mul(c % group.order,
                                                       mapped[j])))
            acc = group.add(acc, term)
    return acc is None


if __name__ == "__main__":
    from groups import BLSG1Group, I2OSP, P256Group

    class CountingRNG:
        """Fixed nonces for the self-test only."""
        def __init__(self):
            self.n = 41

        def random_scalar(self):
            self.n += 1
            return self.n

    p256 = P256Group()

    # The ChaumPedersen serialization example of {{serialize-linear-relations}}
    # (elements [G, H, X, Y], all coefficients 1), checked against its header
    # bytes written out by hand.
    cp = LinearRelation(p256, [p256.gen] * 4,
                        [Equation([(2, 1)], [(0, 0, 1)]),
                         Equation([(3, 1)], [(0, 1, 1)])])
    one = I2OSP(1, 32)
    header = (LE(2, 4)
              + LE(1, 4) + LE(2, 4) + one
              + LE(1, 4) + LE(0, 4) + LE(0, 4) + one
              + LE(1, 4) + LE(3, 4) + one
              + LE(1, 4) + LE(0, 4) + LE(1, 4) + one)
    assert serialize_linear_relation(cp).startswith(header)

    for g, suite in ((p256, "sigma-proofs_Shake128_P256"),
                     (BLSG1Group(), "sigma-proofs_Shake128_BLS12381")):
        # Schnorr end to end, both flavors, plus one tamper each. One tag
        # per flavor, carrying the flavor marker and the ciphersuite
        # identifier verbatim ({{sigma-proofs-tag}}): a tag shared across
        # flavors would let a batchable proof be re-encoded as an accepting
        # compact proof (the F4 adversarial vectors of the appendix).
        x = 7
        X = g.mul(x, g.generator())
        inst = LinearRelation(g, [g.generator(), X],
                              [Equation([(1, 1)], [(0, 0, 1)])])
        assert validate_instance(inst)
        assert linear_map(inst, [x]) == image(inst)
        assert parse_statement(
            g, serialize_linear_relation(inst)).elements == inst.elements
        batchable_tag = f"self-test-DSFS-with-{suite}".encode()
        compact_tag = f"self-test-CMPT-with-{suite}".encode()
        proof = prove_batchable(batchable_tag, inst, [x], CountingRNG())
        assert verify_batchable(batchable_tag, inst, proof)
        assert not verify_batchable(batchable_tag, inst,
                                    proof[:-1] + bytes([proof[-1] ^ 1]))
        sid = derive_session_id(batchable_tag)
        assert batch_verify(g, [sid, sid], [inst, inst], [proof, proof])
        compact = prove_compact(compact_tag, inst, [x], CountingRNG())
        assert verify_compact(compact_tag, inst, compact)
        assert not verify_compact(compact_tag, inst,
                                  compact[:-1] + bytes([compact[-1] ^ 1]))
        print(f"sigma_protocols[{g.name}]: ok")
