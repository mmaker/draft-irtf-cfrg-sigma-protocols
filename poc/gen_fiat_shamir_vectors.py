#!/usr/bin/env python3
"""Generate Fiat-Shamir test vectors. Standard library only.

    python3 poc/gen_fiat_shamir_vectors.py [output_dir]   # default: poc/vectors

Self-contained: the few primitives the vectors exercise (the SHAKE128 and
TurboSHAKE128 duplex sponges, session-id derivation, the byte-string,
unsigned-integer, and field codecs, and one round of the sumcheck protocol) are
inlined below. The standard library has no TurboSHAKE128, so its underlying
Keccak-p[1600, 12] sponge is inlined too.

The vectors are split into three files, each a self-contained suite:

  fiatShamirCodecVectors          hash-independent codecs (encoding and
                                  deserialization); concern neither sponge
  fiatShamirShake128Vectors       the SHAKE128 sponge-dependent vectors
  fiatShamirTurboShake128Vectors  the TurboSHAKE128 sponge-dependent vectors

The two hash suites carry the same vector Names, differing only in the `Hash`
field and the resulting bytes. Within each file the vectors are ordered as a
bring-up ramp for implementers: each one depends only on primitives that earlier
vectors already exercised (sponge -> session id -> challenge -> sumcheck
protocol; encode -> deserialize for the codecs), so the first failing vector
points at the lowest broken layer.

Record schema
-------------
Every record is a flat map with a fixed field vocabulary, grouped as
identity -> instantiation -> parameters -> inputs -> outputs -> verdict. A field
is present only when the vector depends on it; the same concept always uses the
same key.

  identity       Name           machine id; cross-references fs-interop/TESTS.md
                 Title          one-sentence human description
                 Function       the spec operation exercised, e.g. EncodeUint,
                                DecodeUint, DeserializeField (see the draft)
  instantiation  Hash           duplex sponge instantiation (SHAKE128 or
                                TurboSHAKE128), present whenever the sponge is
                                involved
                 Group          named scalar field (P-256), present whenever a
                                field modulus is involved
  parameters     Modulus        the field characteristic p, as Ns bytes; makes
                                the width Ns and the canonical range [0, p) explicit
                 ExtensionDegree the codec parameter m (field-codec vectors only)
  inputs         SessionId      32-byte session identifier seeding the sponge
                 Tag            application tag (DeriveSessionID)
                 Operations     ordered [{absorb: hex} | {squeeze: n}] sponge trace
                 Value, Input, ContextTag, Degree, ClaimedSum, Coefficients
  outputs        Output         primary byte output (sponge stream / encoding)
                 Challenge      a Fiat-Shamir scalar (Output reduced mod Modulus)
                 Coordinates, ReducedClaim, Narg

A sequence-valued field (Operations, Coefficients, Coordinates) is a JSON list,
never a set of index-suffixed keys.

The "answer" of a vector is always a named output field (Output / Challenge /
ReducedClaim / ... ); there is no single catch-all key, mirroring RFC 9380's
labeled-field style.

These vectors are positive-only: every record pins a concrete output that a
conforming implementation reproduces byte-for-byte. Writes the three suites
above as fiatShamir{Codec,Shake128,TurboShake128}Vectors.{json,txt}.
"""

import hashlib
import json
import os
import sys

# --- Shared constants -----------------------------------------------------
#
# Two instantiation axes appear in these vectors and are named per-record:
# the duplex sponge (`Hash`) and, where a scalar field is needed, the group
# (`Group`) and its modulus (`Modulus`). We use P-256 to match the sigma-proofs
# P-256 ciphersuite. The sponge and byte-string vectors depend on neither
# `Group` nor `Modulus`; only the integer and field codecs and the
# non-interactive argument depend on M.

SID = bytes(range(32))  # session id whose byte i has value i: 000102...1e1f
HASH = "SHAKE128"  # the default duplex sponge instantiation; the `Hash` field
GROUP = "P-256"  # the named scalar field; the `Group` field
R = 168  # duplex sponge rate in bytes (the capacity is 32); shared by both suites
M = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 order
NS = ((M - 1).bit_length() + 7) // 8  # scalar byte length Ns; 32 for this M
# DecodeUint/DecodeField oversample by k/8 extra bytes for a k-bit security
# level; SHAKE128 targets 128 bits, so 16 extra bytes bound the reduction bias
# to 2^-128 (matching RFC 9380, Section 5).
EXTRA = 16
MODULUS = M.to_bytes(
    NS, "little"
).hex()  # P-256 order as Ns bytes, for the `Modulus` field

# --- TurboSHAKE128 over Keccak-p[1600, 12] (RFC 9861) ---------------------
#
# The standard library has no TurboSHAKE128, so it is inlined here as a
# minimal drop-in for hashlib.shake_128, exposing the update / copy /
# digest(n) surface the duplex sponge needs. TurboSHAKE128(M, D=0x1F, L)
# absorbs M at rate R, applies pad10*1 padding with domain byte D, then
# squeezes L bytes. It coincides with SHAKE128 except that the permutation runs
# the last 12 of the 24 Keccak rounds (Keccak-p[1600, 12]); the domain byte
# 0x1F equals SHAKE128's suffix, so only the round count differs. This was
# validated against the RFC 9861 vectors and, with all 24 rounds, against
# hashlib's SHAKE128.

_MASK64 = (1 << 64) - 1
_RC = [  # the 24 Keccak-f round constants; rounds 12..23 are used here
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


def _keccak_p1600_12(state):
    """Keccak-p[1600, 12]: the final 12 of the 24 Keccak-f rounds (12..23).
    `state` is a 200-byte bytearray; returns the permuted 200 bytes."""
    a = [int.from_bytes(state[8 * i : 8 * i + 8], "little") for i in range(25)]
    for rnd in range(12, 24):
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
        out[8 * i : 8 * i + 8] = (a[i] & _MASK64).to_bytes(8, "little")
    return out


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
        state = bytearray(200)
        m, i = self._buf, 0
        while len(m) - i >= R:  # absorb full rate blocks
            for j in range(R):
                state[j] ^= m[i + j]
            state = _keccak_p1600_12(state)
            i += R
        for j in range(len(m) - i):  # absorb the final partial block
            state[j] ^= m[i + j]
        state[len(m) - i] ^= self._D  # domain byte, then pad10*1 ...
        state[R - 1] ^= 0x80  # ... with the final padding bit
        state = _keccak_p1600_12(state)
        out = bytearray()
        while len(out) < length:  # squeeze, permuting between rate blocks
            out += state[:R]
            if len(out) < length:
                state = _keccak_p1600_12(state)
        return bytes(out[:length])


# --- Duplex sponge (capacity 32 bytes, rate R = 168) ----------------------
#
# Both hash suites share Init / Absorb / Squeeze and differ only in the
# underlying XOF context, chosen via `new_ctx`: hashlib.shake_128 for SHAKE128,
# TurboSHAKE128 above for TurboSHAKE128.


class DuplexSponge:
    """Squeeze(n) yields the next n bytes of XOF(session_id || zeros ||
    absorbed) for the chosen hash suite. Consecutive squeezes continue one
    stream; a non-empty absorb after a squeeze restarts it. An empty absorb is
    a no-op (it never restarts the stream). Squeezed bytes are never fed back."""

    def __init__(self, session_id, new_ctx=hashlib.shake_128):
        assert len(session_id) == 32
        self._ctx = new_ctx()
        self._ctx.update(session_id + bytes(R - 32))  # pad to the rate
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
    # 32-byte domain-separation label, padded into one rate block by Init
    sponge = DuplexSponge(b"irtf-cfrg-fiat-shamir/session-id", new_ctx)
    sponge.absorb(tag)
    return sponge.squeeze(32)


# Named hash suites: (Hash field value, XOF-context factory).
SHAKE128_SUITE = (HASH, hashlib.shake_128)
TURBOSHAKE128_SUITE = ("TurboSHAKE128", TurboSHAKE128)


# --- Codecs ---------------------------------------------------------------


class Reject(Exception):
    """A NARG string failed to parse; the verifier rejects."""


def encode_varlen(s):  # EncodeVarLenString: 4-byte little-endian length || bytes
    return len(s).to_bytes(4, "little") + s


def encode_uint(x):  # EncodeUint: fixed-width little-endian integer mod M
    return x.to_bytes(NS, "little")


def decode_uint(buf):  # DecodeUint: oversampled reduction, bias <= 2^-128
    return int.from_bytes(buf, "little") % M


def encode_field(coordinates, p, m):
    """EncodeField: concatenate the fixed-width encodings of m coordinates."""
    if len(coordinates) != m:
        raise ValueError("wrong number of field coordinates")
    ns = ((p - 1).bit_length() + 7) // 8
    if any(x < 0 or x >= p for x in coordinates):
        raise ValueError("field coordinate out of range")
    return b"".join(x.to_bytes(ns, "little") for x in coordinates)


def decode_field(buf, p, m):
    """DecodeField: independently reduce m oversampled coordinates modulo p."""
    ns = ((p - 1).bit_length() + 7) // 8
    chunk_len = ns + EXTRA
    if len(buf) != m * chunk_len:
        raise Reject
    return tuple(
        int.from_bytes(buf[i * chunk_len : (i + 1) * chunk_len], "little") % p
        for i in range(m)
    )


def deserialize_field(buf, off, p, m):
    """DeserializeField: parse m canonical fixed-width coordinates modulo p."""
    ns = ((p - 1).bit_length() + 7) // 8
    coordinates = []
    for i in range(m):
        start = off + i * ns
        if len(buf) - start < ns:
            raise Reject
        x = int.from_bytes(buf[start : start + ns], "little")
        if x >= p:
            raise Reject
        coordinates.append(x)
    return tuple(coordinates), off + m * ns


# --- One round of the sumcheck protocol -----------------------------------
#
# The sumcheck protocol proves sum_{x in {0,1}^v} g(x) = H for a v-variate
# polynomial g. In round 1 the prover sends the univariate "round polynomial"
#     g_1(X) = sum_{x_2,...,x_v in {0,1}} g(X, x_2, ..., x_v),
# of degree d (here d = 2, serialized as its d + 1 coefficients with EncodeField).
# The verifier checks the round identity g_1(0) + g_1(1) == H, draws a challenge r
# by Fiat-Shamir, and reduces the claim to H' = g_1(r) for the next round. We
# exercise exactly that single round: the NARG string is the serialized g_1.

SUMCHECK_TAG = b"sumcheck"


def poly_eval(coeffs, x):  # Horner evaluation of sum_i coeffs[i] * X^i mod M
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % M
    return acc


def sumcheck_challenge(session_id, claimed_sum, round_poly, new_ctx):
    sponge = DuplexSponge(session_id, new_ctx)
    sponge.absorb(encode_varlen(SUMCHECK_TAG))  # encode[0]: domain tag
    sponge.absorb(encode_uint(claimed_sum))  # instance: the claimed sum H
    sponge.absorb(round_poly)  # prover message g_1: absorbed == serialized
    return decode_uint(sponge.squeeze(NS + EXTRA))


def sumcheck_prove(session_id, claimed_sum, coeffs, new_ctx):
    # Honest prover: the round polynomial is consistent with the claimed sum.
    assert (poly_eval(coeffs, 0) + poly_eval(coeffs, 1)) % M == claimed_sum
    round_poly = encode_field(coeffs, M, len(coeffs))
    r = sumcheck_challenge(session_id, claimed_sum, round_poly, new_ctx)
    return r, poly_eval(coeffs, r), round_poly  # narg == round_poly


def sumcheck_verify(session_id, claimed_sum, num_coeffs, narg, new_ctx):
    """Returns (accepted, challenge, reduced_claim); shares no prover state."""
    try:
        coeffs, off = deserialize_field(narg, 0, M, num_coeffs)
        if off != len(narg):  # trailing bytes are rejected
            raise Reject
    except Reject:
        return False, None, None
    if (poly_eval(coeffs, 0) + poly_eval(coeffs, 1)) % M != claimed_sum:
        return False, None, None  # round identity g_1(0) + g_1(1) == H failed
    r = sumcheck_challenge(session_id, claimed_sum, narg, new_ctx)
    return True, r, poly_eval(coeffs, r)  # reduce the claim to H' = g_1(r)


# --- Vector construction --------------------------------------------------

hx = bytes.hex  # bytes -> lowercase hex


def absorb(data):
    return {"type": "absorb", "data": hx(data)}


def squeeze(length):
    return {"type": "squeeze", "length": length}


def sponge_vector(out, name, title, operations, suite):
    hash_name, new_ctx = suite
    sponge = DuplexSponge(SID, new_ctx)
    stream = bytearray()
    for op in operations:
        if op["type"] == "absorb":
            sponge.absorb(bytes.fromhex(op["data"]))
        else:
            stream += sponge.squeeze(op["length"])
    out.append(
        {
            "Name": name,
            "Title": title,
            "Function": "DuplexSponge",
            "Hash": hash_name,
            "SessionId": hx(SID),
            "Operations": operations,
            "Output": hx(bytes(stream)),
        }
    )
    return bytes(stream)


def emit_sponge_and_sid(out, suite):
    """The duplex sponge state-machine vectors plus the session-id derivation,
    for one hash suite, appended to `out`."""
    hash_name, new_ctx = suite
    # 1. Duplex sponge: the foundation. Simplest first, then the state-machine
    #    laws in build-up order, ending with a multi-block stress test.
    sponge_vector(
        out,
        "init_squeeze",
        "Squeeze 32 bytes immediately after initialization",
        [squeeze(32)],
        suite,
    )
    sponge_vector(
        out,
        "absorb_squeeze",
        "Absorb a message, then squeeze 64 bytes",
        [absorb(b"hello world"), squeeze(64)],
        suite,
    )
    sponge_vector(
        out,
        "absorb_split",
        "Absorbing in parts equals absorbing all at once",
        [absorb(b"ab"), absorb(b"c"), squeeze(32)],
        suite,
    )
    # Consecutive squeezes (no absorb between) continue one stream: 16 || 16 == 32.
    streamed = sponge_vector(
        out,
        "stream",
        "Consecutive squeezes continue a single output stream",
        [absorb(b"abc"), squeeze(16), squeeze(16)],
        suite,
    )
    fresh = DuplexSponge(SID, new_ctx)
    fresh.absorb(b"abc")
    assert streamed == fresh.squeeze(32)
    # An empty absorb is a no-op: it neither adds input nor restarts the output
    # stream, so the second squeeze continues where the first left off (rather
    # than repeating it, which would hand out the same challenge twice). The
    # vector's Output is output_1 || output_2; the two 32-byte halves differ
    # (the stream did not restart) and together equal one 64-byte squeeze of the
    # same "abc" with no empty absorb in between (the empty absorb was a no-op).
    empty_out = sponge_vector(
        out,
        "empty_absorb",
        "Empty absorb",
        [absorb(b"abc"), squeeze(32), absorb(b""), squeeze(32)],
        suite,
    )
    output_1, output_2 = empty_out[:32], empty_out[32:]
    assert output_1 != output_2
    continued = DuplexSponge(SID, new_ctx)
    continued.absorb(b"abc")
    assert empty_out == continued.squeeze(64)
    sponge_vector(
        out,
        "interleave",
        "Squeeze, absorb more input, then squeeze again",
        [absorb(bytes(range(10))), squeeze(16), absorb(b"more data"), squeeze(16)],
        suite,
    )
    sponge_vector(
        out,
        "multiblock",
        "Absorb and squeeze multiple blocks",
        [absorb(bytes([0xAB] * 600)), squeeze(600)],
        suite,
    )

    # 2. Session identifiers: the sponge with a fixed domain-separation label.
    tag = b"interop-test-v00"
    out.append(
        {
            "Name": "derive_sid",
            "Title": "Derive a session identifier from an application tag",
            "Function": "DeriveSessionID",
            "Hash": hash_name,
            "Tag": hx(tag),
            "Output": hx(derive_session_id(tag, new_ctx)),
        }
    )


def emit_encode_codecs(out):
    """The pure encoders. Hash-independent, so they live in the shared codec
    suite. EncodeVarLenString is field-independent; the integer codec is fixed by
    the group (its width Ns and modulus M)."""
    out.append(
        {
            "Name": "encode_varlen",
            "Title": "Length-prefixed byte-string encoding (EncodeVarLenString)",
            "Function": "EncodeVarLenString",
            "Input": hx(b"proof"),
            "Output": hx(encode_varlen(b"proof")),
        }
    )
    out.append(
        {
            "Name": "encode_uint",
            "Title": "Fixed-width unsigned-integer encoding (EncodeUint)",
            "Function": "EncodeUint",
            "Group": GROUP,
            "Modulus": MODULUS,
            "Value": format(0xDEADBEEF, "x"),  # the integer x, as hex
            "Output": hx(encode_uint(0xDEADBEEF)),
        }
    )


def emit_decode_uint(out, suite):
    """The sponge-backed scalar challenge, for one hash suite."""
    hash_name, new_ctx = suite
    # DecodeUint squeezes Ns + 16 bytes and reduces them modulo M; the extra 16
    # bytes bound the sampling bias by 2^-128. Output is the wide squeeze; the
    # Challenge is Output reduced modulo Modulus (an Ns-byte scalar). With a
    # 32-byte Modulus the operation squeezes 32 + 16 = 48 bytes.
    sponge = DuplexSponge(SID, new_ctx)
    sponge.absorb(encode_varlen(b"instance"))
    buf = sponge.squeeze(NS + EXTRA)
    out.append(
        {
            "Name": "decode_uint",
            "Title": "Squeeze and reduce a P-256 scalar challenge (DecodeUint)",
            "Function": "DecodeUint",
            "Hash": hash_name,
            "Group": GROUP,
            "Modulus": MODULUS,
            "SessionId": hx(SID),
            "Operations": [absorb(encode_varlen(b"instance")), squeeze(NS + EXTRA)],
            "Output": hx(buf),
            "Challenge": hx(decode_uint(buf).to_bytes(NS, "little")),
        }
    )


def emit_deserialize_field(out):
    """Deserialization: a NARG string parsed back into field coordinates. Pins a
    canonical degree-2 (m = 2) field element and the two coordinates
    DeserializeField -- the canonical NARG parser -- recovers from it.
    Hash-independent, so it lives in the shared codec suite."""
    field_m = 2
    field_encoding = encode_field((0xDEADBEEF, M - 1), M, field_m)
    coords, off = deserialize_field(field_encoding, 0, M, field_m)
    assert off == len(field_encoding) and coords == (0xDEADBEEF, M - 1)
    out.append(
        {
            "Name": "deserialize_field",
            "Title": "Deserialize a canonical degree-2 field element (DeserializeField)",
            "Function": "DeserializeField",
            "Group": GROUP,
            "Modulus": MODULUS,
            "ExtensionDegree": field_m,
            "Input": hx(field_encoding),
            "Coordinates": [hx(c.to_bytes(NS, "little")) for c in coords],
        }
    )


def emit_sumcheck(out, suite):
    """One round of the sumcheck protocol: a worked example of the FS transform
    on a non-sigma IO pattern (absorb field elements, squeeze one challenge), for
    one hash suite. The round-identity check is the sumcheck protocol's own
    soundness concern, not a Fiat-Shamir property."""
    hash_name, new_ctx = suite
    degree = 2
    # Deterministic, reproducible round polynomial: full-width coefficients
    # squeezed from a fixed seed, with the claimed sum set to g_1(0) + g_1(1).
    prng = DuplexSponge(
        derive_session_id(b"sumcheck-round-1-coefficients", new_ctx), new_ctx
    )
    coeffs = [decode_uint(prng.squeeze(NS + EXTRA)) for _ in range(degree + 1)]
    claimed_sum = (poly_eval(coeffs, 0) + poly_eval(coeffs, 1)) % M
    r, reduced_claim, narg = sumcheck_prove(SID, claimed_sum, coeffs, new_ctx)
    accepted, r_v, reduced_v = sumcheck_verify(
        SID, claimed_sum, degree + 1, narg, new_ctx
    )
    assert accepted and r_v == r and reduced_v == reduced_claim
    out.append(
        {
            "Name": "sumcheck",
            "Title": "One round of the sumcheck protocol: round polynomial, challenge, reduced claim",
            "Function": "Sumcheck",
            "Hash": hash_name,
            "Group": GROUP,
            "Modulus": MODULUS,
            "SessionId": hx(SID),
            "ContextTag": hx(SUMCHECK_TAG),
            "Degree": degree,
            "ClaimedSum": hx(claimed_sum.to_bytes(NS, "little")),
            "Coefficients": [hx(c.to_bytes(NS, "little")) for c in coeffs],
            "Challenge": hx(r.to_bytes(NS, "little")),
            "ReducedClaim": hx(reduced_claim.to_bytes(NS, "little")),
            "Narg": hx(narg),
        }
    )


def build_suite(suite):
    """One hash suite's bring-up ramp: sponge -> session id -> challenge ->
    sumcheck. The codec vectors are hash-independent and live in their own
    suite (see build_codecs)."""
    out = []
    emit_sponge_and_sid(out, suite)
    emit_decode_uint(out, suite)
    emit_sumcheck(out, suite)
    return out


def build_codecs():
    """The shared, hash-independent codec suite: encode -> deserialize."""
    out = []
    emit_encode_codecs(out)
    emit_deserialize_field(out)
    return out


def build():
    """Return the three suites as (file basename, vectors) pairs."""
    return [
        ("fiatShamirCodecVectors", build_codecs()),
        ("fiatShamirShake128Vectors", build_suite(SHAKE128_SUITE)),
        ("fiatShamirTurboShake128Vectors", build_suite(TURBOSHAKE128_SUITE)),
    ]


# --- Rendering ------------------------------------------------------------
#
# The .txt is human-facing (each suite is included in the draft); the .json is
# the machine-readable source of truth. Both share the record schema above. Hex
# values are wrapped on byte (even-offset) boundaries so each line holds whole
# bytes and can be diffed by eye; a wrapped value is the concatenation of its
# continuation lines. Per-vector titles are level-3 headings so a suite can sit
# under a level-2 heading in the draft.


# --- vector rendering -----------------------------------------------------
#
# The rendering has two rules, and they are the whole grammar:
#
#   1. A value is written inline after `Key = ` when it fits the document
#      width; otherwise it is written on the following lines, indented by
#      two spaces, and those lines are joined with no separator.
#   2. A sequence-valued field always uses the indented block form, one
#      item per line, each introduced by `- `.
#
# So an indented line beginning `- ` appends an item, and any other
# indented line continues the value above it. Nothing else is significant,
# and no key ever repeats within a vector, which is what lets the .txt and
# the .json carry exactly the same records.

WIDTH = 72
INDENT = "  "

# Byte strings wrap at a whole 32 bytes per line, rather than at whatever
# the document width allows. A 32-byte value is then exactly one line and a
# 64-byte value exactly two, so a reader counts bytes by counting lines
# instead of counting characters.
HEX_BYTES_PER_LINE = 32

# Byte strings longer than this always take the indented block form, even
# when they would fit inline. Without it, whether a value wraps depends on
# how long its key happens to be, and two 32-byte values render differently
# under `Narg` and `SessionId`. Short tags still sit inline.
HEX_INLINE_MAX_BYTES = 16

# The suite component of each vector `Id`, keyed by output file basename.
_SUITE_ID = {
    "fiatShamirCodecVectors": "codec",
    "fiatShamirShake128Vectors": "shake128",
    "fiatShamirTurboShake128Vectors": "turboshake128",
}


def _is_hex(s):
    return (
        isinstance(s, str)
        and len(s) > 0
        and len(s) % 2 == 0
        and all(c in "0123456789abcdef" for c in s)
    )


def _emit(f, key, payload):
    """Write `Key = payload`, inline when it fits, otherwise as an indented
    block. Byte strings break on even offsets, so that every continuation
    line is a whole number of bytes."""
    lhs = f"{key} = "
    long_bytes = _is_hex(payload) and len(payload) > 2 * HEX_INLINE_MAX_BYTES
    if not long_bytes and len(lhs) + len(payload) <= WIDTH:
        f.write(lhs + payload + "\n")
        return
    f.write(f"{key} =\n")
    hexish = _is_hex(payload) or (
        payload.startswith("0x") and _is_hex(payload[2:])
    )
    step = 2 * HEX_BYTES_PER_LINE if hexish else WIDTH - len(INDENT)
    for i in range(0, len(payload), step):
        f.write(INDENT + payload[i : i + step] + "\n")


def _emit_seq(f, key, items):
    """Write a sequence as an indented block, one `- item` per line. Items
    too long for a line are wrapped and continued, so a reader joins any
    non-`- ` continuation onto the item above it."""
    f.write(f"{key} =\n")
    room = WIDTH - len(INDENT) - 2
    for item in items:
        if len(item) <= room:
            f.write(f"{INDENT}- {item}\n")
            continue
        hexish = _is_hex(item) or (item.startswith("0x") and _is_hex(item[2:]))
        step = 2 * HEX_BYTES_PER_LINE if hexish else room
        f.write(f"{INDENT}- {item[:step]}\n")
        for i in range(step, len(item), step):
            f.write(INDENT + INDENT + item[i : i + step] + "\n")


def _render_op(op):
    """One `Operations` item: the operation name, then its argument."""
    if op["type"] == "absorb":
        return "absorb " + (op["data"] or '""')
    return f"squeeze {op['length']}"


def write_txt(path, vectors, heading="###"):
    # Every vector leads with `Id`, so that a harness and the prose can refer
    # to one stably. Title, Comment and the Group label are prose and stay
    # out of the fence.
    with open(path, "w") as f:
        for v in vectors:
            f.write(f"{heading} {v['Title']}\n~~~\n")
            _emit(f, "Id", v["Id"])
            for key, value in v.items():
                if key in ("Id", "Name", "Title", "Comment", "Group"):
                    continue
                if key == "Operations":
                    _emit_seq(f, key, [_render_op(op) for op in value])
                elif isinstance(value, list):
                    _emit_seq(f, key, [str(x) for x in value])
                else:
                    _emit(f, key, str(value) or '""')
            f.write("~~~\n\n")


def main(out_dir=None):
    out_dir = out_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "vectors"
    )
    os.makedirs(out_dir, exist_ok=True)
    total = 0
    for basename, vectors in build():
        # `Id` is the stable handle for a vector: `<draft>/<suite>/<name>`.
        # It is assigned here so the suite component always matches the
        # file the vector is written to.
        suite = _SUITE_ID[basename]
        for rec in vectors:
            rec["Id"] = f"fiat-shamir/{suite}/{rec['Name']}"
        with open(os.path.join(out_dir, basename + ".json"), "w") as f:
            json.dump(
                [
                    {"Id": rec["Id"],
                     **{k: v for k, v in rec.items()
                        if k not in ("Comment", "Id")}}
                    for rec in vectors
                ],
                f,
                indent=2,
            )
            f.write("\n")
        write_txt(os.path.join(out_dir, basename + ".txt"), vectors)
        print(f"{len(vectors):2d} vectors -> {basename}.{{json,txt}}")
        total += len(vectors)
    print(f"{total} vectors written to {out_dir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
