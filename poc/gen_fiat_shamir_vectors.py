#!/usr/bin/env python3
"""Generate Fiat-Shamir test vectors. Standard library only.

    python3 poc/gen_fiat_shamir_vectors.py [output_dir]   # default: poc/vectors

Self-contained: the few primitives the vectors exercise (the SHAKE128 and
TurboSHAKE128 duplex sponges, session-id derivation, the byte-string,
unsigned-integer, and field codecs, and the sumcheck protocol for a
multilinear polynomial) are inlined below. The standard library has no
TurboSHAKE128, so its underlying Keccak-p[1600, 12] sponge is inlined too.

The vectors are split into three files, each a self-contained suite:

  fiatShamirCodecVectors          hash-independent codecs (encoding and
                                  deserialization); concern neither sponge
  fiatShamirShake128Vectors       the SHAKE128 sponge-dependent vectors
  fiatShamirTurboShake128Vectors  the TurboSHAKE128 sponge-dependent vectors

The two hash suites carry the same vector Names, differing only in the `Hash`
field and the resulting bytes. Within each file the vectors are ordered as a
bring-up ramp for implementers: each one depends only on primitives that earlier
vectors already exercised (sponge -> session id -> challenge -> sumcheck
protocol; serialize -> deserialize for the codecs), so the first failing vector
points at the lowest broken layer.

Record schema
-------------
Every record is a flat map with a fixed field vocabulary, grouped as
identity -> instantiation -> parameters -> inputs -> outputs -> verdict. A field
is present only when the vector depends on it; the same concept always uses the
same key.

  identity       Name           machine id; cross-references fs-interop/TESTS.md
                 Title          one-sentence human description
                 Function       the spec operation exercised, e.g. SerializeUint,
                                DecodeUint, DeserializeField (see the draft)
  instantiation  Hash           duplex sponge instantiation (SHAKE128 or
                                TurboSHAKE128), present whenever the sponge is
                                involved
                 Group          named scalar field (P-256 or Mersenne31),
                                present when the modulus is a standardized
                                field's; absent when the modulus is a bare
                                prime claimed by no standard (2^256 - 189)
  parameters     Modulus        the field characteristic p, an integer; fixes
                                the width Ns and the canonical range [0, p)
                 ExtensionDegree the codec parameter m (field-codec vectors only)
                 NumVariables   the sumcheck parameter v (sumcheck vectors only)
  inputs         SessionId      32-byte session identifier seeding the sponge
                 Tag            application tag (DeriveSessionID)
                 Operations     ordered [{absorb: hex} | {squeeze: n}] sponge trace
                 Value, Input, ClaimedSum, Witness
  outputs        Output         primary byte output (sponge stream / encoding)
                 Challenge      a Fiat-Shamir scalar (Output reduced mod Modulus)
                 XofInput       the full one-shot XOF input over which the last
                                challenge is computed (sumcheck intermediates
                                vector only)
                 Coordinates, FinalEvaluation, Narg

Two value types, matching the format paragraph of the draft's Test Vectors
appendix: byte strings are lowercase hex exactly as serialized (Input, Output,
SessionId, Tag, Narg, absorb payloads); integers are
JSON numbers when small (ExtensionDegree, NumVariables, Witness entries,
squeeze lengths) and `0x`-prefixed most-significant-first strings when
field-sized (Modulus, Value, Coordinates, ClaimedSum, Challenge,
FinalEvaluation). The .txt rendering writes integers verbatim.

A sequence-valued field (Operations, Coordinates, Witness, and the per-round
Output and Challenge of the sumcheck intermediates vector) is a JSON list,
never a set of index-suffixed keys. The .txt rendering differs: the Witness
table is one comma-separated list, per-element outputs use indexed keys
(`Coordinates[0]` numbered as the draft's `a[0], ..., a[m-1]`; `Output[1]`
and `Challenge[1]` numbered as the draft's rounds `r[1], ..., r[v]`), and
the Operation trace stays one line per step.

The "answer" of a vector is always a named output field (Output / Challenge /
FinalEvaluation / ... ); there is no single catch-all key, mirroring RFC 9380's
labeled-field style.

Most vectors are positive: the record pins a concrete output that a conforming
implementation reproduces byte-for-byte. Records carrying `Expected = reject`
are negative: a conforming implementation MUST refuse the pinned input. Every
reject vector sits adjacent to an accepted boundary value (x = M next to the
accepted x = M - 1, a payload one byte short of its length prefix, and so on),
so each comparison in the draft is probed from both sides. Reject vectors
carry a prose `Comment` naming the draft requirement they exercise; the
rejection class itself (deserialize / length / verify) is asserted by the
self-test below but deliberately not emitted, since the draft does not
prescribe error values. Two sumcheck reject vectors (the non-canonical
coefficient and the broken round identity) are hash-independent -- the
rejection fires before any byte is squeezed -- and therefore live in the
codec suite; the self-test verifies each rejects under both hash suites.
The trailing-byte reject exercises the end-of-input check, which fires
only after every challenge has been squeezed, so it is hash-dependent:
each hash suite carries its own copy next to the accepted execution.

Writes the three suites above as
fiatShamir{Codec,Shake128,TurboShake128}Vectors.{json,txt}.
"""

import hashlib
import json
import os
import sys
import textwrap

# --- Shared constants -----------------------------------------------------
#
# Two instantiation axes appear in these vectors and are named per-record:
# the duplex sponge (`Hash`) and, where a modulus is needed, the prime
# (`Modulus`) plus, when that prime belongs to a standardized field, its
# name (`Group`). Two 256-bit primes appear, deliberately distinct:
#
#   Q = 2^256 - 189   the largest 256-bit prime, claimed by no standard, so
#                     the little-endian *default* serialization applies. Used
#                     by every vector that pins default-path serialization or
#                     deserialization bytes: the draft mandates big-endian
#                     serialization for fields fixed big-endian by their
#                     standard, so pinning little-endian bytes to such a
#                     field's order would contradict that MUST.
#   M = P-256 order   a field the draft's carve-out fixes big-endian. Used
#                     only where P-256 is conforming: the big-endian
#                     SerializeField vector, and the DecodeUint vectors,
#                     which pin that decoding stays little-endian for every
#                     field, byte-order carve-out or not.
#
# The sumcheck vectors use the Mersenne31 field (defined with the sumcheck
# section below). The sponge and byte-string vectors depend on no modulus.

SID = bytes(range(32))  # session id whose byte i has value i: 000102...1e1f
HASH = "SHAKE128"  # the default duplex sponge instantiation; the `Hash` field
GROUP = "P-256"  # the named scalar field; the `Group` field
R = 168  # duplex sponge rate in bytes (the capacity is 32); shared by both suites
M = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 order
Q = 2**256 - 189  # the largest 256-bit prime; the order of nothing standardized
NS = ((M - 1).bit_length() + 7) // 8  # scalar byte length Ns; 32 for both M and Q
assert ((Q - 1).bit_length() + 7) // 8 == NS
# DecodeUint/DecodeField oversample by k/8 extra bytes for a k-bit security
# level; SHAKE128 targets 128 bits, so 16 extra bytes bound the reduction bias
# to 2^-128 (matching RFC 9380, Section 5).
EXTRA = 16


def ix(n):  # integer -> 0x-prefixed hex, padded to an even digit count
    s = format(n, "x")
    return "0x" + ("0" + s if len(s) % 2 else s)


MODULUS = ix(M)  # P-256 order as an integer, for the `Modulus` field
MODULUS_Q = ix(Q)  # 2^256 - 189 as an integer, for the `Modulus` field

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


def serialize_varlen(s):  # SerializeVarLenString: 4-byte little-endian length || bytes
    return len(s).to_bytes(4, "little") + s


def serialize_uint(x, p):  # SerializeUint: fixed-width little-endian integer mod p
    assert 0 <= x < p
    return x.to_bytes(NS, "little")


def decode_uint(buf):  # DecodeUint: oversampled reduction, bias <= 2^-128
    return int.from_bytes(buf, "little") % M


def serialize_field(coordinates, p, m):
    """SerializeField: concatenate the fixed-width encodings of m coordinates."""
    if len(coordinates) != m:
        raise ValueError("wrong number of field coordinates")
    ns = ((p - 1).bit_length() + 7) // 8
    if any(x < 0 or x >= p for x in coordinates):
        raise ValueError("field coordinate out of range")
    return b"".join(x.to_bytes(ns, "little") for x in coordinates)


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


def deserialize_uint(buf, p):
    """DeserializeUint: exactly Ns canonical little-endian bytes, x < p."""
    if len(buf) < NS:
        raise Reject
    x = int.from_bytes(buf[:NS], "little")
    if x >= p:
        raise Reject
    return x


def deserialize_varlen(buf):
    """DeserializeVarLenString: a 4-byte length N, then N payload bytes."""
    if len(buf) < 4:
        raise Reject
    n = int.from_bytes(buf[:4], "little")
    if len(buf) - 4 < n:  # not 4 + n <= len(buf): that sum can overflow
        raise Reject
    return buf[4 : 4 + n]


def serialize_field_be(coordinates, p, m):
    """The big-endian carve-out of the field codec: I2OSP per coordinate,
    mandated when the field's standard fixes a big-endian serialization
    (P-256 per SEC1, BLS12-381)."""
    ns = ((p - 1).bit_length() + 7) // 8
    if len(coordinates) != m or any(x < 0 or x >= p for x in coordinates):
        raise ValueError("invalid field coordinates")
    return b"".join(x.to_bytes(ns, "big") for x in coordinates)


# --- The sumcheck protocol over Mersenne31 --------------------------------
#
# The example protocol of the draft's "Example protocol: sumcheck" appendix,
# implemented verbatim: SumcheckProve and SumcheckVerify below follow the
# numbered pseudocode steps. The application context enters through the
# session identifier, derived from the tag "sumcheck" via DeriveSessionID;
# the instance (v, S) is absorbed as encode[0] = SerializeUint(v, 2^32)
# || SerializeField(S, p, 1); each round absorbs the coefficient pair
# (a_0, a_1) of the round polynomial and decodes one challenge as
# LE2IP(Squeeze(Ns)) mod p -- the alternative small-field decoding the
# draft's decoding section permits, in place of the default Ns + 16
# oversampling (bias ~2^-31, below the ~2^-29 soundness error of the
# interactive argument).
#
# The vectors use the Mersenne31 field p = 2^31 - 1 with the little-endian
# default serialization (Ns = 4), and the witness (1, 2, 4, ..., 2^15):
# v = 4 variables, claimed sum 65535.

SUMCHECK_TAG = b"sumcheck"  # the DeriveSessionID tag binding the context
P31 = 2**31 - 1  # the Mersenne31 prime
NS31 = 4  # its serialization width Ns
SUMCHECK_V = 4  # the number of variables v
SUMCHECK_WITNESS = [1 << i for i in range(1 << SUMCHECK_V)]  # 1, 2, ..., 2^15


def sumcheck_instance_encoding(v, s):
    """encode[0] of the example protocol: the number of variables as
    SerializeUint(v, 2^32), and the claimed sum."""
    return v.to_bytes(4, "little") + serialize_field((s,), P31, 1)


def sumcheck_round_message(w):
    """The round polynomial g(X) = a_0 + a_1 X of the lowest variable, as
    its coefficients: g(0) and g(1) are the even/odd half-sums of the table."""
    g0 = sum(w[0::2]) % P31
    g1 = sum(w[1::2]) % P31
    return g0, (g1 - g0) % P31


def sumcheck_fold(w, r):
    """Bind the lowest variable to r: entry j becomes the line through
    (0, w[2j]) and (1, w[2j+1]) evaluated at r. Halves the table."""
    return [(w[2 * j] + r * (w[2 * j + 1] - w[2 * j])) % P31 for j in range(len(w) // 2)]


def multilinear_eval(w, rs):
    """Direct evaluation of the multilinear extension of w at rs, from the
    Lagrange basis on the hypercube; independently validates the even/odd
    convention (bit k of the index pairs with challenge rs[k])."""
    acc = 0
    for j, wj in enumerate(w):
        term = wj
        for k, r in enumerate(rs):
            term = term * ((r if (j >> k) & 1 else 1 - r) % P31) % P31
        acc = (acc + term) % P31
    return acc


def sumcheck_prove(session_id, new_ctx):
    """Returns (round messages, challenges, final evaluation). The claimed
    sum is absorbed internally (step 1 of the pseudocode); the caller
    recomputes it from the witness."""
    sponge = DuplexSponge(session_id, new_ctx)
    claimed = sum(SUMCHECK_WITNESS) % P31
    sponge.absorb(sumcheck_instance_encoding(SUMCHECK_V, claimed))
    w = list(SUMCHECK_WITNESS)
    messages, challenges = [], []
    while len(w) > 1:
        a0, a1 = sumcheck_round_message(w)
        msg = serialize_field((a0, a1), P31, 2)
        sponge.absorb(msg)  # prover message: absorbed == serialized
        r = int.from_bytes(sponge.squeeze(NS31), "little") % P31
        w = sumcheck_fold(w, r)
        messages.append(msg)
        challenges.append(r)
    return messages, challenges, w[0]


def sumcheck_verify(session_id, claimed, narg, new_ctx, rounds=SUMCHECK_V):
    """Returns (accepted, challenges, final claim); shares no prover state.
    Rejection of a malformed round message fires during deserialization,
    before any byte is squeezed."""
    sponge = DuplexSponge(session_id, new_ctx)
    sponge.absorb(sumcheck_instance_encoding(rounds, claimed))
    off, current, challenges = 0, claimed, []
    try:
        for _ in range(rounds):
            (a0, a1), new_off = deserialize_field(narg, off, P31, 2)
            if (2 * a0 + a1) % P31 != current:  # g(0) + g(1) == current claim
                return False, None, None
            sponge.absorb(narg[off:new_off])
            off = new_off
            r = int.from_bytes(sponge.squeeze(NS31), "little") % P31
            current = (a0 + a1 * r) % P31  # reduce the claim to g(r)
            challenges.append(r)
        if off != len(narg):  # trailing bytes are rejected
            raise Reject
    except Reject:
        return False, None, None
    return True, challenges, current


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
        "Squeeze a 32-byte string after initialization",
        [squeeze(32)],
        suite,
    )
    sponge_vector(
        out,
        "absorb_squeeze",
        "Absorb the byte string `hello world`, then squeeze 64 bytes",
        [absorb(b"hello world"), squeeze(64)],
        suite,
    )
    sponge_vector(
        out,
        "absorb_split",
        "Absorb is associative: `Absorb(\"abc\")` is equivalent to `Absorb(\"ab\"); Absorb(\"c\")`",
        [absorb(b"ab"), absorb(b"c"), squeeze(32)],
        suite,
    )
    # Consecutive squeezes (no absorb between) continue one stream: 16 || 16 == 32.
    streamed = sponge_vector(
        out,
        "stream",
        "Squeeze is associative: `Squeeze(16 + 16)` is equivalent to `Squeeze(16) || Squeeze(16)`",
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
        "Absorb of the empty string is a no-op",
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
        "Absorb and squeeze can be interleaved",
        [absorb(bytes(range(10))), squeeze(16), absorb(b"more data"), squeeze(16)],
        suite,
    )
    sponge_vector(
        out,
        "multiblock",
        "Absorbing a byte string of length longer than the rate.",
        [absorb(bytes([0xAB] * 600)), squeeze(600)],
        suite,
    )
    # Rate boundaries. After Init the padded session id fills exactly one
    # rate block, so this absorb ends exactly at the next block boundary --
    # the position where a native (incremental permutation) duplex sponge
    # must call the permutation and where the XOF padding moves to a fresh
    # block. The split squeeze crosses the output-block boundary at byte
    # 168: the first call stops one byte short of it, the second reads
    # across it.
    sponge_vector(
        out,
        "rate_block",
        "Squeeze at the rate boundary",
        [absorb(bytes(range(R))), squeeze(R - 1), squeeze(2)],
        suite,
    )
    # A zero-length squeeze is a no-op: it returns the empty string and
    # must neither restart the output stream nor ratchet the state, so the
    # trace (absorb "abc", squeeze 0, absorb "def") equals absorbing
    # "abcdef" outright. A native duplex sponge that permutes on every
    # squeeze-to-absorb transition, including the empty one, diverges here.
    zero_out = sponge_vector(
        out,
        "squeeze_zero",
        "A zero-length squeeze between absorbs is a no-op",
        [absorb(b"abc"), squeeze(0), absorb(b"def"), squeeze(32)],
        suite,
    )
    plain = DuplexSponge(SID, new_ctx)
    plain.absorb(b"abcdef")
    assert zero_out == plain.squeeze(32)

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


def emit_serialize_codecs(out):
    """The pure serializers. Hash-independent, so they live in the shared codec
    suite. SerializeVarLenString is field-independent; the integer codec is fixed
    by its modulus (the width Ns and the canonical range [0, p))."""
    out.append(
        {
            "Name": "serialize_varlen",
            "Title": "Byte-string serialization: `SerializeVarLenString`",
            "Function": "SerializeVarLenString",
            "Input": hx(b"proof"),
            "Output": hx(serialize_varlen(b"proof")),
        }
    )
    out.append(
        {
            "Name": "serialize_uint",
            "Title": "`SerializeUint`: unsigned-integer serialization.",
            "Comment": "The modulus is `2^256 - 189`, the largest 256-bit "
            "prime. It is not the order of any standardized field, so the "
            "little-endian default serialization applies.",
            "Function": "SerializeUint",
            "Modulus": MODULUS_Q,
            "Value": ix(0xDEADBEEF),  # the integer x
            "Output": hx(serialize_uint(0xDEADBEEF, Q)),
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
    sponge.absorb(serialize_varlen(b"instance"))
    buf = sponge.squeeze(NS + EXTRA)
    out.append(
        {
            "Name": "decode_uint",
            "Title": "Squeeze and reduce a P-256 scalar challenge (`DecodeUint`)",
            "Comment": "The P-256 scalar field *serializes* big-endian "
            "({{serialize-field}}). However, the squeezed bytes are interpreted "
            "little-endian, via `LE2IP`, for every modulus "
            "({{decoding-uint}}).",
            "Function": "DecodeUint",
            "Hash": hash_name,
            "Group": GROUP,
            "Modulus": MODULUS,
            "SessionId": hx(SID),
            "Operations": [absorb(serialize_varlen(b"instance")), squeeze(NS + EXTRA)],
            "Output": hx(buf),
            "Challenge": ix(decode_uint(buf)),
        }
    )


def emit_deserialize_field(out):
    """Deserialization: a NARG string parsed back into field coordinates. Pins a
    canonical degree-2 (m = 2) field element and the two coordinates
    DeserializeField -- the canonical NARG parser -- recovers from it.
    Hash-independent, so it lives in the shared codec suite."""
    field_m = 2
    field_serialization = serialize_field((0xDEADBEEF, Q - 1), Q, field_m)
    coords, off = deserialize_field(field_serialization, 0, Q, field_m)
    assert off == len(field_serialization) and coords == (0xDEADBEEF, Q - 1)
    out.append(
        {
            "Name": "deserialize_field",
            "Title": "`DeserializeField`, used to deserialize a degree-2 element of the field of characteristic `2^256 - 189` (the default, little-endian serialization).",
            "Function": "DeserializeField",
            "Modulus": MODULUS_Q,
            "ExtensionDegree": field_m,
            "Input": hx(field_serialization),
            "Coordinates": [ix(c) for c in coords],
        }
    )


def emit_codec_boundaries(out):
    """Boundary and rejection vectors for the codec and deserialization
    layer. Hash-independent. Each range comparison in the draft is probed
    from both sides: the accepted value sits in this suite (or in
    deserialize_field, whose second coordinate is M - 1), the adjacent
    rejected value in the record next to it."""
    # Degenerate valid: the empty string is a legal var-len message; its
    # encoding is the four zero bytes of its length prefix and nothing else.
    empty = serialize_varlen(b"")
    assert deserialize_varlen(empty) == b""
    out.append(
        {
            "Name": "varlen_empty",
            "Title": "The empty byte string may be encoded as a variable-length string.",
            "Comment": "It will have zero length prefix and no payload. "
            "`DeserializeVarLenString` returns the empty string after "
            "consuming exactly four bytes.",
            "Function": "SerializeVarLenString",
            "Input": "",
            "Output": hx(empty),
        }
    )
    # Decoding is infallible: DecodeUint reduces, it never rejects. The
    # 48-byte little-endian encoding of M itself reduces to zero -- the
    # extreme case of the modular wraparound.
    buf = M.to_bytes(NS + EXTRA, "little")
    assert decode_uint(buf) == 0
    out.append(
        {
            "Name": "decode_uint_wraparound",
            "Title": "Decoding is infallible and distribution-preserving",
            "Comment": "`DecodeUint` reduces the 48 input bytes modulo the P-256 scalar-field order.",
            "Function": "DecodeUint",
            "Group": GROUP,
            "Modulus": MODULUS,
            "Input": hx(buf),
            "Challenge": ix(0),
        }
    )
    # The big-endian carve-out: fields whose standard fixes a big-endian
    # serialization (P-256 per SEC1) MUST use I2OSP in place of the
    # little-endian default. This is the only vector on that branch.
    be = serialize_field_be((0xDEADBEEF,), M, 1)
    assert be == (0xDEADBEEF).to_bytes(NS, "big")
    out.append(
        {
            "Name": "serialize_field_be",
            "Title": "Field serialization of the P-256 scalar field happens via `I2OSP`.",
            "Function": "SerializeField",
            "ByteOrder": "big-endian",
            "Group": GROUP,
            "Modulus": MODULUS,
            "Value": ix(0xDEADBEEF),
            "Output": hx(be),
        }
    )

    def reject(name, title, comment, function, input_, **extra):
        record = {"Name": name, "Title": title}
        if comment:
            record["Comment"] = comment
        record.update({"Function": function, **extra, "Input": hx(input_), "Expected": "reject"})
        out.append(record)

    for buf in (Q.to_bytes(NS, "little"),):
        try:
            deserialize_uint(buf, Q)
            raise AssertionError("Q must be rejected")
        except Reject:
            pass
    reject(
        "deserialize_uint_reject_modulus",
        "The modulus itself is not accepted as a valid serialization.",
        "",
        "DeserializeUint",
        Q.to_bytes(NS, "little"),
        Modulus=MODULUS_Q,
    )
    short = (0xDEADBEEF).to_bytes(NS - 1, "little")
    try:
        deserialize_uint(short, Q)
        raise AssertionError("short scalar must be rejected")
    except Reject:
        pass
    reject(
        "deserialize_uint_reject_short",
        "Deserialization fails for inputs shorter than `Ns` bytes", "",
        "DeserializeUint",
        short,
        Modulus=MODULUS_Q,
    )
    bad_field = (Q - 1).to_bytes(NS, "little") + b"\xff" * NS
    try:
        deserialize_field(bad_field, 0, Q, 2)
        raise AssertionError("non-canonical coordinate must be rejected")
    except Reject:
        pass
    reject(
        "deserialize_field_reject_second_coordinate",
        "When deserializing field extension elements, all coordinates must be validated",
        "For instance, in this example the first value is the maximal "
        "canonical coordinate `p - 1` and the second is `2^256 - 1`, which "
        "exceeds it. Therefore, deserialization must fail.",
        "DeserializeField",
        bad_field,
        Modulus=MODULUS_Q,
        ExtensionDegree=2,
    )
    truncated = serialize_varlen(b"proof")[:-1]
    try:
        deserialize_varlen(truncated)
        raise AssertionError("truncated payload must be rejected")
    except Reject:
        pass
    reject(
        "deserialize_varlen_reject_truncated",
        "A payload one byte shorter than its length prefix is rejected.",
        "The input is the serialization of the byte string `proof` (the "
        "`serialize_varlen` vector) with its last byte removed: the length "
        "prefix promises 5 payload bytes and only 4 remain.",
        "DeserializeVarLenString",
        truncated,
    )
    overflow = b"\xff\xff\xff\xff" + b"\xde\xad\xbe\xef"
    try:
        deserialize_varlen(overflow)
        raise AssertionError("overflowing length prefix must be rejected")
    except Reject:
        pass
    reject(
        "deserialize_varlen_reject_overflow",
        "The maximal length prefix 2^32 - 1 is rejected.",
        "",
        "DeserializeVarLenString",
        overflow,
    )


MODULUS31 = ix(P31)  # Mersenne31 as an integer


def emit_narg_battery(out):
    """The NARG tamper vectors of the draft's implementation guidance,
    applied to the sumcheck instance. Hash-independent: each rejection
    fires while processing the first round message, before any byte is
    squeezed, so one record serves both hash suites (the self-test
    verifies this under both)."""
    # Start from the honest SHAKE128 transcript and re-encode the first
    # coefficient of the first round message as a_0 + p: the same value
    # modulo p in different bytes (a_0 + p < 2^32, so it still fits Ns
    # bytes). An implementation that reduces instead of rejecting recovers
    # the honest coefficients, passes every round identity, and thereby
    # accepts a second, distinct NARG string for the same statement.
    claimed = sum(SUMCHECK_WITNESS) % P31
    messages, _, _ = sumcheck_prove(SID, hashlib.shake_128)
    narg = b"".join(messages)
    a0 = int.from_bytes(narg[:NS31], "little")
    noncanonical = (a0 + P31).to_bytes(NS31, "little") + narg[NS31:]
    for _, new_ctx in (SHAKE128_SUITE, TURBOSHAKE128_SUITE):
        accepted, _, _ = sumcheck_verify(SID, claimed, noncanonical, new_ctx)
        assert not accepted, "non-canonical coefficient must be rejected"
    out.append(
        {
            "Name": "sumcheck_reject_noncanonical_coefficient",
            "Title": "The example protocol ({{example-sumcheck}}), where the first prover message is an invalid serialization (`p`, the modulus, is added to the canonical encoding)",
            "Comment": "",
            "Function": "Sumcheck",
            "Group": "Mersenne31",
            "Modulus": MODULUS31,
            "NumVariables": SUMCHECK_V,
            "SessionId": hx(SID),
            "ClaimedSum": ix(claimed),
            "Narg": hx(noncanonical),
            "Expected": "reject",
        }
    )
    # A canonical re-encoding that breaks the round identity instead: the
    # first coefficient becomes a_0 + 1, still a canonical field element,
    # so deserialization succeeds and the verifier rejects at the round
    # identity g(0) + g(1) == S (2 * (a_0 + 1) + a_1 = S + 2 != S). The
    # identity of round 1 involves no challenge, so this rejection also
    # fires before any byte is squeezed and is hash-independent.
    assert a0 + 1 < P31
    tampered = (a0 + 1).to_bytes(NS31, "little") + narg[NS31:]
    for _, new_ctx in (SHAKE128_SUITE, TURBOSHAKE128_SUITE):
        accepted, _, _ = sumcheck_verify(SID, claimed, tampered, new_ctx)
        assert not accepted, "broken round identity must be rejected"
    out.append(
        {
            "Name": "sumcheck_reject_round_identity",
            "Title": "An invalid NARG string for the example protocol ({{example-sumcheck}}), where a prover message does not satisfy verification",
            "Comment": "",
            "Function": "Sumcheck",
            "Group": "Mersenne31",
            "Modulus": MODULUS31,
            "NumVariables": SUMCHECK_V,
            "SessionId": hx(SID),
            "ClaimedSum": ix(claimed),
            "Narg": hx(tampered),
            "Expected": "reject",
        }
    )


def emit_sumcheck(out, suite):
    """The sumcheck protocol over Mersenne31, for one hash suite: a worked
    example of the FS transform on a non-sigma IO pattern (absorb a round
    message, squeeze a challenge, four times), followed by the end-of-input
    rejection of the same transcript with a trailing byte appended."""
    hash_name, new_ctx = suite
    sid = derive_session_id(SUMCHECK_TAG, new_ctx)
    claimed = sum(SUMCHECK_WITNESS) % P31
    messages, challenges, final = sumcheck_prove(sid, new_ctx)
    accepted, challenges_v, final_v = sumcheck_verify(
        sid, claimed, b"".join(messages), new_ctx
    )
    assert accepted and challenges_v == challenges and final_v == final
    # The folded value equals the multilinear extension evaluated at the
    # challenge point, computed independently from the Lagrange basis.
    assert final == multilinear_eval(SUMCHECK_WITNESS, challenges)
    out.append(
        {
            "Name": "sumcheck",
            "Title": "The sumcheck protocol example ({{example-sumcheck}}) over Mersenne31.",
            "Comment": "",
            "Function": "Sumcheck",
            "Hash": hash_name,
            "Group": "Mersenne31",
            "Modulus": MODULUS31,
            "NumVariables": SUMCHECK_V,
            "Tag": hx(SUMCHECK_TAG),
            "SessionId": hx(sid),
            "Witness": list(SUMCHECK_WITNESS),
            "ClaimedSum": ix(claimed),
            "Narg": hx(b"".join(messages)),
            "FinalEvaluation": ix(final),
        }
    )
    # The end-of-input check (step 9 of SumcheckVerify): the honest NARG
    # string with a single zero byte appended. Every round message parses
    # and every round identity holds under this suite's challenges, so the
    # rejection fires only after the last round, at the unread trailing
    # byte. Unlike the codec-suite rejections, reaching step 9 requires
    # this suite's challenges, so each hash suite pins its own copy.
    trailing = b"".join(messages) + b"\x00"
    accepted, _, _ = sumcheck_verify(sid, claimed, trailing, new_ctx)
    assert not accepted, "trailing bytes must be rejected"
    out.append(
        {
            "Name": "sumcheck_reject_trailing_bytes",
            "Title": "A NARG string with trailing bytes is rejected",
            "Comment": "",
            "Function": "Sumcheck",
            "Hash": hash_name,
            "Group": "Mersenne31",
            "Modulus": MODULUS31,
            "NumVariables": SUMCHECK_V,
            "Tag": hx(SUMCHECK_TAG),
            "SessionId": hx(sid),
            "ClaimedSum": ix(claimed),
            "Narg": hx(trailing),
            "Expected": "reject",
        }
    )


def emit_sumcheck_intermediates(out, suite):
    """The sumcheck instance again, with every intermediate value pinned:
    the full one-shot XOF input and, per round, the raw squeeze and its
    reduction, so a diverging implementation can localize the failing stage
    (encoding, hashing, or decoding) rather than only detect it. The session
    id is set directly rather than derived from a tag, so the SHAKE128
    record's execution is the base of the codec-suite sumcheck rejections."""
    hash_name, new_ctx = suite
    claimed = sum(SUMCHECK_WITNESS) % P31
    messages, challenges, final = sumcheck_prove(SID, new_ctx)
    narg = b"".join(messages)
    instance = sumcheck_instance_encoding(SUMCHECK_V, claimed)
    xof_input = SID + bytes(R - 32) + instance + narg
    # Replay the transcript reading each round's raw pre-reduction squeeze,
    # and check it against the equivalent one-shot XOF evaluation over the
    # prefix of xof_input ending at that round's message.
    sponge = DuplexSponge(SID, new_ctx)
    sponge.absorb(instance)
    raws = []
    for i, msg in enumerate(messages):
        sponge.absorb(msg)
        raw = sponge.squeeze(NS31)
        prefix = xof_input[: R + len(instance) + 2 * NS31 * (i + 1)]
        one_shot = new_ctx()
        one_shot.update(prefix)
        assert raw == one_shot.digest(NS31)
        raws.append(raw)
    assert [int.from_bytes(b, "little") % P31 for b in raws] == challenges


def build_suite(suite):
    """One hash suite's bring-up ramp: sponge -> session id -> challenge ->
    sumcheck. The codec vectors are hash-independent and live in their own
    suite (see build_codecs)."""
    out = []
    emit_sponge_and_sid(out, suite)
    emit_decode_uint(out, suite)
    emit_sumcheck(out, suite)
    emit_sumcheck_intermediates(out, suite)
    return out


def build_codecs():
    """The shared, hash-independent codec suite: serialize -> deserialize ->
    boundary and reject vectors -> the NARG tamper vectors."""
    out = []
    emit_serialize_codecs(out)
    emit_deserialize_field(out)
    emit_codec_boundaries(out)
    emit_narg_battery(out)
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
# continuation lines. Sequences render in three ways, matching the format
# paragraph of the draft's Test Vectors appendix: the Operation trace is one
# line per step (an ordered trace, not a value), per-element outputs use
# indexed keys (_INDEX_BASE below), and any other sequence is one
# comma-separated list wrapped only after commas.


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
