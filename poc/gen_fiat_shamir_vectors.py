#!/usr/bin/env python3
"""Generate Fiat-Shamir test vectors. Standard library only.

    python3 poc/gen_fiat_shamir_vectors.py [output_dir]   # default: poc/vectors

Self-contained: the few primitives the vectors exercise (the SHAKE128 duplex
sponge, session-id derivation, the byte-string, unsigned-integer, and field
codecs, and one round of the sumcheck protocol) are inlined below.

The vectors are ordered as a bring-up ramp for implementers: each one depends
only on primitives that earlier vectors already exercised (sponge -> session id
-> codecs -> deserialization rejections -> sumcheck protocol), so the first
failing vector points at the lowest broken layer. Each section title is a
readable sentence; the `Name` field cross-references fs-interop/TESTS.md.

The verifier's MUST-reject surface (non-canonical, truncated, over-long, or
trailing bytes) is tested once at the codec layer rather than per protocol, so
the sumcheck section is a positive-only worked example.

Each block names its instantiation in a `Ciphersuite` field: SHAKE128 for the
group-independent sponge and session-id vectors, "any" for the ciphersuite-
independent byte-string codec, and "SHAKE128 / P-256" for the vectors that also
fix a scalar field (the integer and field codecs and the sumcheck protocol).
Writes fiatShamirVectors.{json,txt}.
"""

import hashlib
import json
import os
import sys

# --- Shared constants -----------------------------------------------------
#
# Two ciphersuite axes appear in these vectors and are named per-block in the
# `Ciphersuite` field: the duplex sponge (SHAKE128) and, where a scalar field
# is needed, the group. We use P-256 to match the sigma-proofs P-256 ciphersuite.
# The sponge and byte-string vectors are independent of the group; only the
# unsigned-integer and field codecs and the non-interactive argument depend on M.

SID = bytes(range(32))  # session id whose byte i has value i: 000102...1e1f
DUPLEX_SPONGE = "SHAKE128"
GROUP = "P-256"
M = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 order
NS = ((M - 1).bit_length() + 7) // 8  # scalar byte length; 32 for this M

# --- SHAKE128 duplex sponge (capacity 32 bytes, rate 168) -----------------


class DuplexSponge:
    """Squeeze(n) yields the next n bytes of SHAKE128(session_id || zeros ||
    absorbed). Consecutive squeezes continue one stream; a non-empty absorb
    after a squeeze restarts it. An empty absorb is a no-op (it never restarts
    the stream). Squeezed bytes are never fed back."""

    def __init__(self, session_id):
        assert len(session_id) == 32
        self._ctx = hashlib.shake_128()
        self._ctx.update(session_id + bytes(168 - 32))  # pad to the rate
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


def derive_session_id(tag):
    sponge = DuplexSponge(b"irtf-cfrg-fiat-shamir/session-id")  # 32-byte label
    sponge.absorb(tag)
    return sponge.squeeze(32)


# --- Codecs ---------------------------------------------------------------


class Reject(Exception):
    """A NARG string failed to parse; the verifier rejects."""


def encode_varlen(s):  # EncodeVarLenString: 4-byte big-endian length || bytes
    return len(s).to_bytes(4, "big") + s


def deserialize_varlen(buf, off):
    if len(buf) - off < 4:
        raise Reject
    n = int.from_bytes(buf[off : off + 4], "big")
    if len(buf) - off < 4 + n:
        raise Reject
    return buf[off + 4 : off + 4 + n], off + 4 + n


def encode_uint(x):  # EncodeUint: fixed-width big-endian integer mod M
    return x.to_bytes(NS, "big")


def decode_uint(buf):  # DecodeUint: oversampled reduction, bias <= 2^-256
    return int.from_bytes(buf, "big") % M


def encode_field(coordinates, p, m):
    """EncodeField: concatenate the fixed-width encodings of m coordinates."""
    if len(coordinates) != m:
        raise ValueError("wrong number of field coordinates")
    ns = ((p - 1).bit_length() + 7) // 8
    if any(x < 0 or x >= p for x in coordinates):
        raise ValueError("field coordinate out of range")
    return b"".join(x.to_bytes(ns, "big") for x in coordinates)


def decode_field(buf, p, m):
    """DecodeField: independently reduce m oversampled coordinates modulo p."""
    ns = ((p - 1).bit_length() + 7) // 8
    chunk_len = ns + 32
    if len(buf) != m * chunk_len:
        raise Reject
    return tuple(
        int.from_bytes(buf[i * chunk_len : (i + 1) * chunk_len], "big") % p
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
        x = int.from_bytes(buf[start : start + ns], "big")
        if x >= p:
            raise Reject
        coordinates.append(x)
    return tuple(coordinates), off + m * ns


def narg_field_accepts(buf, m):
    """Verifier check for a NARG carrying m field coordinates: parse them
    canonically and require no trailing bytes. Used by the rejection vectors."""
    try:
        _, off = deserialize_field(buf, 0, M, m)
    except Reject:
        return False
    return off == len(buf)


def narg_varlen_accepts(buf):
    """Verifier check for a NARG carrying one length-prefixed byte string."""
    try:
        _, off = deserialize_varlen(buf, 0)
    except Reject:
        return False
    return off == len(buf)


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


def sumcheck_challenge(session_id, claimed_sum, round_poly):
    sponge = DuplexSponge(session_id)
    sponge.absorb(encode_varlen(SUMCHECK_TAG))  # encode[0]: domain tag
    sponge.absorb(encode_uint(claimed_sum))  # instance: the claimed sum H
    sponge.absorb(round_poly)  # prover message g_1: absorbed == serialized
    return decode_uint(sponge.squeeze(NS + 32))


def sumcheck_prove(session_id, claimed_sum, coeffs):
    # Honest prover: the round polynomial is consistent with the claimed sum.
    assert (poly_eval(coeffs, 0) + poly_eval(coeffs, 1)) % M == claimed_sum
    round_poly = encode_field(coeffs, M, len(coeffs))
    r = sumcheck_challenge(session_id, claimed_sum, round_poly)
    return r, poly_eval(coeffs, r), round_poly  # narg == round_poly


def sumcheck_verify(session_id, claimed_sum, num_coeffs, narg):
    """Returns (accepted, challenge, reduced_claim); shares no prover state."""
    try:
        coeffs, off = deserialize_field(narg, 0, M, num_coeffs)
        if off != len(narg):  # trailing bytes are rejected
            raise Reject
    except Reject:
        return False, None, None
    if (poly_eval(coeffs, 0) + poly_eval(coeffs, 1)) % M != claimed_sum:
        return False, None, None  # round identity g_1(0) + g_1(1) == H failed
    r = sumcheck_challenge(session_id, claimed_sum, narg)
    return True, r, poly_eval(coeffs, r)  # reduce the claim to H' = g_1(r)


# --- Vector construction --------------------------------------------------

vectors = []
hx = bytes.hex  # bytes -> lowercase hex


def absorb(data):
    return {"type": "absorb", "data": hx(data)}


def squeeze(length):
    return {"type": "squeeze", "length": length}


def sponge_vector(name, title, operations):
    sponge = DuplexSponge(SID)
    out = bytearray()
    for op in operations:
        if op["type"] == "absorb":
            sponge.absorb(bytes.fromhex(op["data"]))
        else:
            out += sponge.squeeze(op["length"])
    vectors.append(
        {
            "Name": name,
            "Title": title,
            "Ciphersuite": DUPLEX_SPONGE,
            "SessionId": hx(SID),
            "Operations": operations,
            "Output": hx(bytes(out)),
        }
    )
    return bytes(out)


def build():
    # 1. Duplex sponge: the foundation. Simplest first, then the state-machine
    #    laws in build-up order, ending with a multi-block stress test.
    sponge_vector(
        "init_squeeze",
        "Squeeze 32 bytes immediately after initialization",
        [squeeze(32)],
    )
    sponge_vector(
        "absorb_squeeze",
        "Absorb a message, then squeeze 64 bytes",
        [absorb(b"hello world"), squeeze(64)],
    )
    sponge_vector(
        "absorb_split",
        "Absorbing in parts equals absorbing all at once",
        [absorb(b"ab"), absorb(b"c"), squeeze(32)],
    )
    # Consecutive squeezes (no absorb between) continue one stream: 16 || 16 == 32.
    streamed = sponge_vector(
        "stream",
        "Consecutive squeezes continue a single output stream",
        [absorb(b"abc"), squeeze(16), squeeze(16)],
    )
    fresh = DuplexSponge(SID)
    fresh.absorb(b"abc")
    assert streamed == fresh.squeeze(32)
    # An empty absorb is a no-op: it neither adds input nor restarts the output
    # stream, so the second squeeze continues where the first left off (rather
    # than repeating it, which would hand out the same challenge twice).
    empty_sponge = DuplexSponge(SID)
    empty_sponge.absorb(b"abc")
    output_1 = empty_sponge.squeeze(32)
    empty_sponge.absorb(b"")
    output_2 = empty_sponge.squeeze(32)
    assert output_1 != output_2
    continued = DuplexSponge(SID)
    continued.absorb(b"abc")
    assert output_1 + output_2 == continued.squeeze(64)
    vectors.append(
        {
            "Name": "empty_absorb",
            "Title": "An empty absorb is a no-op and does not restart the output stream",
            "Ciphersuite": DUPLEX_SPONGE,
            "SessionId": hx(SID),
            "Operation1": 'absorb:616263 (ASCII "abc")',
            "Operation2": "squeeze:32",
            "Output1": hx(output_1),
            "Operation3": 'absorb:"" (zero bytes)',
            "Operation4": "squeeze:32",
            "Output2": hx(output_2),
        }
    )
    sponge_vector(
        "interleave",
        "Squeeze, absorb more input, then squeeze again",
        [absorb(bytes(range(10))), squeeze(16), absorb(b"more data"), squeeze(16)],
    )
    sponge_vector(
        "multiblock",
        "Absorb and squeeze multiple blocks",
        [absorb(bytes([0xAB] * 600)), squeeze(600)],
    )

    # 2. Session identifiers: the sponge with a fixed domain-separation label.
    tag = b"interop-test-v00"
    vectors.append(
        {
            "Name": "derive_sid",
            "Title": "Derive a session identifier from an application tag",
            "Ciphersuite": DUPLEX_SPONGE,
            "Tag": hx(tag),
            "Output": hx(derive_session_id(tag)),
        }
    )

    # 3. Codecs: the pure encoders first, then the sponge-backed challenge.
    #    EncodeVarLenString is ciphersuite-independent; the integer and field
    #    codecs are fixed by the group (their width Ns and modulus).
    vectors.append(
        {
            "Name": "encode_varlen",
            "Title": "Length-prefixed byte-string encoding (EncodeVarLenString)",
            "Ciphersuite": "any (ciphersuite-independent)",
            "Input": hx(b"proof"),
            "Output": hx(encode_varlen(b"proof")),
        }
    )
    vectors.append(
        {
            "Name": "encode_uint",
            "Title": "Fixed-width unsigned-integer encoding (EncodeUint)",
            "Ciphersuite": GROUP,
            "Value": str(0xDEADBEEF),
            "Modulus": hx(M.to_bytes(32, "big")),
            "Output": hx(encode_uint(0xDEADBEEF)),
        }
    )
    sponge = DuplexSponge(SID)
    sponge.absorb(encode_varlen(b"instance"))
    buf = sponge.squeeze(NS + 32)
    vectors.append(
        {
            "Name": "decode_uint",
            "Title": "Squeeze a P-256 scalar (DecodeUint)",
            "Ciphersuite": f"{DUPLEX_SPONGE} / {GROUP}",
            "SessionId": hx(SID),
            "Operations": [absorb(encode_varlen(b"instance")), squeeze(NS + 32)],
            "Output": hx(buf),
            "Challenge": hx(decode_uint(buf).to_bytes(32, "big")),
        }
    )

    # 3b. Deserialization rejections. A NARG string is untrusted input, so the
    #     verifier MUST reject anything non-canonical, truncated, over-long, or
    #     with trailing bytes (see the draft's deserialization requirements).
    #     These are codec-level invariants, tested once here rather than
    #     re-instantiated inside every protocol that uses the codecs.
    # A well-formed degree-2 (m=2) field element, used only as the canonical
    # input that the field rejection vectors below tamper with.
    field_degree = 2
    field_encoding = encode_field((0xDEADBEEF, M - 1), M, field_degree)
    field_truncated = field_encoding[:-1]
    field_trailing = field_encoding + b"\x00"
    field_noncanonical = M.to_bytes(NS, "big") + field_encoding[NS:]  # coord0 == M
    # A byte-string length prefix is attacker-controlled and may exceed the
    # bytes present (the 4 + N overflow flagged in the deserialization section).
    varlen_overflow = (len(b"proof") + 1).to_bytes(4, "big") + b"proof"
    assert not narg_field_accepts(field_truncated, field_degree)
    assert not narg_field_accepts(field_trailing, field_degree)
    assert not narg_field_accepts(field_noncanonical, field_degree)
    assert not narg_varlen_accepts(varlen_overflow)
    field_cs = f"{GROUP} scalar characteristic / m=2"
    for name, title, cs, tampered in [
        (
            "reject_truncated",
            "Reject a malformed (truncated) field element",
            field_cs,
            field_truncated,
        ),
        (
            "reject_trailing",
            "Reject a malformed (trailing bytes) field element",
            field_cs,
            field_trailing,
        ),
        (
            "reject_noncanonical",
            "Reject a malformed (integer equal to the modulus) field element",
            field_cs,
            field_noncanonical,
        ),
        (
            "reject_varlen_overflow",
            "Reject a byte-string length prefix larger than the input",
            "any (ciphersuite-independent)",
            varlen_overflow,
        ),
    ]:
        vectors.append(
            {
                "Name": name,
                "Title": title,
                "Ciphersuite": cs,
                "Input": hx(tampered),
                "Result": "reject",
            }
        )

    # 4. One round of the sumcheck protocol: a worked example of the FS transform
    #    on a non-sigma IO pattern (absorb field elements, squeeze one challenge).
    #    Serialization rejections are covered generically above, so this section
    #    is positive-only; the round-identity check is the sumcheck protocol's
    #    own soundness concern, not a Fiat-Shamir property.
    degree = 2
    # Deterministic, reproducible round polynomial: full-width coefficients
    # squeezed from a fixed seed, with the claimed sum set to g_1(0) + g_1(1).
    prng = DuplexSponge(derive_session_id(b"sumcheck-round-1-coefficients"))
    coeffs = [decode_uint(prng.squeeze(NS + 32)) for _ in range(degree + 1)]
    claimed_sum = (poly_eval(coeffs, 0) + poly_eval(coeffs, 1)) % M
    r, reduced_claim, narg = sumcheck_prove(SID, claimed_sum, coeffs)
    accepted, r_v, reduced_v = sumcheck_verify(SID, claimed_sum, degree + 1, narg)
    assert accepted and r_v == r and reduced_v == reduced_claim
    vectors.append(
        {
            "Name": "sumcheck",
            "Title": "One round of the sumcheck protocol: round polynomial, challenge, reduced claim",
            "Ciphersuite": f"{DUPLEX_SPONGE} / {GROUP}",
            "SessionId": hx(SID),
            "ContextTag": hx(SUMCHECK_TAG),
            "Degree": degree,
            "ClaimedSum": hx(claimed_sum.to_bytes(32, "big")),
            "Coefficient0": hx(coeffs[0].to_bytes(32, "big")),
            "Coefficient1": hx(coeffs[1].to_bytes(32, "big")),
            "Coefficient2": hx(coeffs[2].to_bytes(32, "big")),
            "Challenge": hx(r.to_bytes(32, "big")),
            "ReducedClaim": hx(reduced_claim.to_bytes(32, "big")),
            "Narg": hx(narg),
        }
    )


# --- Rendering ------------------------------------------------------------


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
# under `Output` and `SessionId`. Short tags still sit inline.
HEX_INLINE_MAX_BYTES = 16


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
    step = 2 * HEX_BYTES_PER_LINE if _is_hex(payload) else WIDTH - len(INDENT)
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
        step = 2 * HEX_BYTES_PER_LINE if _is_hex(item) else room
        f.write(f"{INDENT}- {item[:step]}\n")
        for i in range(step, len(item), step):
            f.write(INDENT + INDENT + item[i : i + step] + "\n")


def _render_op(op):
    """One `Operations` item: the operation name, then its argument."""
    if op["type"] == "absorb":
        return "absorb " + (op["data"] or '""')
    return f"squeeze {op['length']}"


def write_txt(path):
    # Every vector leads with `Id`, so that a harness and the prose can
    # refer to one stably; it replaces the bare `Name` the fence used to
    # carry. Title stays outside the fence, as the section heading.
    with open(path, "w") as f:
        for v in vectors:
            f.write(f"## {v['Title']}\n~~~\n")
            _emit(f, "Id", f"fiat-shamir/{v['Name']}")
            for key, value in v.items():
                if key in ("Id", "Name", "Title"):
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
    build()
    # `Id` is the stable handle for a vector, and leads both renderings so
    # that a record is identifiable before it is parsed.
    for rec in vectors:
        rec["Id"] = f"fiat-shamir/{rec['Name']}"
    with open(os.path.join(out_dir, "fiatShamirVectors.json"), "w") as f:
        json.dump(
            [
                {"Id": rec["Id"], **{k: v for k, v in rec.items() if k != "Id"}}
                for rec in vectors
            ],
            f,
            indent=2,
        )
        f.write("\n")
    write_txt(os.path.join(out_dir, "fiatShamirVectors.txt"))
    print(f"{len(vectors)} vectors written to {out_dir}/fiatShamirVectors.{{json,txt}}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
