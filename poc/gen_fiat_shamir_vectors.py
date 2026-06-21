#!/usr/bin/env python3
"""Generate Fiat-Shamir test vectors. Standard library only.

    python3 poc/gen_fiat_shamir_vectors.py [output_dir]   # default: poc/vectors

Self-contained: the few primitives the vectors exercise (the SHAKE128 duplex
sponge, session-id derivation, the byte-string and unsigned-integer codecs, and
a minimal non-interactive argument) are inlined below, faithful to dsfs.py.

The vectors are ordered as a bring-up ramp for implementers: each one depends
only on primitives that earlier vectors already exercised (sponge -> session id
-> codecs -> non-interactive argument -> rejections), so the first failing
vector points at the lowest broken layer. Each section title is a readable
sentence; the `Name` suffix cross-references the fs-interop/TESTS.md manifest.

Each block names its instantiation in a `Ciphersuite` field: SHAKE128 for the
group-independent sponge and session-id vectors, "any" for the ciphersuite-
independent byte-string codec, and "SHAKE128 / P-256" for the vectors that also
fix a scalar field (the integer codec and the non-interactive argument).
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
# unsigned-integer codec and the non-interactive argument depend on M.

SID = bytes(range(32))  # session id whose byte i has value i: 000102...1e1f
DUPLEX_SPONGE = "SHAKE128"
GROUP = "P-256"
M = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 order
NS = ((M - 1).bit_length() + 7) // 8  # scalar byte length; 32 for this M

# --- SHAKE128 duplex sponge (capacity 32 bytes, rate 168) -----------------


class DuplexSponge:
    """Squeeze(n) yields the next n bytes of SHAKE128(session_id || zeros ||
    absorbed). Consecutive squeezes continue one stream; an absorb after a
    squeeze restarts it. Squeezed bytes are never fed back."""

    def __init__(self, session_id):
        assert len(session_id) == 32
        self._ctx = hashlib.shake_128()
        self._ctx.update(session_id + bytes(168 - 32))  # pad to the rate
        self._reader = None

    def absorb(self, x):
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


def deserialize_uint(buf, off):
    if len(buf) - off < NS:
        raise Reject
    x = int.from_bytes(buf[off : off + NS], "big")
    if x >= M:  # canonical representative required
        raise Reject
    return x, off + NS


def decode_uint(buf):  # DecodeUint: oversampled reduction, bias <= 2^-256
    return int.from_bytes(buf, "big") % M


# --- Minimal non-interactive argument -------------------------------------
#
# A 1.5-round protocol: prover sends a byte string, gets a scalar challenge c,
# replies with s = 3*c + 5 mod M (a deterministic stand-in for a real response).


def narg_prove(session_id, instance, message):
    sponge = DuplexSponge(session_id)
    sponge.absorb(encode_varlen(instance))  # encode[0]: instance, absorbed only
    sponge.absorb(encode_varlen(message))  # prover message: absorbed == serialized
    c = decode_uint(sponge.squeeze(NS + 32))
    s = (3 * c + 5) % M
    narg = encode_varlen(message) + encode_uint(s)
    return c, s, narg


def narg_verify(session_id, instance, narg):
    """A function of (session_id, instance, narg) only; shares no prover state."""
    try:
        _message, off = deserialize_varlen(narg, 0)
        s, off = deserialize_uint(narg, off)
        if off != len(narg):  # trailing bytes are rejected
            raise Reject
    except Reject:
        return False
    sponge = DuplexSponge(session_id)
    sponge.absorb(encode_varlen(instance))
    sponge.absorb(narg[: len(narg) - NS])  # message wire bytes == EncodeVarLenString
    return s == (3 * decode_uint(sponge.squeeze(NS + 32)) + 5) % M


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
        {"Name": name, "Title": title, "Ciphersuite": DUPLEX_SPONGE,
         "Category": "Duplex sponge",
         "SessionId": hx(SID), "Operations": operations, "Output": hx(bytes(out))}
    )
    return bytes(out)


def build():
    # 1. Duplex sponge: the foundation. Simplest first, then the state-machine
    #    laws in build-up order, ending with a multi-block stress test.
    sponge_vector("t01_init_squeeze",
                  "Squeeze 32 bytes immediately after initialization",
                  [squeeze(32)])
    sponge_vector("t02_absorb_squeeze",
                  "Absorb a message, then squeeze 64 bytes",
                  [absorb(b"hello world"), squeeze(64)])
    sponge_vector("t03_absorb_split",
                  "Absorbing in parts equals absorbing all at once",
                  [absorb(b"ab"), absorb(b"c"), squeeze(32)])
    # Consecutive squeezes (no absorb between) continue one stream: 16 || 16 == 32.
    streamed = sponge_vector("t04_stream",
                             "Consecutive squeezes continue a single output stream",
                             [absorb(b"abc"), squeeze(16), squeeze(16)])
    fresh = DuplexSponge(SID); fresh.absorb(b"abc")
    assert streamed == fresh.squeeze(32)
    sponge_vector("t05_restart_after_absorb",
                  "Absorbing after a squeeze restarts the output stream",
                  [absorb(b"hello "), squeeze(16), absorb(b"world"), squeeze(48)])
    sponge_vector("t06_interleave",
                  "Squeeze, absorb more input, then squeeze again",
                  [absorb(bytes(range(10))), squeeze(16), absorb(b"more data"), squeeze(16)])
    sponge_vector("t07_multiblock",
                  "Absorb and squeeze spanning multiple Keccak blocks",
                  [absorb(bytes([0xAB] * 600)), squeeze(600)])

    # 2. Session identifiers: the sponge with a fixed domain-separation label.
    tag = b"interop-test-v00"
    vectors.append(
        {"Name": "t08_derive_sid",
         "Title": "Derive a session identifier from an application tag",
         "Ciphersuite": DUPLEX_SPONGE, "Category": "Session identifiers",
         "Tag": hx(tag), "Output": hx(derive_session_id(tag))}
    )

    # 3. Codecs: the pure encoders first, then the sponge-backed challenge.
    #    EncodeVarLenString is ciphersuite-independent; the integer codec is
    #    fixed by the group (its width Ns, and the modulus for DecodeUint).
    vectors.append(
        {"Name": "t09_encode_varlen",
         "Title": "Length-prefixed byte-string encoding (EncodeVarLenString)",
         "Ciphersuite": "any (ciphersuite-independent)", "Category": "Codecs",
         "Input": hx(b"proof"), "Output": hx(encode_varlen(b"proof"))}
    )
    vectors.append(
        {"Name": "t10_encode_uint",
         "Title": "Fixed-width unsigned-integer encoding (EncodeUint)",
         "Ciphersuite": GROUP, "Category": "Codecs",
         "Value": str(0xDEADBEEF), "Modulus": hx(M.to_bytes(32, "big")),
         "Output": hx(encode_uint(0xDEADBEEF))}
    )
    sponge = DuplexSponge(SID); sponge.absorb(encode_varlen(b"instance"))
    buf = sponge.squeeze(NS + 32)
    vectors.append(
        {"Name": "t11_decode_uint",
         "Title": "Squeeze a challenge scalar, then reduce it (DecodeUint)",
         "Ciphersuite": f"{DUPLEX_SPONGE} / {GROUP}", "Category": "Codecs",
         "SessionId": hx(SID),
         "Operations": [absorb(encode_varlen(b"instance")), squeeze(NS + 32)],
         "Output": hx(buf), "Challenge": hx(decode_uint(buf).to_bytes(32, "big"))}
    )

    # 4. Non-interactive argument: everything combined, then the rejections.
    instance, message = b"test instance", b"commitment"
    c, s, narg = narg_prove(SID, instance, message)
    assert narg_verify(SID, instance, narg)
    vectors.append(
        {"Name": "t12_narg",
         "Title": "Minimal non-interactive argument: commit, challenge, respond",
         "Ciphersuite": f"{DUPLEX_SPONGE} / {GROUP}",
         "Category": "Non-interactive argument",
         "SessionId": hx(SID), "Instance": hx(instance), "Message": hx(message),
         "Challenge": hx(c.to_bytes(32, "big")), "Response": hx(s.to_bytes(32, "big")),
         "Narg": hx(narg)}
    )

    bad_length = bytearray(narg)
    bad_length[3] = (bad_length[3] + 1) % 256  # bump the message length prefix
    negatives = [
        ("t13a_trailing", "Reject a non-interactive argument with a trailing byte",
         narg + b"\x00"),
        ("t13b_truncated", "Reject a truncated non-interactive argument",
         narg[:-1]),
        ("t13c_noncanonical", "Reject a non-canonical scalar (integer equal to the modulus)",
         encode_varlen(message) + M.to_bytes(32, "big")),
        ("t13d_badlen", "Reject a corrupted byte-string length prefix",
         bytes(bad_length)),
    ]
    for name, title, tampered in negatives:
        assert not narg_verify(SID, instance, tampered)
        vectors.append(
            {"Name": name, "Title": title,
             "Ciphersuite": f"{DUPLEX_SPONGE} / {GROUP}",
             "Category": "Non-interactive argument (negative)",
             "SessionId": hx(SID), "Instance": hx(instance),
             "TamperedNarg": hx(tampered), "Result": "reject"}
        )


# --- Rendering ------------------------------------------------------------


def write_txt(path):
    with open(path, "w") as f:
        for v in vectors:
            f.write(f"## {v['Title']}\n~~~\n")
            for key, value in v.items():
                if key == "Title":
                    continue
                if key == "Operations":
                    for i, op in enumerate(value, 1):
                        rhs = ("absorb:" + op["data"] if op["type"] == "absorb"
                               else "squeeze:" + str(op["length"]))
                        _wrap(f, f"Operation{i} = {rhs}")
                    continue
                _wrap(f, f"{key} = {value}")
            f.write("~~~\n\n")


def _wrap(f, line, width=68):
    for i in range(0, len(line), width):
        hunk = line[i : i + width]
        if hunk.strip():
            f.write(hunk + "\n")


def main(out_dir=None):
    out_dir = out_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")
    os.makedirs(out_dir, exist_ok=True)
    build()
    with open(os.path.join(out_dir, "fiatShamirVectors.json"), "w") as f:
        json.dump(vectors, f, indent=2)
        f.write("\n")
    write_txt(os.path.join(out_dir, "fiatShamirVectors.txt"))
    print(f"{len(vectors)} vectors written to {out_dir}/fiatShamirVectors.{{json,txt}}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
