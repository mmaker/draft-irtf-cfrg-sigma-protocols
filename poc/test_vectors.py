"""Verify the test vectors of both drafts against this implementation.

    python3 poc/test_vectors.py

Reads the JSON vector files in poc/vectors/ -- the machine-readable form
of the vectors rendered in the drafts' Test Vectors appendices -- and
checks every record against the modules in this directory. Verification
is regeneration wherever the vectors pin the randomness: the valid
sigma-protocols proofs are re-proven byte-for-byte from the instance,
the witness, and the seeded PRNG of the appendix ({{seeded-prng}}), the
sumcheck NARG strings are re-proven from the witness, and the functional
Fiat-Shamir vectors (sponge traces, session ids, codecs) are recomputed
from their inputs. Records carrying `Expected = reject` MUST be refused;
each sigma reject names in `BaseId` the accepted vector it mutates, so a
verifier that rejects everything fails the accept/reject pairing instead
of passing most of the suite.

Batch verification is checked on the claim of the sigma draft's appendix:
every subset of the valid batchable proofs verifies as a batch, and a
batch containing any rejected batchable NARG string is rejected.

The same vectors are written out in the drafts' Test Vectors appendices;
the final pass parses every fenced vector block out of the two draft
sources and checks it field-for-field against its JSON record, so the
hand-maintained appendices cannot drift from the machine-readable files.

Standard library only; exits non-zero on the first failing check.
"""

import hashlib
import json
import os

import sumcheck
from fiat_shamir import (DuplexSponge, Reject, decode_uint, derive_session_id,
                         deserialize_field, deserialize_uint,
                         deserialize_varlen, serialize_field_be,
                         serialize_uint, serialize_varlen)
from groups import BLSG1Group, DeserializeError, P256Group
from keccak import TurboSHAKE128
from sigma_protocols import (SigmaError, image, linear_map, parse_statement,
                             batch_verify, prove_batchable, prove_compact,
                             validate_instance, verify_batchable,
                             verify_compact)

VECTOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "vectors")

HASHES = {"SHAKE128": hashlib.shake_128, "TurboSHAKE128": TurboSHAKE128}

SUITES = {
    "sigma-proofs_Shake128_P256": ("p256", P256Group()),
    "sigma-proofs_Shake128_BLS12381": ("bls12381", BLSG1Group()),
}

# Named fields whose modulus a record may carry; pinned so a vector file
# cannot silently drift from the group it claims.
GROUP_MODULI = {
    "P-256": P256Group().order,
    "Mersenne31": sumcheck.P,
}

_checks = 0


def check(cond, what):
    global _checks
    _checks += 1
    if not cond:
        raise AssertionError(what)


def to_int(v):
    """Integers are JSON numbers when small and 0x-prefixed strings when
    field-sized (the format paragraph of the Test Vectors appendix)."""
    return v if isinstance(v, int) else int(v, 16)


# --- The seeded PRNG of the sigma draft's appendix ({{seeded-prng}}) --------

FLAVOR_MARKERS = {"batchable": "DSFS", "compact": "CMPT"}


def testdrng_tag(suite, name, flavor=None):
    """The PRNG tag of one of a vector's streams: the instance/witness
    stream has no flavor component; each flavor's nonce stream carries its
    flavor marker."""
    marker = f"{FLAVOR_MARKERS[flavor]}-" if flavor else ""
    return f"TestDRNG-SIGMA-PROOFS-{marker}{suite}-{name}".encode("ascii")


class TestDRNG:
    """random_scalar() = DecodeField(Squeeze(Ns + 16), p, 1) on a SHAKE128
    duplex sponge initialized with DeriveSessionID of the stream's PRNG
    tag. Test-only: applications MUST NOT use a deterministic RNG; prover
    randomness MUST be seeded from OS entropy."""

    def __init__(self, group, suite, name, flavor=None):
        self.group = group
        self.ds = DuplexSponge(derive_session_id(testdrng_tag(suite, name,
                                                              flavor)))

    def random_scalar(self):
        return decode_uint(self.ds.squeeze(self.group.Ns + 16),
                           self.group.order)


# --- Fiat-Shamir vectors ----------------------------------------------------

def replay_operations(session_id, operations, new_ctx):
    """Run an `Operations` trace; return the concatenated squeezed bytes."""
    sponge = DuplexSponge(session_id, new_ctx)
    out = bytearray()
    for op in operations:
        if op["type"] == "absorb":
            sponge.absorb(bytes.fromhex(op["data"]))
        else:
            out += sponge.squeeze(op["length"])
    return bytes(out)


def check_fiat_shamir_record(rec):
    rid = rec["Id"]
    fn = rec["Function"]
    # A record names its hash suite; the codec records are hash-independent
    # and any sponge they reach (the sumcheck rejections) must reject under
    # both instantiations.
    ctxs = [HASHES[rec["Hash"]]] if "Hash" in rec else list(HASHES.values())
    if "Group" in rec:
        check(to_int(rec["Modulus"]) == GROUP_MODULI[rec["Group"]],
              f"{rid}: Modulus does not match {rec['Group']}")

    if fn == "DuplexSponge":
        out = replay_operations(bytes.fromhex(rec["SessionId"]),
                                rec["Operations"], ctxs[0])
        check(out.hex() == rec["Output"], f"{rid}: sponge output")
    elif fn == "DeriveSessionID":
        sid = derive_session_id(bytes.fromhex(rec["Tag"]), ctxs[0])
        check(sid.hex() == rec["Output"], f"{rid}: session id")
    elif fn == "DecodeUint":
        p = to_int(rec["Modulus"])
        if "Operations" in rec:
            out = replay_operations(bytes.fromhex(rec["SessionId"]),
                                    rec["Operations"], ctxs[0])
            check(out.hex() == rec["Output"], f"{rid}: squeezed bytes")
            buf = out
        else:
            buf = bytes.fromhex(rec["Input"])
        check(decode_uint(buf, p) == to_int(rec["Challenge"]),
              f"{rid}: decoded challenge")
    elif fn == "SerializeVarLenString":
        payload = bytes.fromhex(rec["Input"])
        out = serialize_varlen(payload)
        check(out.hex() == rec["Output"], f"{rid}: serialization")
        check(deserialize_varlen(out) == (payload, b""), f"{rid}: roundtrip")
    elif fn == "SerializeUint":
        p = to_int(rec["Modulus"])
        out = serialize_uint(to_int(rec["Value"]), p)
        check(out.hex() == rec["Output"], f"{rid}: serialization")
        check(deserialize_uint(out, p) == (to_int(rec["Value"]), b""),
              f"{rid}: roundtrip")
    elif fn == "SerializeField":
        check(rec["ByteOrder"] == "big-endian", f"{rid}: unexpected codec")
        out = serialize_field_be((to_int(rec["Value"]),),
                                 to_int(rec["Modulus"]), 1)
        check(out.hex() == rec["Output"], f"{rid}: big-endian serialization")
    elif fn == "DeserializeUint":
        check(rec["Expected"] == "reject", f"{rid}: only rejects pinned")
        try:
            deserialize_uint(bytes.fromhex(rec["Input"]),
                             to_int(rec["Modulus"]))
            check(False, f"{rid}: must reject")
        except Reject:
            check(True, rid)
    elif fn == "DeserializeVarLenString":
        check(rec["Expected"] == "reject", f"{rid}: only rejects pinned")
        try:
            deserialize_varlen(bytes.fromhex(rec["Input"]))
            check(False, f"{rid}: must reject")
        except Reject:
            check(True, rid)
    elif fn == "DeserializeField":
        p, m = to_int(rec["Modulus"]), rec["ExtensionDegree"]
        buf = bytes.fromhex(rec["Input"])
        if rec.get("Expected") == "reject":
            try:
                deserialize_field(buf, p, m)
                check(False, f"{rid}: must reject")
            except Reject:
                check(True, rid)
        else:
            coords, rest = deserialize_field(buf, p, m)
            check(rest == b"", f"{rid}: trailing bytes")
            check(list(coords) == [to_int(c) for c in rec["Coordinates"]],
                  f"{rid}: coordinates")
    elif fn == "Sumcheck":
        rounds = rec["NumVariables"]
        claimed = to_int(rec["ClaimedSum"])
        narg = bytes.fromhex(rec["Narg"])
        for new_ctx in ctxs:
            sid = bytes.fromhex(rec["SessionId"])
            if "Tag" in rec:
                check(derive_session_id(bytes.fromhex(rec["Tag"]),
                                        new_ctx) == sid,
                      f"{rid}: session id")
            if rec.get("Expected") == "reject":
                ok, _, _ = sumcheck.verify(sid, claimed, narg, rounds,
                                           new_ctx)
                check(not ok, f"{rid}: must reject")
                continue
            witness = [to_int(w) for w in rec["Witness"]]
            check(sum(witness) % sumcheck.P == claimed, f"{rid}: claimed sum")
            messages, challenges, final = sumcheck.prove(sid, witness,
                                                         new_ctx)
            check(b"".join(messages) == narg, f"{rid}: NARG regeneration")
            check(final == to_int(rec["FinalEvaluation"]),
                  f"{rid}: final evaluation")
            check(final == sumcheck.multilinear_eval(witness, challenges),
                  f"{rid}: multilinear extension")
            ok, ch, fin = sumcheck.verify(sid, claimed, narg, rounds,
                                          new_ctx)
            check(ok and ch == challenges and fin == final,
                  f"{rid}: verifier")
    else:
        check(False, f"{rid}: unknown Function {fn}")


# --- Sigma-protocols vectors ------------------------------------------------

def sigma_verify(group, flavor, tag, statement, narg_string):
    """Run the full verifier over serialized inputs; True on acceptance,
    False on any of the draft's rejection points."""
    try:
        inst = parse_statement(group, statement)
        if flavor == "batchable":
            return verify_batchable(tag, inst, narg_string)
        return verify_compact(tag, inst, narg_string)
    except (SigmaError, DeserializeError):
        return False


def check_sigma_valid(suite, records):
    short, group = SUITES[suite]
    for rec in records:
        rid = rec["Id"]
        relation, flavor = rec["Relation"], rec["Flavor"]
        check(rid == f"sigma-protocols/{short}/{relation}/{flavor}",
              f"{rid}: Id components")
        check(rec["Function"] == "SigmaProof" and rec["Expected"] == "accept"
              and rec["Ciphersuite"] == suite, f"{rid}: header fields")
        tag = rec["Tag"].encode()
        check(derive_session_id(tag).hex() == rec["SessionId"],
              f"{rid}: session id")
        inst = parse_statement(group, bytes.fromhex(rec["Instance"]))
        check(validate_instance(inst), f"{rid}: instance validation")
        witness = group.scalar_deserialize(bytes.fromhex(rec["Witness"]))
        check(linear_map(inst, witness) == image(inst),
              f"{rid}: witness satisfaction")
        # Regenerate the proof from the pinned nonce stream: the NARG string
        # is reproducible from this document alone, not merely verifiable.
        rng = TestDRNG(group, suite, relation, flavor)
        prove = prove_batchable if flavor == "batchable" else prove_compact
        check(prove(tag, inst, witness, rng).hex() == rec["NargString"],
              f"{rid}: proof regeneration")
        check(sigma_verify(group, flavor, tag,
                           bytes.fromhex(rec["Instance"]),
                           bytes.fromhex(rec["NargString"])),
              f"{rid}: verifier acceptance")


def check_sigma_invalid(suite, records, valid_ids):
    _, group = SUITES[suite]
    for rec in records:
        rid = rec["Id"]
        check(rec["Function"] == "SigmaProof" and rec["Ciphersuite"] == suite,
              f"{rid}: header fields")
        accepted = sigma_verify(group, rec["Flavor"], rec["Tag"].encode(),
                                bytes.fromhex(rec["Instance"]),
                                bytes.fromhex(rec["NargString"]))
        if rec["Expected"] == "accept":
            check(accepted, f"{rid}: baseline must verify")
            check("BaseId" not in rec, f"{rid}: baselines carry no BaseId")
        else:
            check(not accepted, f"{rid}: must reject")
            check(rec["BaseId"] in valid_ids,
                  f"{rid}: BaseId names no valid vector")


def check_sigma_batch(suite, valid, invalid):
    """The appendix claim on batch verification, over the pinned vectors."""
    _, group = SUITES[suite]
    batchable = [rec for rec in valid if rec["Flavor"] == "batchable"]
    sids = [derive_session_id(rec["Tag"].encode()) for rec in batchable]
    insts = [parse_statement(group, bytes.fromhex(rec["Instance"]))
             for rec in batchable]
    nargs = [bytes.fromhex(rec["NargString"]) for rec in batchable]
    n = len(batchable)
    subsets = ([[]] + [[i] for i in range(n)]
               + [[i, j] for i in range(n) for j in range(i + 1, n)]
               + [list(range(n))])
    for idx in subsets:
        check(batch_verify(group, [sids[i] for i in idx],
                           [insts[i] for i in idx],
                           [nargs[i] for i in idx]),
              f"{suite}: valid batch {idx} must verify")
    for rec in invalid:
        if rec["Flavor"] != "batchable" or rec["Expected"] != "reject":
            continue
        try:
            rejected = not batch_verify(
                group,
                sids[:1] + [derive_session_id(rec["Tag"].encode())],
                insts[:1] + [parse_statement(group,
                                             bytes.fromhex(rec["Instance"]))],
                nargs[:1] + [bytes.fromhex(rec["NargString"])])
        except (SigmaError, DeserializeError):
            rejected = True
        check(rejected, f"{rec['Id']}: batch containing it must be rejected")


# --- The vectors inlined in the drafts --------------------------------------
#
# The Test Vectors appendices carry the same records as the JSON files,
# rendered by the grammar of the appendix format paragraph: `Key = value`
# lines, values indented under their key when long (continuation lines
# joined with no separator), and sequences one `- ` item per line. The
# drafts are hand-maintained, so this cross-check is what keeps the two
# forms from drifting apart.

# The vector files inlined in each draft, in order of appearance.
DRAFT_APPENDICES = {
    "draft-irtf-cfrg-fiat-shamir.md": (
        "fiatShamirCodecVectors",
        "fiatShamirShake128Vectors",
        "fiatShamirTurboShake128Vectors",
    ),
    "draft-irtf-cfrg-sigma-protocols.md": (
        "sigma-proofs_Shake128_P256",
        "sigma-proofs-invalid_Shake128_P256",
        "sigma-proofs_Shake128_BLS12381",
        "sigma-proofs-invalid_Shake128_BLS12381",
    ),
}

# Fields rendered as prose around the fenced block (or dropped) rather
# than as `Key = value` lines inside it.
PROSE_FIELDS = {"Name", "Title", "Comment", "Group"}


def parse_markdown_vectors(path):
    """Every fenced block in a draft whose first line carries an `Id`,
    parsed back into records."""
    records = []
    fence = None
    with open(path) as fh:
        for line in fh.read().split("\n"):
            if line.startswith("~~~"):  # a fence, possibly `~~~ language`
                if fence is None:
                    fence = []
                else:
                    if fence and fence[0].startswith("Id ="):
                        records.append(parse_vector_block(fence))
                    fence = None
                continue
            if fence is not None:
                fence.append(line)
    return records


def parse_vector_block(lines):
    rec = {}
    key = None
    for line in lines:
        if line.startswith("  - "):            # sequence item
            if rec[key] is None:
                rec[key] = []
            rec[key].append(line[4:])
        elif line.startswith("    "):          # sequence-item continuation
            rec[key][-1] += line[4:]
        elif line.startswith("  "):            # value continuation
            if rec[key] is None:
                rec[key] = ""
            rec[key] += line[2:]
        elif " = " in line:
            key, _, value = line.partition(" = ")
            rec[key] = value
        else:                                  # `Key =` opens a block value
            assert line.endswith(" ="), line
            key = line[:-2]
            rec[key] = None
    return rec


def render_operation(op):
    """One `Operations` item as the drafts render it."""
    if op["type"] == "absorb":
        return "absorb " + (op["data"] or '""')
    return f"squeeze {op['length']}"


def rendered_record(rec):
    """The `Key = value` form of a JSON record: `Id` first, prose fields
    dropped, every remaining value a string."""
    out = {"Id": rec["Id"]}
    for key, value in rec.items():
        if key == "Id" or key in PROSE_FIELDS:
            continue
        if key == "Operations":
            out[key] = [render_operation(op) for op in value]
        elif isinstance(value, list):
            out[key] = [str(x) for x in value]
        else:
            out[key] = str(value) or '""'
    return out


def check_markdown_vectors():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for draft, stems in DRAFT_APPENDICES.items():
        expected = [rendered_record(rec) for stem in stems
                    for rec in load(stem)]
        got = parse_markdown_vectors(os.path.join(root, draft))
        check(len(got) == len(expected),
              f"{draft}: {len(got)} vectors inlined, {len(expected)} in JSON")
        for want, have in zip(expected, got):
            check(list(have.items()) == list(want.items()),
                  f"{draft}: {want['Id']} diverges from its JSON record")
        print(f"{draft}: {len(got)} inlined vectors match the JSON")


# --- Driver -----------------------------------------------------------------

def load(stem):
    with open(os.path.join(VECTOR_DIR, stem + ".json")) as fh:
        return json.load(fh)


def main():
    for stem in ("fiatShamirCodecVectors", "fiatShamirShake128Vectors",
                 "fiatShamirTurboShake128Vectors"):
        before = _checks
        for rec in load(stem):
            check_fiat_shamir_record(rec)
        print(f"{stem}: {_checks - before} checks")

    for suite, (short, _) in SUITES.items():
        before = _checks
        valid = load(suite)
        invalid = load(f"sigma-proofs-invalid_{suite.removeprefix('sigma-proofs_')}")
        check_sigma_valid(suite, valid)
        check_sigma_invalid(suite, invalid, {rec["Id"] for rec in valid})
        check_sigma_batch(suite, valid, invalid)
        print(f"{suite}: {_checks - before} checks")

    check_markdown_vectors()
    print(f"all {_checks} checks passed")


if __name__ == "__main__":
    main()
