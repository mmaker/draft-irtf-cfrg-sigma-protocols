"""The sumcheck protocol of the Fiat-Shamir draft's example appendix.

The example protocol ({{example-sumcheck}}), implemented verbatim over the
Mersenne31 field: SumcheckProve and SumcheckVerify below follow the
numbered pseudocode steps. The application context enters through the
session identifier; the instance (v, S) is absorbed as encode[0] =
SerializeUint(v, 2^32) || SerializeField(S, p, 1); each round absorbs the
coefficient pair (a_0, a_1) of the round polynomial and decodes one
challenge as LE2IP(Squeeze(Ns)) mod p -- the alternative small-field
decoding the draft's decoding section permits, in place of the default
Ns + 16 oversampling (bias ~2^-31, below the ~2^-29 soundness error of
the interactive argument).

Standard library only; not constant-time; not intended for production.
"""

import hashlib

from fiat_shamir import DuplexSponge, Reject, deserialize_field, serialize_field

P = 2 ** 31 - 1  # the Mersenne31 prime
NS = 4           # its serialization width Ns


def instance_encoding(v, s):
    """encode[0] of the example protocol: the number of variables as
    SerializeUint(v, 2^32), then the claimed sum."""
    return v.to_bytes(4, "little") + serialize_field((s,), P, 1)


def round_message(w):
    """The round polynomial g(X) = a_0 + a_1 X of the lowest variable, as
    its coefficients: g(0) and g(1) are the even/odd half-sums of the table."""
    g0 = sum(w[0::2]) % P
    g1 = sum(w[1::2]) % P
    return g0, (g1 - g0) % P


def fold(w, r):
    """Bind the lowest variable to r: entry j becomes the line through
    (0, w[2j]) and (1, w[2j+1]) evaluated at r. Halves the table."""
    return [(w[2 * j] + r * (w[2 * j + 1] - w[2 * j])) % P
            for j in range(len(w) // 2)]


def multilinear_eval(w, rs):
    """Direct evaluation of the multilinear extension of w at rs, from the
    Lagrange basis on the hypercube; independently validates the even/odd
    convention (bit k of the index pairs with challenge rs[k])."""
    acc = 0
    for j, wj in enumerate(w):
        term = wj
        for k, r in enumerate(rs):
            term = term * ((r if (j >> k) & 1 else 1 - r) % P) % P
        acc = (acc + term) % P
    return acc


def prove(session_id, witness, new_ctx=hashlib.shake_128):
    """SumcheckProve: returns (round messages, challenges, final evaluation).
    The claimed sum is absorbed internally (step 1 of the pseudocode) and
    recomputed from the witness."""
    v = (len(witness) - 1).bit_length()
    assert len(witness) == 1 << v
    sponge = DuplexSponge(session_id, new_ctx)
    claimed = sum(witness) % P
    sponge.absorb(instance_encoding(v, claimed))
    w = list(witness)
    messages, challenges = [], []
    while len(w) > 1:
        a0, a1 = round_message(w)
        msg = serialize_field((a0, a1), P, 2)
        sponge.absorb(msg)  # prover message: absorbed == serialized
        r = int.from_bytes(sponge.squeeze(NS), "little") % P
        w = fold(w, r)
        messages.append(msg)
        challenges.append(r)
    return messages, challenges, w[0]


def verify(session_id, claimed, narg, rounds, new_ctx=hashlib.shake_128):
    """SumcheckVerify: returns (accepted, challenges, final claim); shares
    no prover state. Rejection of a malformed round message fires during
    deserialization, before any byte is squeezed; trailing bytes are
    rejected only after the last round (step 9)."""
    sponge = DuplexSponge(session_id, new_ctx)
    sponge.absorb(instance_encoding(rounds, claimed))
    current, challenges = claimed, []
    try:
        for _ in range(rounds):
            (a0, a1), narg = deserialize_field(narg, P, 2)
            if (2 * a0 + a1) % P != current:  # g(0) + g(1) == current claim
                return False, None, None
            sponge.absorb(serialize_field((a0, a1), P, 2))
            r = int.from_bytes(sponge.squeeze(NS), "little") % P
            current = (a0 + a1 * r) % P  # reduce the claim to g(r)
            challenges.append(r)
        if narg != b"":  # trailing bytes are rejected
            raise Reject
    except Reject:
        return False, None, None
    return True, challenges, current


if __name__ == "__main__":
    from keccak import TurboSHAKE128

    witness = [1 << i for i in range(16)]  # v = 4 variables, sum 65535
    for new_ctx in (hashlib.shake_128, TurboSHAKE128):
        sid = bytes(32)
        messages, challenges, final = prove(sid, witness, new_ctx)
        assert final == multilinear_eval(witness, challenges)
        ok, ch, fin = verify(sid, sum(witness) % P, b"".join(messages), 4,
                             new_ctx)
        assert ok and ch == challenges and fin == final
        ok, _, _ = verify(sid, sum(witness) % P,
                          b"".join(messages) + b"\x00", 4, new_ctx)
        assert not ok, "trailing bytes must be rejected"
    print("sumcheck: ok")
