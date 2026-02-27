#!/usr/bin/sage
# vim: syntax=python

from sagelib.ciphersuite import CIPHERSUITE
from sagelib.sigma_protocols import LinearRelation, CSRNG
from sagelib.test_drng import SeededPRNG

import json


def test_vector(test_vector_function):
    def inner(vectors, suite):
        INSTANCE_WITNESS_SEED = b"instance_witness_generation_seed"
        SESSION_ID = b"session_identifier"
        PROOF_CHAL_RESP_SEED = b"proving-method-challenge-response-format"
        PROOF_COMM_RESP_SEED = b"proving-method-commitment-response-format"

        test_vector_name = test_vector_function.__name__
        name = bytes(test_vector_name, "utf-8")

        NISigmaProtocol = CIPHERSUITE[suite]
        G = NISigmaProtocol.Codec.GG

        instance_witness_seed = INSTANCE_WITNESS_SEED + name
        instance_witness_rng = SeededPRNG(instance_witness_seed, G.ScalarField)
        instance, witness = test_vector_function(instance_witness_rng, G)

        session_id = SESSION_ID + name
        hash_name = NISigmaProtocol(session_id, instance).hash_state.__class__.__name__

        proof_chal_resp_seed = PROOF_CHAL_RESP_SEED + name
        proof_chal_resp_rng = SeededPRNG(proof_chal_resp_seed, G.ScalarField, tracing_enabled=True)
        proof_chal_resp = NISigmaProtocol(session_id, instance).prove(witness, proof_chal_resp_rng)
        assert NISigmaProtocol(session_id, instance).verify(proof_chal_resp)

        proof_comm_resp_seed = PROOF_COMM_RESP_SEED + name
        proof_comm_resp_rng = SeededPRNG(proof_comm_resp_seed, G.ScalarField, tracing_enabled=True)
        proof_comm_resp = NISigmaProtocol(session_id, instance).prove_batchable(witness, proof_comm_resp_rng)
        assert NISigmaProtocol(session_id, instance).verify_batchable(proof_comm_resp)

        print(f"{test_vector_name} test vectors generated\n")

        scalars_to_hex = lambda v: list(map(lambda x: G.ScalarField._serialize(x).hex(), v))
        vectors.append({
            "protocol": test_vector_name,
            "ciphersuite": suite,
            "hash": hash_name,
            "session_id": session_id.hex(),
            "statement": instance.get_label().hex(),
            "witness": scalars_to_hex(witness),
            "randomness_chal_resp": scalars_to_hex(proof_chal_resp_rng.sampled_scalars),
            "proof_chal_resp": proof_chal_resp.hex(),
            "randomness_comm_resp": scalars_to_hex(proof_comm_resp_rng.sampled_scalars),
            "proof_comm_resp": proof_comm_resp.hex(),
        })

    return inner


def wrap_write(fh, *args):
    assert args
    line_length = 68
    string = " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")


def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)


def write_group_vectors(fh, label, vector):
    print("## ", label, file=fh)
    print("~~~", file=fh)
    for key, value in vector.items():
        if isinstance(value, list):
            for i, vi in enumerate(value):
                write_value(fh, f"{key}_{i}", vi)
        else:
            write_value(fh, key, value)
    print("~~~", file=fh, end="\n\n")


@test_vector
def discrete_logarithm(rng: CSRNG, group):
    """
    Proves the following statement:

        DL(X) = PoK{(x): X = x * G}

    """

    statement = LinearRelation(group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X] = statement.allocate_elements(2)
    statement.append_equation(var_X, [(var_x, var_G)])

    G = group.generator()
    statement.set_elements([(var_G, G)])

    x = rng.random_scalar()
    X = group.scalar_mult(x, G)
    assert [X] == statement.linear_map([x])

    statement.set_elements([(var_X, X)])
    return statement, [x]


@test_vector
def dleq(rng: CSRNG, group):
    """
    Proves the following statement:

        DLEQ(G, H, X, Y) = PoK{(x): X = x * G, Y = x * H}

    """
    G = group.generator()
    H = group.scalar_mult(rng.random_scalar(), G)
    x = rng.random_scalar()
    X = group.scalar_mult(x, G)
    Y = group.scalar_mult(x, H)

    statement = LinearRelation(group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X, var_H, var_Y] = statement.allocate_elements(4)
    statement.set_elements([(var_G, G), (var_H, H), (var_X, X), (var_Y, Y)])
    statement.append_equation(var_X, [(var_x, var_G)])
    statement.append_equation(var_Y, [(var_x, var_H)])

    assert [X, Y] == statement.linear_map([x])
    return statement, [x]


@test_vector
def pedersen_commitment(rng: CSRNG, group):
    """
    Proves the following statement:

        PEDERSEN(G, H, C) = PoK{(x, r): C = x * G + r * H}

    """
    G = group.generator()
    H = group.scalar_mult(rng.random_scalar(), G)
    x = rng.random_scalar()
    r = rng.random_scalar()
    witness = [x, r]

    C = group.scalar_mult(x, G) + group.scalar_mult(r, H)
    statement = LinearRelation(group)
    [var_x, var_r] = statement.allocate_scalars(2)
    [var_G, var_H, var_C] = statement.allocate_elements(3)
    statement.set_elements([(var_G, G), (var_H, H), (var_C, C)])
    statement.append_equation(var_C, [(var_x, var_G), (var_r, var_H)])

    return statement, witness


@test_vector
def pedersen_commitment_dleq(rng: CSRNG, group):
    """
    Proves the following statement:

        PEDERSEN(G0, G1, G2, G3, X, Y) =
            PoK{
              (x0, x1):
                X = x0 * G0  + x1 * G1,
                Y = x0 * G2 + x1 * G3
            }
    """
    G = group.generator()
    generators = [group.scalar_mult(rng.random_scalar(), G) for i in range(4)]
    witness = [rng.random_scalar() for i in range(2)]
    X = group.msm(witness, generators[:2])
    Y = group.msm(witness, generators[2:4])

    statement = LinearRelation(group)
    [var_x, var_r] = statement.allocate_scalars(2)
    [var_G0, var_G1, var_X, var_G2, var_G3, var_Y] = statement.allocate_elements(6)

    statement.set_elements([(var_G0, generators[0]), (var_G1, generators[1]),
                           (var_G2, generators[2]), (var_G3, generators[3]),
                           (var_X, X), (var_Y, Y)])

    statement.append_equation(var_X, [(var_x, var_G0), (var_r, var_G1)])
    statement.append_equation(var_Y, [(var_x, var_G2), (var_r, var_G3)])
    return statement, witness


@test_vector
def bbs_blind_commitment_computation(rng: CSRNG, group):
    """
    This example test vector is meant to replace:
    https://www.ietf.org/archive/id/draft-kalos-bbs-blind-signatures-01.html#section-4.1.1

    Proves the following statement:
        PoK{
        (secret_prover_blind, msg_1, ..., msg_M):
            C = secret_prover_blind * Q_2 + msg_1 * J_1 + ... + msg_M * J_M
        }
    """
    G = group.generator()
    # length(committed_messages)
    M = 3
    # BBS.create_generators(M + 1, "BLIND_" || api_id)
    (Q_2, J_1, J_2, J_3) = [group.scalar_mult(rng.random_scalar(), G) for i in range(M+1)]
    # BBS.messages_to_scalars(committed_messages,  api_id)
    (msg_1, msg_2, msg_3) = [rng.random_scalar() for i in range(M)]

    # these are computed before the proof in the specification
    secret_prover_blind = rng.random_scalar()
    C = group.scalar_mult(secret_prover_blind, Q_2) + \
        group.scalar_mult(msg_1, J_1) + \
        group.scalar_mult(msg_2, J_2) + \
        group.scalar_mult(msg_3, J_3)

    # This is the part that needs to be changed in the specification of blind bbs.
    statement = LinearRelation(group)
    [var_secret_prover_blind, var_msg_1, var_msg_2,
        var_msg_3] = statement.allocate_scalars(M+1)
    [var_Q_2, var_J_1, var_J_2, var_J_3] = statement.allocate_elements(M+1)
    [var_C] = statement.allocate_elements(1)
    statement.set_elements([(var_Q_2, Q_2),
                            (var_J_1, J_1),
                            (var_J_2, J_2),
                            (var_J_3, J_3),
                            (var_C, C)
                            ])

    statement.append_equation(
        var_C, [
            (var_secret_prover_blind, var_Q_2),
            (var_msg_1, var_J_1),
            (var_msg_2, var_J_2),
            (var_msg_3, var_J_3)
        ]
    )

    witness = [secret_prover_blind, msg_1, msg_2, msg_3]
    return statement, witness


def main(path="vectors"):
    # Run the short proof serialization test first

    test_vectors = [
        discrete_logarithm,
        dleq,
        pedersen_commitment,
        pedersen_commitment_dleq,
        bbs_blind_commitment_computation,
    ]

    print("Generating sigma protocol test vectors...\n")

    for suite in CIPHERSUITE:
        vectors = []
        for test_vector in test_vectors:
            test_vector(vectors, suite)

        filename = f"{path}/{suite}"
        with open(f"{filename}.json", 'wt') as f:
            json.dump(vectors, f, sort_keys=False, indent=2)
        print(f"Test vectors written to {filename}.json")

        with open(f"{filename}.txt", 'wt') as f:
            for v in vectors:
                write_group_vectors(f, v["protocol"], v)
        print(f"Test vectors written to {filename}.txt")

if __name__ == "__main__":
    main()
