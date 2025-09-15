#!/usr/bin/env python3
"""
Pure Python test suite for Sigma protocols.
Tests P-256 and Ristretto255 groups.
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sigma_protocols import CIPHERSUITE, LinearRelation
from test_drng import TestDRNG


def test_vector(test_vector_function):
    """Decorator for test vector generation."""
    def inner(vectors, suite):
        NIZK = CIPHERSUITE[suite]
        instance_witness_rng = TestDRNG(b"instance_witness_generation_seed")
        proof_generation_rng = TestDRNG(b"proof_generation_seed")

        test_vector_name = f"{test_vector_function.__name__}"

        # Extract group from ciphersuite
        group = NIZK.Codec.GG

        instance, witness = test_vector_function(instance_witness_rng, group)

        session_id = test_vector_name.encode('utf-8')
        narg_string = NIZK(session_id, instance).prove(witness, proof_generation_rng)
        assert NIZK(session_id, instance).verify(narg_string)
        hex_narg_string = narg_string.hex()
        print(f"{test_vector_name} test vector generated for {suite}")

        # Serialize witness
        witness_bytes = NIZK.Codec.GG.ScalarField.serialize(witness)

        vectors[f"{test_vector_name}_{suite}"] = {
            "Ciphersuite": suite,
            "SessionId": session_id.hex(),
            "Statement": instance.get_label().hex(),
            "Witness": witness_bytes.hex(),
            "Proof": hex_narg_string,
        }
    return inner


@test_vector
def discrete_logarithm(rng, group):
    """Generate test vector for discrete logarithm proof."""
    G = group.generator()
    x = group.ScalarField.random(rng)
    X = G * x

    statement = LinearRelation(group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X] = statement.allocate_elements(2)
    statement.append_equation(var_X, [(var_x, var_G)])
    statement.set_elements([(var_G, G), (var_X, X)])

    return statement, [x]


@test_vector
def dleq(rng, group):
    """Generate test vector for discrete logarithm equality proof."""
    G = group.generator()
    H = group.random(rng)
    x = group.ScalarField.random(rng)
    X = G * x
    Y = H * x

    statement = LinearRelation(group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X, var_H, var_Y] = statement.allocate_elements(4)
    statement.append_equation(var_X, [(var_x, var_G)])
    statement.append_equation(var_Y, [(var_x, var_H)])
    statement.set_elements([(var_G, G), (var_X, X), (var_H, H), (var_Y, Y)])

    return statement, [x]


@test_vector
def pedersen_commitment(rng, group):
    """Generate test vector for Pedersen commitment proof."""
    G = group.generator()
    H = group.random(rng)
    x = group.ScalarField.random(rng)
    r = group.ScalarField.random(rng)
    witness = [x, r]

    C = G * x + H * r

    statement = LinearRelation(group)
    [var_x, var_r] = statement.allocate_scalars(2)
    [var_G, var_H, var_C] = statement.allocate_elements(3)
    statement.append_equation(var_C, [(var_x, var_G), (var_r, var_H)])
    statement.set_elements([(var_G, G), (var_H, H), (var_C, C)])

    return statement, witness


def main():
    """Generate all test vectors."""
    print("Generating sigma protocol test vectors...")

    vectors = {}

    suites = ["P256_SHAKE128", "P256_KECCAK256"]

    for suite in suites:
        discrete_logarithm(vectors, suite)
        dleq(vectors, suite)
        pedersen_commitment(vectors, suite)

    # Write vectors to files
    os.makedirs("vectors", exist_ok=True)

    with open("vectors/testSigmaProtocols.json", "w") as f:
        json.dump(vectors, f, indent=2)

    # Also write in text format
    with open("vectors/testSigmaProtocols.txt", "w") as f:
        for test_name, data in vectors.items():
            protocol_name = test_name.rsplit('_', 1)[0]
            suite = data["Ciphersuite"]
            f.write(f"## {protocol_name}_{suite}\n")
            f.write("~~~\n")
            f.write(f"Ciphersuite = {data['Ciphersuite']}\n")
            f.write(f"SessionId = {data['SessionId']}\n")
            f.write(f"Statement = {data['Statement']}\n")
            f.write(f"Witness = {data['Witness']}\n")
            f.write(f"Proof = \n")
            # Split proof into lines of 64 characters
            proof = data['Proof']
            for i in range(0, len(proof), 64):
                f.write(f"    {proof[i:i+64]}\n")
            f.write("~~~\n\n")

    print("Test vectors written to vectors/")
    print("✓ All tests passed!")


if __name__ == "__main__":
    main()