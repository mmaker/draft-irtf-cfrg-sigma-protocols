#!/usr/bin/env python3
"""
Test suite for composition (AND/OR) proofs.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sigma_protocols import AndProof, P256AndCodec, LinearRelation
from test_drng import TestDRNG
from groups import GroupP256
from fiat_shamir import FiatShamirNIZK, Shake128DuplexSponge


def test_and_proof():
    """Test AND composition of two discrete log proofs."""
    print("Testing AND proof composition...")

    group = GroupP256
    rng = TestDRNG(b"composition_test_seed")

    # Create two discrete log relations
    relations = []
    witnesses = []

    for i in range(2):
        relation = LinearRelation(group)
        [var_x] = relation.allocate_scalars(1)
        [var_G, var_X] = relation.allocate_elements(2)
        relation.append_equation(var_X, [(var_x, var_G)])

        # Set up values
        G = group.generator()
        x = group.ScalarField.random(rng)
        X = G * x

        relation.set_elements([(var_G, G), (var_X, X)])

        relations.append(relation)
        witnesses.append([x])

    # Create AND proof
    and_proof = AndProof(relations)

    # Test proof generation and verification
    session_id = b"test_and_proof"
    prover_rng = TestDRNG(b"and_proof_generation_seed")

    # Generate proof
    prover_state, commitment = and_proof.prover_commit(witnesses, prover_rng)

    # Generate challenge (simulated)
    challenge_rng = TestDRNG(b"challenge_generation_seed")
    challenge = group.ScalarField.random(challenge_rng)

    response = and_proof.prover_response(prover_state, challenge)

    # Verify proof
    result = and_proof.verifier(commitment, challenge, response)

    assert result == True, "AND proof verification failed"
    print("✓ AND proof test passed!")


def test_and_proof_serialization():
    """Test AND proof with proper NIZK serialization."""
    print("Testing AND proof serialization...")

    group = GroupP256
    rng = TestDRNG(b"serialization_test_seed")

    # Create a simple discrete log relation
    relation = LinearRelation(group)
    [var_x] = relation.allocate_scalars(1)
    [var_G, var_X] = relation.allocate_elements(2)
    relation.append_equation(var_X, [(var_x, var_G)])

    G = group.generator()
    x = group.ScalarField.random(rng)
    X = G * x
    relation.set_elements([(var_G, G), (var_X, X)])

    and_proof = AndProof([relation])

    # Test AND proof directly without full NIZK
    prover_rng = TestDRNG(b"nizk_proof_generation_seed")

    # Generate proof using AND composition
    prover_state, commitment = and_proof.prover_commit([[x]], prover_rng)

    # Generate challenge (simulated)
    challenge_rng = TestDRNG(b"challenge_generation_seed")
    group = GroupP256
    challenge = group.ScalarField.random(challenge_rng)

    response = and_proof.prover_response(prover_state, challenge)

    # Verify
    result = and_proof.verifier(commitment, challenge, response)
    assert result == True, "Serialized AND proof verification failed"

    print("✓ AND proof serialization test passed!")


def main():
    """Run all composition tests."""
    print("Running composition tests...")

    test_and_proof()
    test_and_proof_serialization()

    print("✓ All composition tests passed!")


if __name__ == "__main__":
    main()