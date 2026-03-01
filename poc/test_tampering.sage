#!/usr/bin/sage
# vim: syntax=python

"""
Negative test to demonstrate the challenge-response format vulnerability.
This test creates a proof, tampers with public statement elements, and checks
if the tampered proof incorrectly verifies.
"""

import sys
import os

from sagelib.ciphersuite import NISchnorrProofShake128P256
from sagelib.sigma_protocols import LinearRelation
from sagelib.test_drng import TestDRNG


def test_tampered_statement_challenge_response():
    """
    Test that tampering with public statement elements causes verification to fail.

    This is a NEGATIVE test - with the tampering vulnerability, the test will FAIL
    because tampered proofs incorrectly verify. With it fixed, the test will PASS.
    """
    print("Test: Tampered statement with challenge-response format...")

    # Setup: Create a simple discrete log proof
    # Prove: X = x * G for secret x
    G_group = NISchnorrProofShake128P256.Codec.GG

    # Create original statement
    statement = LinearRelation(G_group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X] = statement.allocate_elements(2)
    statement.append_equation(var_X, [(var_x, var_G)])

    gen_G = G_group.generator()
    secret_x = G_group.ScalarField.field(42)
    public_X = G_group.scalar_mult(secret_x, gen_G)
    statement.set_elements([(var_G, gen_G), (var_X, public_X)])

    # Generate proof with original statement
    session_id = b"test_tampering"
    rng = TestDRNG(b"test_seed" + b"\x00" * 23)
    prover = NISchnorrProofShake128P256(session_id, statement)
    witness = [secret_x]
    proof = prover.prove(witness, rng)

    # Verify with original statement (should pass)
    verifier_original = NISchnorrProofShake128P256(session_id, statement)
    result_original = verifier_original.verify(proof)
    if not result_original:
        print("  ERROR: Original proof should verify!")
        return False
    print("  ✓ Original proof verifies correctly")

    # Now create a TAMPERED statement with different X value
    tampered_statement = LinearRelation(G_group)
    [var_x_t] = tampered_statement.allocate_scalars(1)
    [var_G_t, var_X_t] = tampered_statement.allocate_elements(2)
    tampered_statement.append_equation(var_X_t, [(var_x_t, var_G_t)])

    # Use same G but different X (tampered)
    tampered_X = G_group.scalar_mult(G_group.ScalarField.field(999), gen_G)
    tampered_statement.set_elements([(var_G_t, gen_G), (var_X_t, tampered_X)])

    # Try to verify original proof with tampered statement
    verifier_tampered = NISchnorrProofShake128P256(session_id, tampered_statement)

    try:
        result_tampered = verifier_tampered.verify(proof)

        if result_tampered:
            # VULNERABILITY: Proof verified with tampered statement!
            print("  ✗ VULNERABILITY: Proof verified with tampered X!")
            print("    Expected: Verification should FAIL")
            print("    Actual: Verification PASSED (incorrect)")
            return False
        else:
            # Fixed: Proof correctly rejected
            print("  ✓ FIXED: Proof correctly rejected with tampered X")
            return True
    except (AssertionError, Exception) as e:
        # Verification threw exception (also counts as rejection)
        print(f"  ✓ FIXED: Proof correctly rejected with tampered X (exception: {type(e).__name__})")
        return True

def test_tampered_statement_batchable():
    """
    Test that batchable format correctly rejects tampered statements.
    """
    print("\nTest: Tampered statement with batchable format (control)...")

    G_group = NISchnorrProofShake128P256.Codec.GG

    # Create original statement
    statement = LinearRelation(G_group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X] = statement.allocate_elements(2)
    statement.append_equation(var_X, [(var_x, var_G)])

    gen_G = G_group.generator()
    secret_x = G_group.ScalarField.field(42)
    public_X = G_group.scalar_mult(secret_x, gen_G)
    statement.set_elements([(var_G, gen_G), (var_X, public_X)])

    # Generate proof with original statement
    session_id = b"test_batchable"
    rng = TestDRNG(b"test_seed_batch" + b"\x00" * 17)
    prover = NISchnorrProofShake128P256(session_id, statement)
    witness = [secret_x]
    proof = prover.prove_batchable(witness, rng)

    # Verify with original statement (should pass)
    verifier_original = NISchnorrProofShake128P256(session_id, statement)
    result_original = verifier_original.verify_batchable(proof)
    if not result_original:
        print("  ERROR: Original proof should verify!")
        return False
    print("  ✓ Original proof verifies correctly")

    # Create tampered statement
    tampered_statement = LinearRelation(G_group)
    [var_x_t] = tampered_statement.allocate_scalars(1)
    [var_G_t, var_X_t] = tampered_statement.allocate_elements(2)
    tampered_statement.append_equation(var_X_t, [(var_x_t, var_G_t)])

    tampered_X = G_group.scalar_mult(G_group.ScalarField.field(999), gen_G)
    tampered_statement.set_elements([(var_G_t, gen_G), (var_X_t, tampered_X)])

    # Try to verify with tampered statement
    verifier_tampered = NISchnorrProofShake128P256(session_id, tampered_statement)

    try:
        result_tampered = verifier_tampered.verify_batchable(proof)

        if result_tampered:
            print("  ✗ FAILED: Batchable format should reject tampered statement!")
            return False
        else:
            print("  ✓ Batchable format correctly rejects tampered X")
            return True
    except (AssertionError, Exception) as e:
        print(f"  ✓ Batchable format correctly rejects tampered X (exception: {type(e).__name__})")
        return True

def run_tests():
    print("=" * 70)
    print("Sigma Protocol Tampering Vulnerability Test Suite")
    print("=" * 70)
    print()

    tests = [
        test_tampered_statement_challenge_response,
        test_tampered_statement_batchable,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        print()

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    if failed > 0:
        print("\nStatus: VULNERABILITY DETECTED or TESTS FAILED")
        print("Expected: challenge-response test should fail (vulnerability present)")
        print("          batchable test should pass (already secure)")

    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    if not success:
        import sys
        sys.exit(1)
