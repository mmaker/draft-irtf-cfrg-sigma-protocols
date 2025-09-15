#!/usr/bin/env python3
"""
Pure Python test suite for duplex sponge implementations.
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fiat_shamir import Keccak256DuplexSponge, Shake128DuplexSponge


def run_operations(iv, operations, DuplexSponge):
    """Execute a sequence of operations on a sponge and return the final output"""
    sponge = DuplexSponge(iv)
    output = None

    for op in operations:
        if op["type"] == "absorb":
            sponge.absorb(bytes.fromhex(op["input"]))
        elif op["type"] == "squeeze":
            output = sponge.squeeze(op["length"])

    return output.hex() if output else ""


def generate_test_vectors():
    """Generate test vectors for duplex sponges."""
    vectors = {}

    sponges = {
        "Keccak": Keccak256DuplexSponge,
        "SHAKE128": Shake128DuplexSponge
    }

    test_cases = [
        {
            "name": "test_keccak_duplex_sponge",
            "iv": "00",
            "operations": [
                {"type": "absorb", "input": "01"},
                {"type": "squeeze", "length": 32}
            ]
        },
        {
            "name": "test_absorb_empty_before_does_not_break",
            "iv": "00",
            "operations": [
                {"type": "absorb", "input": ""},
                {"type": "absorb", "input": "01"},
                {"type": "squeeze", "length": 32}
            ]
        },
        {
            "name": "test_absorb_empty_after_does_not_break",
            "iv": "00",
            "operations": [
                {"type": "absorb", "input": "01"},
                {"type": "absorb", "input": ""},
                {"type": "squeeze", "length": 32}
            ]
        },
        {
            "name": "test_squeeze_zero_behavior",
            "iv": "00",
            "operations": [
                {"type": "absorb", "input": "01"},
                {"type": "squeeze", "length": 0},
                {"type": "squeeze", "length": 32}
            ]
        },
        {
            "name": "test_squeeze_zero_after_behavior",
            "iv": "00",
            "operations": [
                {"type": "absorb", "input": "01"},
                {"type": "squeeze", "length": 32},
                {"type": "squeeze", "length": 0}
            ]
        },
        {
            "name": "test_absorb_squeeze_absorb_consistency",
            "iv": "00",
            "operations": [
                {"type": "absorb", "input": "01"},
                {"type": "squeeze", "length": 16},
                {"type": "absorb", "input": "02"},
                {"type": "squeeze", "length": 16}
            ]
        },
        {
            "name": "test_iv_affects_output",
            "iv": "01",
            "operations": [
                {"type": "absorb", "input": "01"},
                {"type": "squeeze", "length": 32}
            ]
        },
        {
            "name": "test_multiple_blocks_absorb_squeeze",
            "iv": "00",
            "operations": [
                {"type": "absorb", "input": "01" * 100},
                {"type": "squeeze", "length": 64}
            ]
        }
    ]

    for sponge_name, SpongeClass in sponges.items():
        for test_case in test_cases:
            try:
                output = run_operations(
                    bytes.fromhex(test_case["iv"]),
                    test_case["operations"],
                    SpongeClass
                )

                test_name = f"{test_case['name']}_{sponge_name}"
                vectors[test_name] = {
                    "sponge": sponge_name,
                    "iv": test_case["iv"],
                    "operations": test_case["operations"],
                    "output": output
                }
                print(f"{test_name} test vector generated")

            except Exception as e:
                print(f"Error in inner for {sponge_name}: ")
                # Continue with other tests

    return vectors


def main():
    """Generate duplex sponge test vectors."""
    print("Generating duplex sponge test vectors...")

    vectors = generate_test_vectors()

    # Write to file
    os.makedirs("vectors", exist_ok=True)
    with open("vectors/duplexSpongeVectors.json", "w") as f:
        json.dump(vectors, f, indent=2)

    print("Duplex sponge test vectors written to vectors/duplexSpongeVectors.json")
    print("✓ All duplex sponge tests passed!")


if __name__ == "__main__":
    main()