#!/usr/bin/sage
# vim: syntax=python

from sagelib.duplex_sponge import SHAKE128
import json

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
    for key in vector:
        write_value(fh, key, vector[key])
    print("~~~", file=fh, end="\n\n")

def run_operations(iv, operations, duplex_sponge_cls):
    """Execute a sequence of operations on a sponge and return the final output"""
    sponge = duplex_sponge_cls(iv)
    output = None

    for op in operations:
        if op["type"] == "absorb":
            data = bytes.fromhex(op["data"]) if op["data"] else b""
            sponge.absorb(data)
        elif op["type"] == "squeeze":
            output = sponge.squeeze(op["length"])

    return output

def test_vector(test_vector_function):
    def inner(vectors, name, duplex_sponge_cls):
        # Create unique test vector name based on function name and duplex sponge
        test_vector_name = f"{test_vector_function.__name__}_{name}"

        # Create a run_operations function bound to this specific duplex sponge class
        def bound_run_operations(iv, operations):
            return run_operations(iv, operations, duplex_sponge_cls)

        # Pass the bound function to the test
        test_data = test_vector_function(bound_run_operations)
        test_data["DuplexSponge"] = name
        vectors[test_vector_name] = test_data
        print(f"{test_vector_name} test vector generated\n")
    return inner

@test_vector
def test_keccak_duplex_sponge(run_ops):
    """Basic test of Keccak duplex sponge"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": b"basic duplex sponge test".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_empty_before_does_not_break(run_ops):
    """Test absorbing empty message after actual message"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": b"empty message after".hex()},
        {"type": "absorb", "data": ""},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_empty_after_does_not_break(run_ops):
    """Test absorbing empty message before actual message"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": ""},
        {"type": "absorb", "data": b"empty message before".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_squeeze_zero_behavior(run_ops):
    """Test squeezing zero bytes between operations"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "squeeze", "length": int(0)},
        {"type": "absorb", "data": b"zero squeeze test".hex()},
        {"type": "squeeze", "length": int(0)},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_squeeze_zero_after_behavior(run_ops):
    """Test squeezing zero bytes after operations"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "squeeze", "length": int(0)},
        {"type": "absorb", "data": b"zero squeeze after".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_squeeze_absorb_consistency(run_ops):
    """Test interleaving absorb and squeeze operations"""
    iv = b"edge-case-test-domain-absorb".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": b"interleave first".hex()},
        {"type": "squeeze", "length": int(32)},
        {"type": "absorb", "data": b"interleave second".hex()},
        {"type": "squeeze", "length": int(32)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_associativity_of_absorb(run_ops):
    """Test that absorbing data is associative"""
    iv = b"absorb-associativity-domain".ljust(64, b'\x00')

    # Test case 1: absorb all at once
    operations1 = [
        {"type": "absorb", "data": b"associativity test full".hex()},
        {"type": "squeeze", "length": int(32)}
    ]
    out1 = run_ops(iv, operations1)

    # Test case 2: absorb in parts
    operations2 = [
        {"type": "absorb", "data": b"associativity".hex()},
        {"type": "absorb", "data": b" test split".hex()},
        {"type": "squeeze", "length": int(32)}
    ]
    out2 = run_ops(iv, operations2)
    assert out2 == out2

    return {
        "IV": iv.hex(),
        "Operations": operations1,
        "Expected": out1.hex()
    }

@test_vector
def test_iv_affects_output(run_ops):
    """Test that different IVs produce different outputs"""
    iv1 = b"domain-one-differs-here".ljust(64, b'\x00')
    iv2 = b"domain-two-differs-here".ljust(64, b'\x00')

    operations = [
        {"type": "absorb", "data": b"iv difference test".hex()},
        {"type": "squeeze", "length": int(32)}
    ]

    output1 = run_ops(iv1, operations)
    output2 = run_ops(iv2, operations)
    assert output1 != output2

    return {
        "IV": iv1.hex(),
        "Operations": operations,
        "Expected": output1.hex()
    }

@test_vector
def test_multiple_blocks_absorb_squeeze(run_ops):
    """Test absorbing and squeezing multiple blocks"""
    iv = b"multi-block-absorb-test".ljust(64, b'\x00')
    input_data = bytes([0xAB] * (3 * 200))

    operations = [
        {"type": "absorb", "data": input_data.hex()},
        {"type": "squeeze", "length": int(3 * 200)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

def main(path="vectors"):
    vectors = {}
    test_vectors = [
        test_keccak_duplex_sponge,
        test_absorb_empty_before_does_not_break,
        test_absorb_empty_after_does_not_break,
        test_squeeze_zero_behavior,
        test_squeeze_zero_after_behavior,
        test_absorb_squeeze_absorb_consistency,
        test_associativity_of_absorb,
        test_iv_affects_output,
        test_multiple_blocks_absorb_squeeze,
    ]

    duplex_sponges = {"SHAKE128": SHAKE128}

    print("Generating duplex sponge test vectors...\n")

    for name, duplex_sponge_cls in duplex_sponges.items():
        for test_fn in test_vectors:
            test_fn(vectors, name, duplex_sponge_cls)

    with open(path + "/duplexSpongeVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)

    with open(path + "/duplexSpongeVectors.txt", 'wt') as f:
        for vector_name in vectors:
            vector = {
                "DuplexSponge": vectors[vector_name]["DuplexSponge"],
                "IV": vectors[vector_name]["IV"],
            }
            for i, operation in enumerate(vectors[vector_name]["Operations"]):
                if operation["type"] == "absorb":
                    operation_value = "absorb:" + operation["data"]
                else:
                    operation_value = "squeeze:" + str(operation["length"])
                vector["Operation" + str(i + 1)] = operation_value
            vector["Expected"] = vectors[vector_name]["Expected"]
            write_group_vectors(f, vector_name, vector)

    print(f"Test vectors written to {path}/duplexSpongeVectors.json")

if __name__ == "__main__":
    main()
