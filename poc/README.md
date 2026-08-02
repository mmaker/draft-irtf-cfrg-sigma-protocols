# Reference implementation

A pure-Python, standard-library-only reference implementation of
draft-irtf-cfrg-sigma-protocols and draft-irtf-cfrg-fiat-shamir, written
for specification discussion and test-vector verification. It privileges
clarity over performance, is not constant-time, and is not intended for
production use.

## Layout

| File | Contents |
| ---- | -------- |
| `groups.py` | The prime-order groups of the ciphersuites (P-256, BLS12-381 G1) with their canonical element and scalar codecs. |
| `keccak.py` | TurboSHAKE128 over Keccak-p[1600, 12] (RFC 9861), hashlib-compatible; SHAKE128 comes from `hashlib`. |
| `fiat_shamir.py` | The duplex sponge interface, session-id derivation, and the byte-string, unsigned-integer, and field codecs of the Fiat-Shamir draft. |
| `sumcheck.py` | The sumcheck protocol of the Fiat-Shamir draft's example appendix, over Mersenne31. |
| `sigma_protocols.py` | Linear relations, instance validation, statement serialization, the Sigma Protocol, batchable and compact NARG strings, and batch verification. |
| `test_vectors.py` | Verifies every record in `vectors/*.json`; also holds the seeded test PRNG of the sigma draft's appendix. |
| `vectors/` | The machine-readable test vectors, one JSON file per suite; the same vectors are rendered in the drafts' Test Vectors appendices. |

## Running

Each module runs its own self-test when executed directly. The vector
harness checks all vectors of both drafts:

```
python3 poc/test_vectors.py
```

Verification is regeneration wherever the vectors pin the randomness:
valid proofs are re-proven byte-for-byte from the instance, witness, and
the seeded PRNG of the appendix, so the vectors are reproducible from the
drafts alone; `Expected = reject` records must be refused, and each
rejection is paired with the accepted baseline vector it mutates.
