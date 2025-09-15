"""
Pure Python implementation of ciphersuites for Sigma protocols.
"""

from .sigma_protocols import SchnorrProof
from fiat_shamir import P256Codec, FiatShamirNIZK, Shake128DuplexSponge, Keccak256DuplexSponge


# Define ciphersuites for P-256
CIPHERSUITE = {
    "P256_SHAKE128": FiatShamirNIZK(
        SchnorrProof,
        P256Codec,
        Shake128DuplexSponge
    ),
    "P256_KECCAK256": FiatShamirNIZK(
        SchnorrProof,
        P256Codec,
        Keccak256DuplexSponge
    ),
}