from sagelib.fiat_shamir import NISigmaProtocol
from sagelib.duplex_sponge import SHAKE128, KeccakDuplexSponge
from sagelib.sigma_protocols import SchnorrProof
from sagelib.codec import P256Codec, Bls12381Codec

class NISchnorrProofShake128P256(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = P256Codec
    Hash = SHAKE128

    @staticmethod
    def get_protocol_id() -> bytes:
        return b"sigma-proofs_Shake128_P256".ljust(64, b"\0")


class NISchnorrProofShake128Bls12381(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = SHAKE128

    @staticmethod
    def get_protocol_id() -> bytes:
        return b"sigma-proofs_Shake128_BLS12381".ljust(64, b"\0")


class NISchnorrProofKeccakDuplexSpongeBls12381(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = KeccakDuplexSponge

    @staticmethod
    def get_protocol_id() -> bytes:
        return b"sigma-proofs_OWKeccak1600_Bls12381".ljust(64, b"\0")


CIPHERSUITE = {
    "sigma-proofs_Shake128_P256": NISchnorrProofShake128P256,
    "sigma-proofs_Shake128_BLS12381": NISchnorrProofShake128Bls12381,
}
