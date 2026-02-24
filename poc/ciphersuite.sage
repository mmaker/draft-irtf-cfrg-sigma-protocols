from sagelib.fiat_shamir import NISigmaProtocol
from sagelib.duplex_sponge import SHAKE128, KeccakDuplexSponge
from sagelib.sigma_protocols import SchnorrProof
from sagelib.codec import P256Codec, Bls12381Codec

class NISchnorrProofKeccakDuplexSpongeP256(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = P256Codec
    Hash = KeccakDuplexSponge


class NISchnorrProofShake128Bls12381(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = SHAKE128


class NISchnorrProofKeccakDuplexSpongeBls12381(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = KeccakDuplexSponge


CIPHERSUITE = {
    "Schnorr_KeccakDuplexSponge_P256": NISchnorrProofKeccakDuplexSpongeP256,
    "Schnorr_Shake128_BLS12381": NISchnorrProofShake128Bls12381,
    "Schnorr_KeccakDuplexSponge_Bls12381": NISchnorrProofKeccakDuplexSpongeBls12381,
}