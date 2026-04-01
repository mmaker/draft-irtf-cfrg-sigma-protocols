---
title: "Fiat-Shamir Transformation"
category: info

docname: draft-irtf-cfrg-fiat-shamir-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - zero knowledge
 - hash
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "mmaker/draft-irtf-cfrg-sigma-protocols"
  latest: "https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-fiat-shamir.html"

author:
-
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"

normative:

informative:
  SHA3:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

--- abstract

This document describes how to construct a non-interactive proof via the Fiat–Shamir transformation, using a generic procedure that compiles an interactive proof into a non-interactive one by relying on a stateful duplex sponge object.

The duplex sponge interface requires two methods: absorb and squeeze, which respectively read and write elements of a specified base type. The absorb operation incrementally updates the duplex sponge's internal state, while the squeeze operation produces variable-length, unpredictable outputs. This interface can be instantiated with different constructions based on permutation or compression functions.

This specification also defines codecs to securely map prover messages into the duplex sponge domain, from the duplex sponge domain into verifier messages.
It also establishes how the non-interactive argument string should be serialized.

--- middle

# Introduction

The Fiat-Shamir transformation is a technique that uses a duplex sponge to convert a public-coin interactive protocol between a prover and a verifier into a corresponding non-interactive argument.
The term "public-coin" here refers to interactive protocols where all verifier messages are essentially random values sent in the clear.
It depends on:

- An _initialization vector_ (IV) uniquely identifying the protocol, the session, and the statement being proven.
- An _interactive protocol_ supporting a family of statements to be proven.
- A _duplex sponge instantiation_ capable of absorbing inputs incrementally and squeezing variable-length unpredictable messages.
- A _codec_, which securely remaps prover elements into the base alphabet, and outputs of the duplex sponge into verifier messages (preserving the distribution).

# Security Considerations

The Fiat-Shamir transformation carries over the soundness and witness hiding properties of the interactive proof:

- **Completeness**: If the statement being proved is true, an honest verifier can be convinced of this fact by an honest prover via the proof.

- **Soundness**: If the interactive proof is sound, then so is the non-interactive proof. In particular, valid proofs cannot be generated without possession of the corresponding witness.

- **Zero-Knowledge**: If the interactive proof is honest-verifier zero-knowledge, then so is the non-interactive proof. In particular, the resulting argument string does not reveal any information beyond what can be directly inferred from the statement being valid. This ensures that verifiers gain no knowledge about the witness.

In particular, the Fiat-Shamir transformation of Sigma Protocols is a zero-knowledge and sound argument of knowledge.

Note that non-interactive Sigma Protocols do not have deniability, as the non-interactive nature of the protocol implies transferable message authenticity.

# The Duplex Sponge Interface

The duplex sponge interface defines the space (the `Unit`) where the duplex sponge operates, plus a function for absorbing and squeezing prover messages. It provides the following interface.

    class DuplexSponge:
      def init(iv: bytes) -> DuplexSponge
      def absorb(self, x: list[Unit])
      def squeeze(self, length: int) -> list[Unit]

Where:

- `init(iv: bytes) -> DuplexSponge` denotes the initialization function. This function takes as input a 64-byte initialization vector `iv` and initializes the state of the duplex sponge.
- `absorb(self, values: list[Unit])` denotes the absorb operation of the duplex sponge. This function takes as input a list of `Unit` elements and mutates the `DuplexSponge` internal state.
- `squeeze(self, length: int)` denotes the squeeze operation of the duplex sponge. This function takes as input an integral `length` and squeezes a list of `Unit` elements of length `length`.

# The Codec interface

A codec is a collection of:
- functions that map prover messages into `Unit`s,
- functions that map `Unit`s into verifier messages, preserving the uniform distribution

A codec provides the following interface.

    class Codec:
        def prover_message(self, state, elements)
        def verifier_challenge(self, state) -> verifier_challenge

Where:

- `prover_message(self, state, elements)` denotes the absorb operation of the codec. This function takes as input the duplex sponge, and elements with which to mutate the duplex sponge.
- `verifier_challenge(self, state) -> verifier_challenge` denotes the squeeze operation of the codec. This function takes as input the duplex sponge to produce an unpredictable verifier challenge `verifier_challenge`.

The `verifier_challenge` function must generate a challenge from the underlying scalar field that is statistically close to uniform, from the public inputs given to the verifier, as described in {{decode-random-bytes-scalars}}.

# Initialization of the Duplex Sponge State

The duplex sponge state is initialized by sequentially absorbing:

- A `protocol_id`: the unique identifier for the interactive protocol and the associated relation being proven. This identifier MUST be 64 bytes.
- A `session_id`: the session identifier, for user-provided contextual information about the context where the proof is made (e.g. a URL, or a timestamp). This identifier is currently generated as 32 zero-bytes concatenated with a 32-byte digest derived using the duplex sponge.
- An `instance_label`: the instance identifier for the statement being proven.

The `session_id` is computed as:

    state = DuplexSponge.init(b"fiat-shamir/session-id".ljust(64, b"\x00"))
    state.absorb(session)
    session_id = [0] * 32 || state.squeeze(32)

The protocol instance label is absorbed without an explicit length prefix.
Therefore, the encoding used to produce `instance_label` MUST be prefix-free.

# Fiat-Shamir transformation for Sigma Protocols

We describe how to construct non-interactive proofs for sigma protocols.
The Fiat-Shamir transformation is parameterized by:

- a `SigmaProtocol`, which specifies an interactive 3-message protocol as defined in {{Section 2 of !SIGMA=I-D.draft-irtf-cfrg-sigma-protocols-00}};
- a `Codec`, which specifies how to absorb prover messages and how to squeeze verifier challenges;
- a `DuplexSpongeInterface`, which specifies a duplex sponge for computing challenges.

Upon initialization, the protocol receives as input:
- `session`, which identifies the session being proven
- `instance`, the sigma protocol instance for proving or verifying

    class NISigmaProtocol:
        Protocol: SigmaProtocol = None
        Codec: Codec = None
        DuplexSponge: DuplexSpongeInterface = None

        def __init__(self, session, instance):
            protocol_id = self.get_protocol_id()
            assert len(protocol_id) == 64
            self.sigma_protocol = self.Protocol(instance)
            self.codec = self.Codec()
            instance_label = self.sigma_protocol.get_instance_label()
            session_state = self.DuplexSponge(b"fiat-shamir/session-id".ljust(64, b"\x00"))
            session_state.absorb(session)
            session_id = [0] * 32 || session_state.squeeze(32)
            self.state = self.DuplexSponge(protocol_id)
            self.state.absorb(session_id)
            self.state.absorb(instance_label)

        def _prove(self, witness, rng):
            # Core proving logic that returns commitment, challenge, and response.
            # The challenge is generated via the duplex sponge.
            (prover_state, commitment) = self.sigma_protocol.prover_commit(witness, rng)
            self.codec.prover_message(self.state, commitment)
            challenge = self.codec.verifier_challenge(self.state)
            response = self.sigma_protocol.prover_response(prover_state, challenge)
            return (commitment, challenge, response)

        def prove(self, witness, rng):
            # Default proving method using challenge-response format.
            (commitment, challenge, response) = self._prove(witness, rng)
            assert self.sigma_protocol.verifier(commitment, challenge, response)
            return self.sigma_protocol.serialize_challenge(challenge) + self.sigma_protocol.serialize_response(response)

        def verify(self, proof):
            # Before running the sigma protocol verifier, one must also check that:
            # - the proof length is exactly Nc + response_bytes_len,
            Nc = self.sigma_protocol.instance.Domain.scalar_byte_length()
            assert len(proof) == Nc + self.sigma_protocol.instance.response_bytes_len

            # - proof deserialization successfully produces a valid challenge and a valid response,
            challenge_bytes = proof[:Nc]
            response_bytes = proof[Nc:]
            challenge = self.sigma_protocol.deserialize_challenge(challenge_bytes)
            response = self.sigma_protocol.deserialize_response(response_bytes)
            commitment = self.sigma_protocol.simulate_commitment(response, challenge)

            # - the re-computed challenge equals the serialized challenge.
            self.codec.prover_message(self.state, commitment)
            expected_challenge = self.codec.verifier_challenge(self.state)
            if challenge != expected_challenge:
                return False

            return self.sigma_protocol.verifier(commitment, challenge, response)

        def prove_batchable(self, witness, rng):
            # Proving method using commitment-response format.
            # Allows for batching.
            (commitment, challenge, response) = self._prove(witness, rng)
            # running the verifier here is just a sanity check
            assert self.sigma_protocol.verifier(commitment, challenge, response)
            return self.sigma_protocol.serialize_commitment(commitment) + self.sigma_protocol.serialize_response(response)

        def verify_batchable(self, proof):
            # Before running the sigma protocol verifier, one must also check that:
            # - the proof length is exactly commit_bytes_len + response_bytes_len
            assert len(proof) == self.sigma_protocol.instance.commit_bytes_len + self.sigma_protocol.instance.response_bytes_len

            # - proof deserialization successfully produces a valid commitment and a valid response
            commitment_bytes = proof[:self.sigma_protocol.instance.commit_bytes_len]
            response_bytes = proof[self.sigma_protocol.instance.commit_bytes_len:]
            commitment = self.sigma_protocol.deserialize_commitment(commitment_bytes)
            response = self.sigma_protocol.deserialize_response(response_bytes)

            self.codec.prover_message(self.state, commitment)
            challenge = self.codec.verifier_challenge(self.state)
            return self.sigma_protocol.verifier(commitment, challenge, response)

Serialization and deserialization of scalars and group elements are defined by the ciphersuite chosen in the Sigma Protocol. In particular, `serialize_challenge`, `deserialize_challenge`, `serialize_response`, and `deserialize_response` call into the scalar `serialize` and `deserialize` functions. Likewise, `serialize_commitment` and `deserialize_commitment` call into the group element `serialize` and `deserialize` functions.

## NISigmaProtocol instances (ciphersuites)

We describe noninteractive sigma protocol instances for combinations of protocols (SigmaProtocol), codec (Codec), and duplex sponge (DuplexSpongeInterface). Descriptions of codecs and duplex sponge interfaces are in the following sections.

    class NISchnorrProofShake128P256(NISigmaProtocol):
        Protocol = SchnorrProof
        Codec = P256Codec
        DuplexSponge = SHAKE128

    class NISchnorrProofShake128Bls12381(NISigmaProtocol):
        Protocol = SchnorrProof
        Codec = Bls12381Codec
        DuplexSponge = SHAKE128

    class NISchnorrProofKeccakDuplexSpongeBls12381(NISigmaProtocol):
        Protocol = SchnorrProof
        Codec = Bls12381Codec
        DuplexSponge = KeccakDuplexSponge

# Codec for Schnorr proofs {#group-prove}

We describe a codec for Schnorr proofs over groups of prime order `p` where `Unit = u8`.

    class ByteSchnorrCodec(Codec):
        GG: groups.Group = None

        def prover_message(self, elements: list):
            state.absorb(self.GG.serialize(elements))

        def verifier_challenge(self, state):
            # see https://eprint.iacr.org/2025/536.pdf, Appendix C.
            Ns = self.GG.ScalarField.scalar_byte_length()
            uniform_bytes = state.squeeze(
                Ns + 32
            )
            scalar = OS2IP(uniform_bytes) % self.GG.ScalarField.order
            return scalar

We describe a codec for the P256 curve.

    class P256Codec(ByteSchnorrCodec):
        GG = groups.GroupP256()

# Duplex Sponge Interfaces

## SHAKE128

SHAKE128 is a variable-length extendable-output function based on the Keccak sponge construction {{SHA3}}.
It belongs to the SHA-3 family and is used here to provide a duplex sponge interface.

### Initialization

    new(self, iv)

    Inputs:

    - iv, a byte array

    Outputs:

    -  a duplex sponge instance

    1. initial_block = iv + b'\00' * 104  # len(iv) + 104 == SHAKE128 rate
    2. self.state = hashlib.shake_128()
    3. self.state.update(initial_block)

### SHAKE128 Absorb

    absorb(state, x)

    Inputs:

    - state, a duplex sponge state
    - x, a byte array

    1. h.update(x)

### SHAKE128 Squeeze

    squeeze(state, length)

    Inputs:

    - state, the duplex sponge state
    - length, the number of elements to be squeezed

    1. return self.state.copy().digest(length)

## Duplex Sponge

A duplex sponge in overwrite mode is based on a permutation function that operates on a state vector. It implements the `DuplexSpongeInterface` and maintains internal state to support incremental absorption and variable-length output generation.

### Initialization

This is the constructor for a duplex sponge object. It is initialized with a 64-byte initialization vector.

    new(iv)

    Inputs:
    - iv, a 64-byte initialization vector

    Procedure:
    1. self.absorb_index = 0
    2. self.squeeze_index = self.permutation_state.R
    3. self.rate = self.permutation_state.R
    4. self.capacity = self.permutation_state.N - self.permutation_state.R

### Absorb

The absorb function incorporates data into the duplex sponge state using overwrite mode.

    absorb(self, input)

    Inputs:
    - self, the current duplex sponge object
    - input, the input bytes to be absorbed

    Procedure:
    1. self.squeeze_index = self.rate
    2. while len(input) != 0:
    3.     if self.absorb_index == self.rate:
    4.         self.permutation_state.permute()
    5.         self.absorb_index = 0
    6.     chunk_size = min(self.rate - self.absorb_index, len(input))
    7.     next_chunk = input[:chunk_size]
    8.     self.permutation_state[self.absorb_index:self.absorb_index + chunk_size] = next_chunk
    9.     self.absorb_index += chunk_size
    10.    input = input[chunk_size:]

### Squeeze

The squeeze operation extracts output elements from the sponge state, which are uniformly distributed and can be used as a digest, key stream, or other cryptographic material.

    squeeze(self, length)

    Inputs:
    - self, the current duplex sponge object
    - length, the number of bytes to be squeezed out of the sponge

    Outputs:
    - digest, a byte array of `length` elements uniformly distributed

    Procedure:
    1. output = b''
    2. while length != 0:
    3.     if self.squeeze_index == self.rate:
    4.         self.permutation_state.permute()
    5.         self.squeeze_index = 0
    6.         self.absorb_index = 0
    7.     chunk_size = min(self.rate - self.squeeze_index, length)
    8.     output += bytes(self.permutation_state[self.squeeze_index:self.squeeze_index+chunk_size])
    9.     self.squeeze_index += chunk_size
    10.    length -= chunk_size
    11. return output

### Keccak-f\[1600\] Implementation

`Keccak-f` is the permutation function underlying {{SHA3}}.

`KeccakDuplexSponge` instantiates `DuplexSponge` with `Keccak-f[1600]`, using rate `R = 136` bytes and capacity `C = 64` bytes.

# Codecs registry

## Elliptic curves

### Notation and Terminology {#notation}

For an elliptic curve, we consider two fields, the coordinate fields, which indicates the base field, the field over which the elliptic curve equation is defined, and the scalar field, over which the scalar operations are performed.

The following functions and notation are used throughout the document.

- `concat(x0, ..., xN)`: Concatenation of byte strings.
- `OS2IP` and `I2OSP`: Convert a byte string to and from a non-negative integer, as described in
  {{!RFC8017}}. Note that these functions operate on byte strings in big-endian byte order.
- The function `ecpoint_to_bytes` converts an elliptic curve point in affine-form into an array string of length `ceil(ceil(log2(coordinate_field_order))/ 8) + 1` using `int_to_bytes` prepended by one byte. This is defined as

      ecpoint_to_bytes(element)
      Inputs:
      - `element`, an elliptic curve element in affine form, with attributes `x` and `y` corresponding to its affine coordinates, represented as integers modulo the coordinate field order.

      Outputs:

      A byte array

      Constants:

      Ng, the number of bytes to represent an element in the coordinate field, equal to `ceil(log2(field.order())/8)`.

      1. byte = 2 if sgn0(element.y) == 0 else 3
      2. return I2OSP(byte, 1) + I2OSP(x, Ng)

### Absorb scalars

    absorb_scalars(state, scalars)

    Inputs:

    - state, the duplex sponge
    - scalars, a list of elements of the elliptic curve's scalar field

    Constants:

    - Ns, the number of bytes to represent a scalar element, equal to `ceil(log2(p)/8)`.

    1. for scalar in scalars:
    2.     state.absorb(I2OSP(scalar, Ns))

### Absorb elements

    absorb_elements(state, elements)

    Inputs:

    - state, the duplex sponge
    - elements, a list of group elements

    1. for element in elements:
    2.     state.absorb(ecpoint_to_bytes(element))

### Decoding random bytes as scalars {#decode-random-bytes-scalars}

Given `Ns + 32` bytes, it is possible to generate a scalar modulo `p` that is statistically close to uniform.
Interpret the bytes as a big-endian integer, then reduce it modulo `p`, where `p` is the order of the group.

    squeeze_scalars(state, length)

    Inputs:

    - state, the duplex sponge
    - length, an unsigned integer of 64 bits determining the number of scalars to output.

    Constants:

    - Ns, the number of bytes to represent a scalar, equal to `ceil(log2(p)/8)`.

    1. for i in range(length):
    2.     scalar_bytes = state.squeeze(Ns + 32)
    3.     scalars.append(OS2IP(scalar_bytes) % p)

--- back

# Test Vectors


{::include ./poc/vectors/duplexSpongeVectors.txt}
