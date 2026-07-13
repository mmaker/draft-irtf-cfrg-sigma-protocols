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

This document describes how to construct a non-interactive proof via the Fiat–Shamir transformation, using a generic procedure that compiles an interactive proof into a non-interactive one by relying on a stateful transcript object.

The transcript interface requires two methods: absorb and squeeze, which respectively read and write elements of a specified base type. The absorb operation incrementally updates the transcript's internal state, while the squeeze operation produces variable-length, unpredictable outputs. This interface can be instantiated with different constructions, such as a cryptographic sponge or a hash-and-expand construction.

This specification also defines codecs to securely map prover messages into the transcript domain, and from the transcript domain into verifier messages.
It also establishes how the non-interactive argument string should be serialized.

--- middle

# Introduction

The Fiat-Shamir transformation is a technique that uses a stateful transcript object to convert a public-coin interactive protocol between a prover and a verifier into a corresponding non-interactive argument.
The term "public-coin" here refers to interactive protocols where all verifier messages are essentially random values sent in the clear.
It depends on:

- An _initialization vector_ (IV) uniquely identifying the protocol, the session, and the statement being proven.
- An _interactive protocol_ supporting a family of statements to be proven.
- A _transcript instantiation_ capable of absorbing inputs incrementally and squeezing variable-length unpredictable messages.
- A _codec_, which securely remaps prover elements into the base alphabet, and outputs of the transcript into verifier messages (preserving the distribution).

# Security Considerations

The Fiat-Shamir transformation carries over the soundness and witness hiding properties of the interactive proof:

- **Completeness**: If the statement being proved is true, an honest verifier can be convinced of this fact by an honest prover via the proof.

- **Soundness**: If the interactive proof is sound, then so is the non-interactive proof. In particular, valid proofs cannot be generated without possession of the corresponding witness.

- **Zero-Knowledge**: If the interactive proof is honest-verifier zero-knowledge, then so is the non-interactive proof. In particular, the resulting argument string does not reveal any information beyond what can be directly inferred from the statement being valid. This ensures that verifiers gain no knowledge about the witness.

In particular, the Fiat-Shamir transformation of Sigma Protocols is a zero-knowledge and sound argument of knowledge.

Note that non-interactive Sigma Protocols do not have deniability, as the non-interactive nature of the protocol implies transferable message authenticity.

## Correlation-Intractability and Computational Depth

When the Fiat-Shamir transformation is applied to interactive proofs, a potential concern is the correlation intractability of the hash function, particularly in relation to self-referential attacks. If the verification logic of the relation itself evaluates or simulates the transcript generator internally (such as in recursive proofs or proofs of computation), a malicious prover might exploit relation-dependent inputs where the computational depth of the relation and the computational depth of the transcript generator interact.

To mitigate this attack heuristically, implementations SHOULD ensure that the computational depth (or sequential complexity) of the transcript computation is strictly greater than the depth/complexity of evaluating the relation.

Specifically, when applying this transformation where correlation intractability is a concern, implementations SHOULD append a padding string of zero-bytes proportional to the relation's representation size or complexity (e.g., $0^{|C|}$ where $|C|$ represents the number of constraints, gates, or steps in the verification logic) to the transcript immediately after the statement encoding. This ensures that the transcript's computational depth exceeds that of the relation's verification logic, rendering self-referential evaluations infeasible.

# The Transcript Interface

A Fiat-Shamir transcript requires a stateful object exposing two primary operations, following a duplex paradigm:

    class Transcript:
      def init(iv: bytes) -> Transcript
      def absorb(self, x: list[Unit])
      def squeeze(self, length: int) -> list[Unit]

Where:

- `init(iv: bytes) -> Transcript` denotes the initialization function. This function takes as input a 64-byte initialization vector `iv` and initializes the state of the transcript.
- `absorb(self, values: list[Unit])` denotes the absorb operation of the transcript, incorporating prover messages into the transcript state.
- `squeeze(self, length: int)` denotes the squeeze operation of the transcript, extracting `length` pseudo-random bytes from the current state to generate verifier challenges.

# The Codec interface

A codec is a collection of:
- functions that map prover messages into `Unit`s,
- functions that map `Unit`s into verifier messages, preserving the uniform distribution

A codec provides the following interface.

    class Codec:
        def prover_message(self, state, elements)
        def verifier_challenge(self, state) -> verifier_challenge

Where:

- `prover_message(self, state, elements)` denotes the absorb operation of the codec. This function takes as input the transcript, and elements with which to mutate the transcript.
- `verifier_challenge(self, state) -> verifier_challenge` denotes the squeeze operation of the codec. This function takes as input the transcript to produce an unpredictable verifier challenge `verifier_challenge`.

The `verifier_challenge` function must generate a challenge that is statistically close to uniform over the target challenge domain (such as a scalar field, a binary extension field, a bounded range of natural numbers, or a subset combination), using deterministic decoding or sampling algorithms as described in {{Codecs registry}}.

# Initialization of the Transcript State

We describe the initialization of the transcript state for different classes of protocols.

## Initialization for Sigma Protocols

For standard Sigma and Schnorr protocols, the transcript state is initialized by sequentially absorbing:

- A `protocol_id`: the unique identifier for the interactive protocol and the associated relation being proven. This identifier MUST be 64 bytes.
- A `session_id`: the session identifier, for user-provided contextual information about the context where the proof is made (e.g. a URL, or a timestamp). This identifier is currently generated as 32 zero-bytes concatenated with a 32-byte digest derived using the transcript.
- An `instance_label`: the instance identifier for the statement being proven.
- A `circuit_depth_padding`: an optional padding string of zero-bytes proportional to the ZK circuit size (e.g., $0^{|C|}$) immediately after the statement encoding, if correlation intractability is a concern.

The `session_id` is computed as:

    state = Transcript.init(b"fiat-shamir/session-id".ljust(64, b"\x00"))
    state.absorb(session)
    session_id = [0] * 32 || state.squeeze(32)

The protocol instance label and optional padding are absorbed without an explicit length prefix.
Therefore, the encoding used to produce `instance_label` MUST be prefix-free.

## Initialization for Interactive Oracle Proofs (IOPs)

For more general interactive oracle proofs or circuit-based ZK arguments (where statements are defined by ZK relations or circuits), the transcript state is initialized by sequentially absorbing:

1. A domain separator or `protocol_id` (typically used as the initialization vector `iv` to `Transcript.init`).
2. A `session_id`.
3. A circuit identifier (e.g., a hash or unique name representing the ZK relation/circuit being evaluated) and the statement's input/output (I/O) variables.
4. Any optional padding (such as `circuit_depth_padding`) immediately following the statement encoding, if correlation intractability is a concern.

# Fiat-Shamir transformation for Sigma Protocols

We describe how to construct non-interactive proofs for sigma protocols.
The Fiat-Shamir transformation is parameterized by:

- a `SigmaProtocol`, which specifies an interactive 3-message protocol as defined in {{Section 2 of !SIGMA=I-D.draft-irtf-cfrg-sigma-protocols-00}};
- a `Codec`, which specifies how to absorb prover messages and how to squeeze verifier challenges;
- a `TranscriptInterface`, which specifies a transcript for computing challenges.

Upon initialization, the protocol receives as input:
- `session`, which identifies the session being proven
- `instance`, the sigma protocol instance for proving or verifying

    class NISigmaProtocol:
        Protocol: SigmaProtocol = None
        Codec: Codec = None
        Transcript: TranscriptInterface = None

        def __init__(self, session, instance):
            protocol_id = self.get_protocol_id()
            assert len(protocol_id) == 64
            self.sigma_protocol = self.Protocol(instance)
            self.codec = self.Codec()
            instance_label = self.sigma_protocol.get_instance_label()
            session_state = self.Transcript(b"fiat-shamir/session-id".ljust(64, b"\x00"))
            session_state.absorb(session)
            session_id = [0] * 32 || session_state.squeeze(32)
            self.state = self.Transcript(protocol_id)
            self.state.absorb(session_id)
            self.state.absorb(instance_label)

        def _prove(self, witness, rng):
            # Core proving logic that returns commitment, challenge, and response.
            # The challenge is generated via the transcript.
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

We describe noninteractive sigma protocol instances for combinations of protocols (SigmaProtocol), codec (Codec), and transcript (TranscriptInterface). Descriptions of codecs and transcript interfaces are in the following sections.

    class NISchnorrProofShake128P256(NISigmaProtocol):
        Protocol = SchnorrProof
        Codec = P256Codec
        Transcript = SHAKE128

    class NISchnorrProofShake128Bls12381(NISigmaProtocol):
        Protocol = SchnorrProof
        Codec = Bls12381Codec
        Transcript = SHAKE128

    class NISchnorrProofKeccakDuplexSpongeBls12381(NISigmaProtocol):
        Protocol = SchnorrProof
        Codec = Bls12381Codec
        Transcript = KeccakDuplexSponge

# Codec for Schnorr proofs {#group-prove}

We describe a codec for Schnorr proofs over groups of prime order `p` where `Unit = u8`.

    class ByteSchnorrCodec(Codec):
        GG: groups.Group = None

        def prover_message(self, state, elements: list):
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

# Transcript Instantiations

We describe two compliant instantiations of the Transcript interface: the Sponge-based instantiation and the Hash-and-Expand instantiation.

## Sponge-based Instantiation

### SHAKE128

SHAKE128 is a variable-length extendable-output function based on the Keccak sponge construction {{SHA3}}.
It belongs to the SHA-3 family and is used here to provide a Transcript interface.

#### Initialization

    new(self, iv)

    Inputs:
    - iv, a byte array

    Outputs:
    - a transcript instance

    1. initial_block = iv + b'\00' * 104  # len(iv) + 104 == SHAKE128 rate
    2. self.state = hashlib.shake_128()
    3. self.state.update(initial_block)

#### SHAKE128 Absorb

    absorb(state, x)

    Inputs:
    - state, a transcript state
    - x, a byte array

    1. h.update(x)

#### SHAKE128 Squeeze

    squeeze(state, length)

    Inputs:
    - state, the transcript state
    - length, the number of elements to be squeezed

    1. return self.state.copy().digest(length)

### Duplex Sponge

A duplex sponge in overwrite mode is based on a permutation function that operates on a state vector. It implements the `Transcript` interface and maintains internal state to support incremental absorption and variable-length output generation.

#### Initialization

This is the constructor for a duplex sponge object. It is initialized with a 64-byte initialization vector.

    new(iv)

    Inputs:
    - iv, a 64-byte initialization vector

    Procedure:
    1. self.absorb_index = 0
    2. self.squeeze_index = self.permutation_state.R
    3. self.rate = self.permutation_state.R
    4. self.capacity = self.permutation_state.N - self.permutation_state.R

#### Absorb

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

#### Squeeze

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

#### Keccak-f\[1600\] Implementation

`Keccak-f` is the permutation function underlying {{SHA3}}.

`KeccakDuplexSponge` instantiates `DuplexSponge` with `Keccak-f[1600]`, using rate `R = 136` bytes and capacity `C = 64` bytes.

## Hash-and-Expand Instantiation

Alternatively, the Transcript interface CAN be instantiated using a Hash-and-Expand construction to accommodate protocols relying on standard hashes like SHA-256. In this instantiation, `absorb` is implemented by appending the uniquely serialized data to an internal buffer, and  `sqeeze` is implemented by applying a collision-resistant hash to the entire buffer to derive a seed (or key), and expanding that seed using a Pseudorandom Function (PRF) to produce the requested bytes.

    class HashAndExpand:
        Hash = None
        PRF = None

### Initialization

    new(self, iv)

    Inputs:
    - iv, a byte array

    Procedure:
    1. self.transcript = iv
    2. self.key = None
    3. self.counter = 0

### Absorb

    absorb(self, x)

    Inputs:
    - self, the transcript state
    - x, a byte array

    Procedure:
    1. self.transcript = self.transcript + x
    2. self.key = None  # Invalidate any previously cached key

### Squeeze

    squeeze(self, length)

    Inputs:
    - self, the transcript state
    - length, the number of bytes to squeeze

    Outputs:
    - output, a byte array of size `length`

    Procedure:
    1. If self.key is None:
    2.     self.key = self.Hash(self.transcript)
    3.     self.counter = 0
    4. 
    5. output = b''
    6. while len(output) < length:
    7.     block = self.PRF(self.key, self.counter)
    8.     output = output + block
    9.     self.counter = self.counter + 1
   10. return output[:length]

The hash function `Hash` MUST be a cryptographically secure, collision-resistant hash function outputting a seed of appropriate length. The PRF `PRF(key, counter)` denotes a pseudorandom function mapping a key and a counter value to a block of pseudorandom bytes.

### Hash-and-Expand Instantiations (Ciphersuites)

We describe noninteractive transcript instances based on `HashAndExpand` parameterized by specific hash and PRF functions:

    class HashAndExpandSha256AesCtr(HashAndExpand):
        Hash = SHA256
        PRF = AES256_CTR

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

    - state, the transcript
    - scalars, a list of elements of the elliptic curve's scalar field

    Constants:

    - Ns, the number of bytes to represent a scalar element, equal to `ceil(log2(p)/8)`.

    1. for scalar in scalars:
    2.     state.absorb(I2OSP(scalar, Ns))

### Absorb elements

    absorb_elements(state, elements)

    Inputs:

    - state, the transcript
    - elements, a list of group elements

    1. for element in elements:
    2.     state.absorb(ecpoint_to_bytes(element))

### Decoding random bytes as scalars {#decode-random-bytes-scalars}

Given `Ns + 32` bytes, it is possible to generate a scalar modulo `p` that is statistically close to uniform.
Interpret the bytes as a big-endian integer, then reduce it modulo `p`, where `p` is the order of the group.

    squeeze_scalars(state, length)

    Inputs:

    - state, the transcript
    - length, an unsigned integer of 64 bits determining the number of scalars to output.

    Constants:

    - Ns, the number of bytes to represent a scalar, equal to `ceil(log2(p)/8)`.

    1. for i in range(length):
    2.     scalar_bytes = state.squeeze(Ns + 32)
    3.     scalars.append(OS2IP(scalar_bytes) % p)

## Universal ZK TLV Codec

The Universal ZK TLV (Type-Length-Value) Codec provides a structured, prefix-free method for encoding statements and prover messages before they are absorbed by the transcript. This codec ensures that transcripts from interactive oracle proofs (IOPs) are parsed unambiguously.

To comply with the `Codec` interface:

- **`prover_message(self, state, elements)`**: Serializes each prover element in `elements` (e.g., field elements, byte arrays, or arrays of elements) using the TLV encoding rules below, and absorbs the resulting serialized byte stream into the transcript state.
- **`verifier_challenge(self, state)`**: Squeezes pseudo-random bytes from the transcript state to sample a challenge in the target challenge domain (e.g., using the scalar field decoding in {{decode-random-bytes-scalars}} or the sampling procedures described in {{Challenge Sampling Algorithms}}).

### Encoding Rules

Every element encoded by the Universal ZK TLV Codec is formatted as a tuple `(Tag, Length, Value)`:

- **Tag**: A 1-byte field identifying the type of the element.
- **Length**: An 8-byte little-endian integer specifying the length of the `Value` field in bytes (for variable-length elements).
- **Value**: The raw serialized data of the element.

The following tags and formats are defined:

- **Field Element (Tag `0x01`)**: Represents a single scalar or field element. The length of a field element is fixed by the field definition, so the `Length` field is omitted. The encoding is:
  
      0x01 || serialized_bytes

- **Byte Array (Tag `0x02`)**: Represents an arbitrary array of bytes. The encoding is:
  
      0x02 || I2OSP(len(bytes), 8) || bytes
  
  where `I2OSP(..., 8)` is formatted in little-endian order.

- **Field Element Array (Tag `0x03`)**: Represents an array of field elements. The encoding is:
  
      0x03 || I2OSP(len(serialized_elements), 8) || serialized_elements
  
  where `serialized_elements` is the concatenation of the serialized field elements in the array.

# Challenge Sampling Algorithms

To support interactive oracle proofs (IOPs) and complex cryptographic protocols, this section standardizes deterministic sampling algorithms from squeezed bytes.

## Bounded Natural Numbers

The minimal bitmask rejection-sampling algorithm `generate_nat` samples an integer uniformly in the range `[0, bound - 1]`.

    generate_nat(state, bound)

    Inputs:
    - state, the transcript state
    - bound, a positive integer

    Outputs:
    - a natural number in the range [0, bound - 1]

    Procedure:
    1. If bound <= 1:
    2.     return 0
    3. k = bit_length(bound - 1)
    4. byte_len = ceil(k / 8)
    5. mask = (1 << k) - 1
    6. while True:
    7.     random_bytes = state.squeeze(byte_len)
    8.     value = OS2IP(random_bytes) & mask
    9.     if value < bound:
   10.         return value

Where `bit_length(x)` is the minimum number of bits needed to represent the integer `x`, and `OS2IP` converts the bytes to an integer (interpreted in big-endian order).

## Combinations without Replacement

The algorithm `generate_nats_wo_replacement` selects `n` distinct elements from a set of size `m` (where `n <= m`) using a virtual Fisher-Yates shuffle.

    generate_nats_wo_replacement(state, n, m)

    Inputs:
    - state, the transcript state
    - n, the number of elements to sample (n <= m)
    - m, the size of the set

    Outputs:
    - a list of n distinct integers in the range [0, m - 1]

    Procedure:
    1. If n > m:
    2.     error("Cannot sample more elements than the set size")
    3. array = {}
    4. result = []
    5. for i in range(n):
    6.     r = generate_nat(state, m - i)
    7.     val_r = array.get(r, r)
    8.     val_last = array.get(m - 1 - i, m - 1 - i)
    9.     result.append(val_r)
   10.     array[r] = val_last
   11. return result

## Sampling from Binary Extension Fields

For interactive oracle proofs (IOPs) over binary extension fields of the form $GF(2^d) \cong GF(2)[X]/(P(X))$ where $P(X)$ is an irreducible polynomial of degree $d$, challenges are sampled as field elements.

To sample a field element:

1. Let $L = \lceil d / 8 \rceil$ be the number of bytes required to represent $d$ bits.
2. Squeeze $L$ bytes from the transcript.
3. Interpret the squeezed bytes as a polynomial $A(X) = \sum_{i=0}^{d-1} a_i X^i$ where:
   - $a_i$ is the $(i \pmod 8)$-th bit of the $\lfloor i / 8 \rfloor$-th byte (with the 0-th bit being the least significant bit).
4. If $8L > d$, any bits at positions $i \ge d$ are ignored (effectively masking the last byte with a bitmask of $(1 \ll (d \bmod 8)) - 1$ if $d \bmod 8 \neq 0$).

For example, in the binary extension field $GF(2^{128})$ defined by the irreducible polynomial $P(X) = X^{128} + X^7 + X^2 + X + 1$:
- We squeeze exactly $16$ bytes ($128$ bits).
- The first byte's least significant bit corresponds to the coefficient of $X^0$.
- The last byte's most significant bit corresponds to the coefficient of $X^{127}$.

--- back

# Test Vectors


{::include ./poc/vectors/duplexSpongeVectors.txt}
