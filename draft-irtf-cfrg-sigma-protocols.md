---
title: "Interactive Sigma Proofs"
category: info

docname: draft-irtf-cfrg-sigma-protocols-latest
submissiontype: independent
number:
date:
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword: ["zero-knowledge", "sigma protocols", "cryptography", "proofs of knowledge"]
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "mmaker/draft-irtf-cfrg-sigma-protocols"
  latest: "https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html"

author:
  - fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"
  - fullname: "Cathie Yun"
    organization: Apple, Inc.
    email: "cathieyun@gmail.com"

normative:
  fiat-shamir: I-D.irtf-cfrg-fiat-shamir

informative:
  SP800:
    title: "Recommendations for Discrete Logarithm-based Cryptography"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  GiacomelliMO16:
    title: "ZKBoo: Faster Zero-Knowledge for Boolean Circuits"
    target: https://eprint.iacr.org/2016/163.pdf
    date: false
    author:
    -
      fullname: "Irene Giacomelli"
    -
      fullname: "Jesper Madsen"
    -
      fullname: "Claudio Orlandi"
  AttemaCK21:
    title: "A Compressed Sigma-Protocol Theory for Lattices"
    target: https://dl.acm.org/doi/10.1007/978-3-030-84245-1_19
    date: false
    author:
    -
      fullname: Thomas Attema
    -
      fullname: Ronald Cramer
    -
      fullname: Lisa Kohl
  BonehS23:
      title: "A Graduate Course in Applied Cryptography"
      target: https://toc.cryptobook.us/
      author:
      -
        fullname: Dan Boneh
      -
        fullname: Victor Shoup
  Stern93:
    title: "A New Identification Scheme Based on Syndrome Decoding"
    target: https://link.springer.com/chapter/10.1007/3-540-48329-2_2
    date: 1993
    author:
      - fullname: "Jacques Stern"
  CramerDS94:
    title: "Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols"
    target: https://ir.cwi.nl/pub/1456/1456D.pdf
    date: 1994
    author:
      - fullname: "Ronald Cramer"
      - fullname: "Ivan Damgaard"
      - fullname: "Berry Schoenmakers"
  Cramer97:
    title: "Modular Design of Secure yet Practical Cryptographic Protocols"
    target: https://ir.cwi.nl/pub/21438
    date: 1997
    author:
      - fullname: "Ronald Cramer"
  CS97:
      title: "Proof Systems for General Statements about Discrete Logarithms"
      author:
        - fullname: "Jan Camenisch"
        - fullname: "Markus Stadler"
      target: https://crypto.ethz.ch/publications/files/CamSta97b.pdf
  FIPS.186-5: DOI.10.6028/NIST.FIPS.186-5
  FIPS-202: DOI.10.6028/NIST.FIPS.202
  CVE-2020-0601:
    title: "CVE-2020-0601: Windows CryptoAPI Spoofing Vulnerability (CurveBall)"
    target: https://nvd.nist.gov/vuln/detail/CVE-2020-0601
    date: 2020
  CVE-2022-21449:
    title: "CVE-2022-21449: Improper ECDSA signature verification in Java SE / GraalVM (Psychic Signatures)"
    target: https://nvd.nist.gov/vuln/detail/CVE-2022-21449
    date: 2022
  CVE-2022-23806:
    title: "CVE-2022-23806: crypto/elliptic Curve.IsOnCurve returns true for non-canonical field elements in Go"
    target: https://nvd.nist.gov/vuln/detail/CVE-2022-23806
    date: 2022
  CVE-2024-42461:
    title: "CVE-2024-42461: ECDSA signature malleability from BER-encoded signatures in the elliptic package"
    target: https://nvd.nist.gov/vuln/detail/CVE-2024-42461
    date: 2024
  JagerSS15:
    title: "Practical Invalid Curve Attacks on TLS-ECDH"
    target: https://doi.org/10.1007/978-3-319-24174-6_21
    date: 2015
    author:
      - fullname: "Tibor Jager"
      - fullname: "Jörg Schwenk"
      - fullname: "Juraj Somorovsky"

--- abstract

A Sigma Protocol is an interactive zero-knowledge proof of knowledge that allows a prover to convince a verifier of the validity of a statement. It satisfies the properties of completeness, soundness, and zero-knowledge, as described in {{security-considerations}}.

This document describes Sigma Protocols for proving knowledge of pre-images of linear maps in prime-order elliptic curve groups. Examples include zero-knowledge proofs for discrete logarithm relations, ElGamal encryptions, Pedersen commitments, and range proofs.

--- middle

# Introduction

A Sigma Protocol is an interactive proof with the following flow:

~~~ aasvg
+----------------------+                       +----------------------+
|        Prover        |                       |       Verifier       |
|  witness, instance   |                       |       instance       |
+----------------------+                       +----------------------+
          |                                                |
          | prover_commit(witness, rng)                    |
          | commitment                                     |
          |----------------------------------------------->|
          |                                                |
          |                             challenge          |
          |                             random_scalar()    |
          |<-----------------------------------------------|
          |                                                |
          | prover_response(prover_state, challenge)       |
          | response                                       |
          |----------------------------------------------->|
          |                                                |
          |                         verify transcript      |
          |                         accept or reject       |
~~~
{: #fig-sigma-proofs title="Flow of an interactive sigma protocol."}

 The messages are respectively called *commitment* (computed by the prover), *challenge* (randomly sampled from a specific distribution), and *response* (computed by the prover). The prover keeps `prover_state` private between the first and third messages. The public transcript checked by the verifier is `(commitment, challenge, response)`.

 One of the advantages of Sigma Protocols is their composability, which enables the construction of more complex protocols. A classic example is the OR composition {{CramerDS94}}. Given a Sigma Protocol for `N` relations, it is possible to prove knowledge of one of `N` witnesses for those relations. The composed sigma protocols can be made non-interactive using the Fiat-Shamir transformation {{Cramer97}}. However, such compositions must be handled carefully to preserve security properties as discussed in {{security-considerations}}.

# Terminology and conventions in this document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

The following notation is used throughout this document.

# Core interface {#core-interface}

The public functions are obtained relying on an internal structure containing the definition of a Sigma Protocol.

~~~
class SigmaProtocol:
   def new(instance) -> SigmaProtocol
   def prover_commit(self, witness, rng) -> (commitment, prover_state)
   def prover_response(self, prover_state, challenge) -> response
   def verifier(self, commitment, challenge, response) -> bool
   def serialize_commitment(self, commitment) -> bytes
   def serialize_challenge(self, challenge) -> bytes
   def serialize_response(self, response) -> bytes
   def deserialize_commitment(self, data: bytes) -> commitment
   def deserialize_challenge(self, data: bytes) -> challenge
   def deserialize_response(self, data: bytes) -> response
   # optional
   def simulate_response(self, rng) -> response
   # optional
   def simulate_commitment(self, response, challenge) -> commitment
~~~

Where:

- `new(instance) -> SigmaProtocol`, denoting the initialization function. This function takes as input an instance generated via a `LinearRelation`, the public information shared between prover and verifier.

- `prover_commit(self, witness: Witness, rng) -> (commitment, prover_state)`, denoting the **commitment phase**, that is, the computation of the first message sent by the prover in a Sigma Protocol. This method outputs a new commitment together with its associated prover state, depending on the witness known to the prover, the statement to be proven, and a random number generator `rng` as defined in {{rng-definition}}. This step generally requires access to a high-quality entropy source to perform the commitment. Leakage of even just a few bits of the commitment could allow for the complete recovery of the witness. The commitment is meant to be shared, while `prover_state` must be kept secret.

- `prover_response(self, prover_state, challenge) -> response`, denoting the **response phase**, that is, the computation of the second message sent by the prover, depending on the witness, the statement, the challenge received from the verifier, and the internal state `prover_state`. The return value response is a public value and is transmitted to the verifier.

- `verifier(self, commitment, challenge, response) -> bool`, denoting the **verifier algorithm**. This method checks that the protocol transcript is valid for the given statement. The verifier algorithm outputs true if verification succeeds, or false if verification fails.

- `serialize_commitment(self, commitment) -> bytes`, serializes the commitment into a canonical byte representation.

- `serialize_challenge(self, challenge) -> bytes`, serializes the challenge scalar into a canonical byte representation. Used by the compact proof flavor ({{sigma-narg}}).

- `serialize_response(self, response) -> bytes`, serializes the response into a canonical byte representation.

- `deserialize_commitment(self, data: bytes) -> commitment`, deserializes a byte array into a commitment. This function can raise a `DeserializeError` if deserialization fails.

- `deserialize_challenge(self, data: bytes) -> challenge`, deserializes a byte array into a challenge scalar. This function can raise a `DeserializeError` if deserialization fails.

- `deserialize_response(self, data: bytes) -> response`, deserializes a byte array into a response. This function can raise a `DeserializeError` if deserialization fails.

The final two algorithms describe the **zero-knowledge simulator**. In particular, they may be used for proof composition (e.g. OR-composition). The function `simulate_commitment` is also used when verifying short proofs. We have:

- `simulate_response(self, rng) -> response`, denoting the first stage of the simulator.

- `simulate_commitment(self, response, challenge) -> commitment`, returning a simulated commitment -- the second phase of the zero-knowledge simulator.

The simulated transcript `(commitment, challenge, response)` must be indistinguishable from the one generated using the prover algorithms.

The abstraction `SigmaProtocol` allows implementing different types of statements and combiners of those, such as OR statements, validity of t-out-of-n statements, and more.



## Randomized algorithms {#rng-definition}

The generation of proofs involves randomized algorithms that take as
input a source of randomness, denoted as `rng`.
The functionality required in this document is a secure way to sample
non-zero scalars uniformly at random.
Algorithms access this functionality through the following interface.

~~~
class CSRNG(ABC):
    def getrandom(self, length: int) -> bytes:
        pass

    def random_scalar(self) -> groups.Scalar:
        pass
~~~

Implementations MUST use a cryptographically secure pseudorandom number
generator (CSPRNG) to sample non-zero scalars either by using rejection
sampling methods or reducing a large bitstring modulo the group order.
Refer to Section A.4 of {{FIPS.186-5}} for guidance about these methods.

# Sigma Protocols over prime-order groups {#sigma-protocol-group}

The following sub-section presents concrete instantiations of Sigma Protocols over prime-order elliptic curve groups.
It relies on a prime-order elliptic-curve group as described in {{group-abstraction}}.

Valid choices of elliptic curves can be found in {{ciphersuites}}.

Traditionally, Sigma Protocols are defined in Camenisch-Stadler {{CS97}} notation as (for example):

~~~
1. DLEQ(G, H, X, Y) = PoK{
2.   (x):        // Secret variables
3.   X = x * G, Y = x * H        // Predicates to satisfy
4. }
~~~

In the above, line 1 declares that the proof name is "DLEQ", the public information (the **instance**) consists of the group elements `(G, X, H, Y)` denoted in upper-case.
Line 2 states that the private information (the **witness**) consists of the scalar `x`.
Finally, line 3 states that the linear relation that needs to be proven is
`x * G = X` and `x * H = Y`.

## Group abstraction {#group-abstraction}

Because of their dominance, the presentation in the following focuses on proof goals over elliptic curves, therefore leveraging additive notation. For prime-order subgroups of residue classes, all notation needs to be changed to multiplicative, and references to elliptic curves (e.g., curve) need to be replaced by their respective counterparts over residue classes.

We detail the functions that can be invoked on these objects. Example choices can be found in {{ciphersuites}}.

### Group {#group}

- `identity()`, returns the neutral element in the group.
- `generator()`, returns the generator of the prime-order elliptic-curve subgroup used for cryptographic operations.
- `order()`: returns the order of the group `p`.
- `serialize(elements: [Group; N])`, serializes a list of group elements and returns a canonical byte array `buf` of fixed length `Ne * N`.
- `deserialize(buffer)`, attempts to map a byte array `buffer` of size `Ne * N` into `[Group; N]`. Each element **MUST** be the canonical encoding of a valid group element: the decoded point **MUST** lie on the curve and in the prime-order group, and the identity element as well as any non-canonical encoding **MUST** be rejected. These checks are not optional; omitting them enables invalid-curve and spoofing attacks ({{sigma-ni-security}}). This function can raise a `DeserializeError` if deserialization fails.
- `add(element: Group)`, implements elliptic curve addition for the two group elements.
- `equal(element: Group)`, returns `true` if the two elements are the same and `false` otherwise.
- `scalar_mul(scalar: Scalar)`, implements scalar multiplication for a group element by an element in its respective scalar field.

In this spec, instead of `add` we will use `+` with infix notation; instead of `equal` we will use `==`, and instead of `scalar_mul` we will use `*`. A similar behavior can be achieved using operator overloading.

### Scalar

- `identity()`: outputs the (additive) identity element in the scalar field.
- `add(scalar: Scalar)`: implements field addition for the elements in the field.
- `mul(scalar: Scalar)`, implements field multiplication.
- `random(rng)`: samples a scalar from the RNG. Securely decoding random bytes into a random scalar is described by the unsigned-integer decoding of {{fiat-shamir}}.
- `serialize(scalars: list[Scalar; N])`: serializes a list of scalars and returns their canonical representation of fixed length `Ns * N`.
- `deserialize(buffer)`, attempts to map a byte array `buffer` of size `Ns * N` into `[Scalar; N]`. Each scalar **MUST** be the canonical representative in the range `[0, p)`, where `p` is the group order; any non-canonical or out-of-range encoding **MUST** be rejected ({{sigma-ni-security}}). This function can raise a `DeserializeError` if deserialization fails.

In this spec, instead of `add` we will use `+` with infix notation; instead of `equal` we will use `==`, and instead of `mul` we will use `*`. A similar behavior can be achieved using operator overloading.


## Proofs of preimage of a linear map

### Witness representation {#witness}

A witness is an array of scalar elements. The length of the array is denoted `num_scalars`.

~~~
Witness = [Scalar; num_scalars]
~~~

### Linear map {#linear-map}

A _linear map_ takes a `Witness` (an array of `num_scalars` in the scalar field) and maps it to an array of group elements. The length of the image is denoted `num_elements`.

Linear maps can be represented as matrix-vector multiplications, where the multiplication is the elliptic curve scalar multiplication defined in {{group-abstraction}}.

Since the matrix is oftentimes sparse, it is stored in Yale sparse matrix format.

Here is an example:

~~~
class LinearCombination:
    scalar_indices: list[int]
    element_indices: list[int]
~~~

The linear map can then be presented as:

~~~
class LinearMap:
    Group: groups.Group
    linear_combinations: list[LinearCombination]
    group_elements: list[Group]
    num_scalars: int
    num_elements: int

    def map(self, scalars: list[Group.ScalarField; num_scalars]) -> list[Group; num_elements]
~~~

#### Initialization

The linear map `LinearMap` is initialized with

~~~
linear_combinations = []
group_elements = []
num_scalars = 0
num_elements = 0
~~~

#### Linear map evaluation

A witness can be mapped to a vector of group elements via:

~~~
map(self, scalars: [Scalar; num_scalars]) -> list[Group; num_elements]

Inputs:

- self, the current state of the constraint system
- scalars, an array of num_scalars scalars

1. image = []
2. for linear_combination in self.linear_combinations:
3.     coefficients = [scalars[i] for i in linear_combination.scalar_indices]
4.     elements = [self.group_elements[i] for i in linear_combination.element_indices]
5.     image.append(self.Group.msm(coefficients, elements))
6. return image
~~~

### Statements for linear relations

A `LinearRelation` encodes a proof statement of the form `linear_map(witness) = image`, and is used to prove knowledge of a witness that produces `image` under linear map.
It internally stores `linear_map` (cf. {{linear-map}}) and an `image` (an array of `num_elements` Group elements).

~~~
class LinearRelation:
    Domain = group.ScalarField
    Image = group.Group

    linear_map = LinearMap
    image = list[group.Group]

    def allocate_scalars(self, n: int) -> list[int]
    def allocate_elements(self, n: int) -> list[int]
    def append_equation(self, lhs: int, rhs: list[(int, int)]) -> None
    def set_elements(self, elements: list[(int, Group)]) -> None
~~~

#### Element and scalar variables allocation

Two functions allow to allocate the new scalars (the witness) and group elements (the instance).

~~~
allocate_scalars(self, n)

Inputs:
    - self, the current state of the LinearRelation
    - n, the number of scalars to allocate
Outputs:
    - indices, a list of integers each pointing to the new allocated scalars

Procedure:

1. indices = range(self.num_scalars, self.num_scalars + n)
2. self.num_scalars += n
3. return indices
~~~

and below the allocation of group elements

~~~
allocate_elements(self, n)

Inputs:
    - self, the current state of the LinearRelation
    - n, the number of elements to allocate
Outputs:
    - indices, a list of integers each pointing to the new allocated elements

Procedure:

1. indices = range(self.num_elements, self.num_elements + n)
2. self.num_elements += n
3. return indices
~~~

Group elements, being part of the instance, can later be set using the function `set_elements`

~~~
set_elements(self, elements)

Inputs:
    - self, the current state of the LinearRelation
    - elements, a list of pairs of indices and group elements to be set

Procedure:

1. for index, element in elements:
2.   self.linear_map.group_elements[index] = element
~~~

#### Enforcing constraints

~~~
append_equation(self, lhs, rhs)

Inputs:

- self, the current state of the constraint system
- lhs, the left-hand side of the equation
- rhs, the right-hand side of the equation (a list of (ScalarIndex, GroupEltIndex) pairs)

Outputs:

- An Equation instance that enforces the desired relation

Procedure:

1. linear_combination = LinearMap.LinearCombination(scalar_indices=[x[0] for x in rhs], element_indices=[x[1] for x in rhs])
2. self.linear_map.append(linear_combination)
3. self._image.append(lhs)
~~~

### Serializing linear relations {#serialize-linear-relations}

A `LinearRelation` is serialized as a sparse matrix in row-major order, followed by the group elements of the instance. The sparse matrix lists the constraints (equations) in the order they were appended; each constraint is given as the index of its image (left-hand side) element, the number of terms on its right-hand side, and the `(scalar index, element index)` pairs of those terms ({{linear-map}}). The serialized group elements of the linear map are then appended. All group elements **MUST** be set. Scalar variables that were allocated but never used in a constraint are not statement components **MUST NOT** be represented.

Counts and indices are encoded as 4-byte big-endian unsigned integers via `I2OSP` ({{fiat-shamir}}); each such value MUST be less than `2^32`. The procedure assumes every group element of the relation has been set ({{group-abstraction}}).

~~~
SerializeLinearRelation(relation)

Input:

- relation, a linear relation.

Output:

- a byte string

Procedure:

 1. linear_map = relation.linear_map
 2. constraints = linear_map.linear_combinations
 3. out = ""
 4. out = out || I2OSP(len(constraints), 4)
 4. for i in range(len(constraints)):
 5.     out = out || I2OSP(relation.image[i], 4)
 6.     terms = constraints[i]
 7.     out = out || I2OSP(len(terms.scalar_indices), 4)
 8.     for j in range(len(terms.scalar_indices)):
 9.         out = out || I2OSP(terms.scalar_indices[j], 4)
10.         out = out || I2OSP(terms.element_indices[j], 4)
11. return out || Group.serialize(linear_map.group_elements)
~~~

Here `relation.image[i]` is the index of the image (left-hand side) element of the `i`-th constraint, and each right-hand side term `(scalar_indices[j], element_indices[j])` pairs a scalar (witness) index ({{witness}}) with a group-element index.

The encoding binds the entire statement: the shape of the linear map (the number of constraints and the indices wired into each one) together with every group element of the instance. For a fixed relation the output has a fixed length, so it is non-empty and prefix-free, as required of the instance encoding by {{fiat-shamir}}.

### Core protocol

This defines the object `SchnorrProof`. The initialization function takes as input the statement, and pre-processes it.

### Prover procedures

The prover of a Sigma Protocol is stateful and will send two messages, a "commitment" and a "response" message, described below.

#### Prover commitment

~~~
prover_commit(self, witness, rng)

Inputs:

- witness, an array of scalars
- rng, a cryptographically secure random number generator

Outputs:

- A (private) prover state, holding the information of the interactive prover necessary for producing the protocol response
- A (public) commitment message, an element of the linear map image, that is, a vector of group elements.

Procedure:

1. nonces = [rng.random_scalar() for _ in range(self.instance.linear_map.num_scalars)]
2. prover_state = self.ProverState(witness, nonces)
3. commitment = self.instance.linear_map(nonces)
4. return (prover_state, commitment)
~~~

#### Prover response

~~~
prover_response(self, prover_state, challenge)

Inputs:

    - prover_state, the current state of the prover
    - challenge, the verifier challenge scalar

Outputs:

    - An array of scalar elements composing the response

Procedure:

1. witness, nonces = prover_state
2. return [nonces[i] + witness[i] * challenge for i in range(self.instance.linear_map.num_scalars)]
~~~

### Verifier

~~~
verify(self, commitment, challenge, response)

Inputs:

- self, the current state of the SigmaProtocol
- commitment, the commitment generated by the prover
- challenge, the challenge generated by the verifier
- response, the response generated by the prover

Outputs:

- A boolean indicating whether the verification succeeded

Procedure:

1. assert len(commitment) == self.instance.linear_map.num_constraints and len(response) == self.instance.linear_map.num_scalars
2. expected = self.instance.linear_map(response)
3. got = [commitment[i] + self.instance.image[i] * challenge for i in range(self.instance.linear_map.num_constraints)]
4. return got == expected
~~~

### Example: Schnorr proofs

The statement represented in {{sigma-protocol-group}} can be written as:

~~~
statement = LinearRelation(group)
[var_x] = statement.allocate_scalars(1)
[var_G, var_X] = statement.allocate_elements(2)
statement.append_equation(var_X, [(var_x, var_G)])
~~~

At which point it is possible to set `var_G` and `var_X` whenever the group elements are at disposal.

~~~
G = group.generator()
statement.set_elements([(var_G, G), (var_X, X)])
~~~

It is worth noting that in the above example, `[X] == statement.linear_map.map([x])`.

### Example: DLEQ proofs

A DLEQ proof proves a statement:

~~~
DLEQ(G, H, X, Y) = PoK{(x): X = x * G, Y = x * H}
~~~

Given group elements `G`, `H` and `X`, `Y` such that `x * G = X` and `x * H = Y`, then the statement is generated as:

~~~
1. statement = LinearRelation(group)
2. [var_x] = statement.allocate_scalars(1)
3. [var_G, var_X, var_H, var_Y] = statement.allocate_elements(4)
4. statement.set_elements([(var_G, G), (var_H, H), (var_X, X), (var_Y, Y)])
5. statement.append_equation(var_X, [(var_x, var_G)])
6. statement.append_equation(var_Y, [(var_x, var_H)])
~~~

### Example: Pedersen commitments

A representation proof proves a statement

~~~
REPR(G, H, C) = PoK{(x, r): C = x * G + r * H}
~~~

Given group elements `G`, `H` such that `C = x * G + r * H`, then the statement is generated as:

~~~
1. statement = LinearRelation(group)
2. var_x, var_r = statement.allocate_scalars(2)
3. [var_G, var_H, var_C] = statement.allocate_elements(3)
4. statement.set_elements([(var_G, G), (var_H, H), (var_C, C)])
5. statement.append_equation(var_C, [(var_x, var_G), (var_r, var_H)])
~~~

## Ciphersuites {#ciphersuites}

We consider ciphersuites of prime-order elliptic curve groups.

### P-256 (secp256r1)

This ciphersuite uses P-256 {{SP800}} for the Group.

#### Elliptic curve group of P-256 (secp256r1) {{SP800}}

- `order()`: Return the integer `115792089210356248762697446949407573529996955224135760342422259061068512044369`.
- `serialize([A])`: Implemented using the compressed Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}}; `Ne = 33`.
- `deserialize(buf)`: Implemented by attempting to read `buf` into chunks of 33-byte arrays and convert them using the compressed Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and then performs partial public-key validation as defined in section 5.6.2.3.4 of {{!KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar3}}. This includes checking that the coordinates of the resulting point are in the correct range, that the point is on the curve, and that the point is not the point at infinity.

#### Scalar Field of P-256

- `serialize(s)`: Relies on the Field-Element-to-Octet-String conversion according to {{SEC1}}; `Ns = 32`.
- `deserialize(buf)`: Reads the byte array `buf` in chunks of 32 bytes using Octet-String-to-Field-Element from {{SEC1}}. This function can fail if the input does not represent a Scalar in the range `[0, G.Order() - 1]`.

### BLS12-381 (G1)

This ciphersuite uses the prime-order subgroup G1 of the BLS12-381 elliptic curve {{!RFC9380}} for the Group.

#### Elliptic curve group of BLS12-381 (G1) {{!RFC9380}}

- `order()`: Return the integer `52435875175126190479447740508185965837690552500527637822603658699938581184513`.
- `serialize([A])`: Implemented using the compressed serialization for G1 points defined in Appendix C of {{!PAIRING=I-D.irtf-cfrg-pairing-friendly-curves}}; `Ne = 48`.
- `deserialize(buf)`: Reads `buf` in chunks of 48 bytes and inverts the compressed serialization above. It performs full point validation: that the encoding is canonical (the x-coordinate is less than the field characteristic and the metadata bits are consistent), that the resulting point is on the curve, and that it lies in the prime-order subgroup G1. The point at infinity is rejected. This function can raise a `DeserializeError` if deserialization fails.

#### Scalar Field of BLS12-381

- `serialize(s)`: Relies on the big-endian fixed-length integer encoding `I2OSP` ({{fiat-shamir}}); `Ns = 32`.
- `deserialize(buf)`: Reads the byte array `buf` in chunks of 32 bytes using `OS2IP` ({{fiat-shamir}}). This function can fail if the input does not represent a Scalar in the range `[0, G.Order() - 1]`.

# Non-interactive Sigma Protocols {#non-interactive}

The Fiat-Shamir transformation applied to Sigma Protocols yields a non-interactive zero-knowledge argument of knowledge. This section bridges the transformation described in {{fiat-shamir}} with Sigma Protocols.

The challenge for linear relations for a duplex sponge `DS` is derived as:

~~~
duplex_sponge = DS.Init(session_id)
duplex_sponge.Absorb(encode[0](instance))
duplex_sponge.Absorb(Group.serialize(commitment))
challenge = DecodeField(duplex_sponge.Squeeze(Ns + 16), p, 1)
~~~

For example, in the case of `SHAKE128`, for a linear relation over an odd prime-order field, the Fiat-Shamir transformation boils down to:

~~~
verifier_msg[1] := DecodeField(SHAKE128(
                       session_id || zeros(R - 32)
                       || encode[0](instance)
                       || encode[1](prover_msg[1]),
                   (Ns + 16) * 8))
~~~

Using the notation in {{fiat-shamir}}, Sigma Protocols for Linear Relations have `k=2` rounds with `verifier_message[2] = ""`, `encode[0] = SerializeLinearRelation`, `encode[1] = Group.serialize`, and `decode[1] = DecodeField`. The security requirements of the session identifier `session_id` are discussed in {{sigma-proofs-tag}}. The actual choices of `DecodeField` are discussed in {{sigma-proofs-challenge-decoding}}.

## Codecs {#sigma-mapping}

The codecs of {{fiat-shamir}} are instantiated as follows.

### Instance encoding {#sigma-instance-encoding}

The instance encoding `encode[0]` is the serialization of the linear map and the image, produced by `SerializeLinearRelation` ({{serialize-linear-relations}}).

~~~
encode[0](instance)

Input: instance, a linear relation

Output: a byte string

return SerializeLinearRelation(instance)
~~~

### Commitment encoding

The commitment encoding, `encode[1]` in {{fiat-shamir}} is the encoding of the serialized group elements, seen as a fixed-length sequence of messages.

~~~
encode[1](commitment)

Input: commitment, a vector of group elements

Output: a byte string

return Group.serialize(commitment)
~~~

## Challenge decoding {#sigma-proofs-challenge-decoding}

The challenge decoding, `decode[1]` in {{fiat-shamir}}, is the procedure `DecodeField` of {{fiat-shamir}}, and is subject to the same security requirements.

~~~
decode[1](s)

Input: s, a uniformly-distributed byte string

Output: a scalar field element

DecodeField(s, p, m)
~~~

## Tag and session identifier {#sigma-proofs-tag}

The session identifier `session_id` is a 32-byte string. It **SHOULD** be derived from a string `tag` using `DeriveSessionID` of {{fiat-shamir}}. The prover and verifier initialize their duplex sponge state from it ({{non-interactive}}).

The `tag` is a byte string following the security requirements on the session identifier in {{fiat-shamir}}.

As an example, consider a fictional application named Foo. A reasonable choice of `tag` for a _batchable proof_ is:

~~~
FOO-{xx}-{tttt}-DSFS-{hashID}-SIGMA-PROOFS-{yy}
~~~

where `xx` is the two-digit number indicating the version, `yy` is the two-digit number indicating the elliptic-curve ciphersuite, `hashID` is the hash identifier, and `tttt` is a 32-bit integer identifying the epoch.

As another example, a `tag` for a _compact proof_ is:

~~~
FOO-{xx}-{tttt}-CMPT-{hashID}-SIGMA-PROOFS-{yy}
~~~

where `xx` is the two-digit number indicating the version, `yy` is the two-digit number indicating the elliptic-curve ciphersuite, `hashID` is the hash identifier, and `tttt` is a 32-bit integer identifying the epoch as above.

## Non-interactive argument string serialization {#sigma-narg}

Two serialization flavors are possible for Sigma Protocols:

- A **batchable** NARG string serializes the prover messages `(commitment, response)`, as in {{fiat-shamir}}, and it permits batch verification of several proofs at once. The final proof is `Ne * num_equations + Ns * num_scalars` bytes.
- A **compact** NARG string serializes `(challenge, response)`. It is preferable in the common cases, and whenever the commitment (`num_constraints` group elements) is larger than a single challenge scalar. The final proof is `Ns * (num_scalars + 1)` bytes long.

## Batchable

A **batchable** NARG string is the generic transformation ({{fiat-shamir}}), consisting of the concatenation of the prover messages `serialize(commitment) || serialize(response)`.

~~~
prove_batchable(tag, instance, witness, rng)

Inputs:

- tag, a byte string identifying the application and protocol
- instance, the LinearRelation to be proven
- witness, the prover's secret witness
- rng, a cryptographically secure random number generator ({{rng-definition}})

Outputs:

- the batchable proof, a byte string

Procedure:

1. protocol = SchnorrProof.new(instance)
2. session_id = DeriveSessionID(tag)
3. duplex_sponge = DS.Init(session_id)
4. duplex_sponge.Absorb(encode[0](instance))
5. (commitment, prover_state) = protocol.prover_commit(witness, rng)
6. duplex_sponge.Absorb(protocol.serialize_commitment(commitment))
7. challenge = DecodeField(duplex_sponge.Squeeze(Ns + 16), p, 1)
8. response = protocol.prover_response(prover_state, challenge)
9. return protocol.serialize_commitment(commitment)
          || protocol.serialize_response(response)
~~~

Let `Ne` and `Ns` be the element and scalar byte lengths of the ciphersuite ({{ciphersuites}}).

~~~
verify_batchable(tag, instance, proof)

Inputs:

- tag, a byte string identifying the application and protocol
- instance, the LinearRelation to be proven; it MUST be the same as the one used by the prover
- proof, the batchable proof byte string

Outputs:

- a boolean indicating whether the proof is valid

Procedure:

 1. protocol = SchnorrProof.new(instance)
 2. Nc = protocol.instance.linear_map.num_constraints * Ne
 3. Nr = protocol.instance.linear_map.num_scalars * Ns
 4. fail if len(proof) != Nc + Nr
 5. session_id = DeriveSessionID(tag)
 6. duplex_sponge = DS.Init(session_id)
 7. duplex_sponge.Absorb(encode[0](instance))
 8. commitment = Group.deserialize(proof[0 : Nc])
 9. response = Scalar.deserialize(proof[Nc : Nc + Nr])
10. duplex_sponge.Absorb(protocol.serialize_commitment(commitment))
11. challenge = DecodeField(duplex_sponge.Squeeze(Ns + 16), p, 1)
12. return protocol.verifier(commitment, challenge, response)
~~~

## Compact

A **compact** proof serializes `serialize(challenge) || serialize(response)`. The Sigma Protocol transcript is recovered invoking the simulator.

~~~
prove_compact(tag, instance, witness, rng)

Inputs:

- tag, a byte string identifying the application and protocol
- instance, the LinearRelation to be proven
- witness, the prover's secret witness
- rng, a cryptographically secure random number generator ({{rng-definition}})

Outputs:

- the compact proof, a byte string

Procedure:

1. protocol = SchnorrProof.new(instance)
2. session_id = DeriveSessionID(tag)
3. duplex_sponge = DS.Init(session_id)
4. duplex_sponge.Absorb(encode[0](instance))
5. (commitment, prover_state) = protocol.prover_commit(witness, rng)
6. duplex_sponge.Absorb(protocol.serialize_commitment(commitment))
7. challenge = DecodeField(duplex_sponge.Squeeze(Ns + 16), p, 1)
8. response = protocol.prover_response(prover_state, challenge)
9. return protocol.serialize_challenge(challenge)
          || protocol.serialize_response(response)
~~~

The verifier recomputes the commitment from the challenge and response via `simulate_commitment` ({{core-interface}}), then recomputes the challenge from that commitment and accepts only if it matches the one in the proof. Let `Ns` be the scalar byte length of the ciphersuite ({{ciphersuites}}).

~~~
verify_compact(tag, instance, proof)

Inputs:

- tag, a byte string identifying the application and protocol
- instance, the LinearRelation to be proven; it MUST be the same as the one used by the prover
- proof, the compact proof byte string

Outputs:

- a boolean indicating whether the proof is valid

Procedure:

 1. protocol = SchnorrProof.new(instance)
 2. Nch = Ns
 3. Nr = protocol.instance.linear_map.num_scalars * Ns
 4. fail if len(proof) != Nch + Nr
 5. challenge = protocol.deserialize_challenge(proof[0 : Nch])
 6. response = Scalar.deserialize(proof[Nch : Nch + Nr])
 7. commitment = protocol.simulate_commitment(response, challenge)
 8. session_id = DeriveSessionID(tag)
 9. duplex_sponge = DS.Init(session_id)
10. duplex_sponge.Absorb(encode[0](instance))
11. duplex_sponge.Absorb(protocol.serialize_commitment(commitment))
12. expected_challenge = DecodeField(duplex_sponge.Squeeze(Ns + 16), p, 1)
13. return challenge == expected_challenge
~~~

Note that since the simulator always outputs valid proofs, there is no need to run the verifier in this case.

## Security considerations for the transformation {#sigma-ni-security}

The security considerations of {{fiat-shamir}} apply also here. In particular:

- **Security level.** The knowledge-soundness error is governed by the size of the challenge set, the full scalar field of order `p`, together with the random-oracle loss analyzed in {{fiat-shamir}}.
- **Instance binding.** Soundness holds only if the encoded instance binds the entire statement ({{sigma-instance-encoding}}); omitting any generator or image element is a weak Fiat-Shamir vulnerability.
- **Verifier input validation.** The NARG string is untrusted input. Verifiers **MUST** check the proof length (no trailing bytes) and reject malformed encodings before performing any algebraic check. For group elements, deserialization **MUST** verify that each point is canonically encoded, lies on the curve, and lies in the prime-order group. In particular, the latter requires a subgroup-membership check when the group cofactor is greater than one ({{group-abstraction}}). For instance, skipping on-curve or subgroup check enables invalid-curve attacks {{JagerSS15}}; accepting non-canoical field elements {{CVE-2022-23806}}. The session identifier, the NARG string, and the instance are to be considered malicious inputs. For instance, invalid group parameters have previously caused bugs as in {{CVE-2020-0601}}. The identity element **MUST** be rejected ({{group-abstraction}}). For scalars, deserialization MUST reject any value that is not the canonical representative in `[0, p)`; failing to check that signature or response components are in range and nonzero is the validation-skip class behind {{CVE-2022-21449}}, and admitting non-canonical encodings of the same value yields proof malleability {{CVE-2024-42461}}. For compact proofs, the verifier **MUST** recompute the challenge and compare it before accepting.
- **Prover randomness.** Zero-knowledge requires fresh randomness for each proof; reusing or correlating nonces across proofs can leak the witness ({{core-interface}}, {{fiat-shamir}}).
- **Post-quantum.** The hardness of the proved relation rests on the discrete logarithm problem, so these proofs are not post-quantum sound; see {{post-quantum-security-considerations}}.

## Suites {#ni-ciphersuites}

This section lists the ciphersuites for the non-interactive sigma protocol.

A suite is composed of the following parameters:

- an elliptic curve suite ({{ciphersuites}}),
- a duplex sponge ({{fiat-shamir}}).

The ciphersuites defined by this document, and the identifiers used by the test vectors, are:

| Identifier | Group | Duplex Sponge | Security |
|---|---|---|---|
| `Shake128_P256_` | P-256 (secp256r1) | SHAKE128 | 128-bit pre-quantum |
| `Shake128_BLS12381_` | BLS12-381 (G1) | SHAKE128 | 128-bit pre-quantum |
{: #tab-ni-ciphersuites title="Non-interactive Sigma Protocol ciphersuites"}

Each row uses the `SchnorrProof` of {{sigma-protocol-group}} over the named group. `Ne` and `Ns` are the element and scalar byte lengths of that group.

The ciphersuite identifier is a natural component of the `tag` ({{fiat-shamir}}), since it fixes the group, the codecs, and the hash instantiation.

# Security Considerations {#security-considerations}

Interactive Sigma Protocols have the following properties:

- **Knowledge soundness**: If the proof is valid, the prover must have knowledge of a secret witness satisfying the proof statement. This property ensures that valid proofs cannot be generated without possession of the corresponding witness.

- **Honest verifier zero-knowledge**: The proof string produced by the `prove` function does not reveal any information beyond what can be directly inferred from the statement itself. This ensures that honest verifiers gain no knowledge about the witness.

- **Completeness**: If the statement being proved is true, an honest verifier can be convinced of this fact by an honest prover via the proof.

- **Deniable**: Because Interactive Sigma Protocols don't have transferable message authenticity, a third party (not the prover or verifier) cannot be convinced that the prover made the proof. This means that the Sigma Protocol interaction is not transferable as evidence to a third party.

## Privacy Considerations

Sigma Protocols are insecure against malicious verifiers and should not be used.
The non-interactive Fiat-Shamir transformation leads to publicly verifiable (transferable) proofs that are statistically zero-knowledge.

## Constant-Time Requirements

The prover's control flow and memory access patterns are typically influenced by the witness.
To prevent side-channel leakage of witness information, which may reveal private values, it is important that the implementation of underlying group and field operations are constant-time. Operations such as modular reduction, scalar multiplication, random value generation, and all other group and field operations are required to be constant-time especially when working with inputs which are private to prevent side-channel attacks which may reveal their values. In some cases, such as keyed-verification credentials, also the verifier must be constant-time.
Implementations MUST securely delete prover state as soon as it is no longer needed, and SHOULD minimize the lifetime of sensitive material (witness and instance), explicitly zeroize temporary buffers after proof generation, use secure de-allocation mechanisms when available, and reduce exposure in crash dumps, swap/page files, and diagnostic logging.

# Post-Quantum Security Considerations {#post-quantum-security-considerations}

The zero-knowledge proofs described in this document provide statistical zero-knowledge and statistical soundness properties when modeled in the random oracle model.

## Privacy Considerations

These proofs offer zero-knowledge guarantees, meaning they do not leak any information about the prover's witness beyond what can be inferred from the proven statement itself. This property holds even against quantum adversaries with unbounded computational power.

Specifically, these proofs can be used to protect privacy against post-quantum adversaries, in applications demanding:

- Post-quantum anonymity
- Post-quantum unlinkability
- Post-quantum blindness
- Protection against "harvest now, decrypt later" attacks.

## Soundness Considerations

While the proofs themselves offer privacy protections against quantum adversaries, the hardness of the relation being proven depends (at best) on the hardness of the discrete logarithm problem over the elliptic curves specified in {{ciphersuites}}.
Since this problem is known to be efficiently solvable by quantum computers using Shor's algorithm, these proofs MUST NOT be relied upon for post-quantum soundness guarantees.

Implementations requiring post-quantum soundness SHOULD transition to alternative proof systems such as:

- MPC-in-the-Head approaches as described in {{GiacomelliMO16}}
- Lattice-based approaches as described in {{AttemaCK21}}
- Code-based approaches as described in {{Stern93}}

Implementations should consider the timeline for quantum computing advances when planning migration to post-quantum sound alternatives.
Implementers MAY adopt a hybrid approach during migration to post-quantum security by using AND composition of proofs. This approach enables gradual migration while maintaining security against classical adversaries.
This composition retains soundness if **both** problems remain hard. AND composition of proofs is NOT described in this specification, but examples may be found in the proof-of-concept implementation and in {{BonehS23}}.

# Acknowledgments
{:numbered="false"}

The authors thank Jan Bobolz, Vishruti Ganesh, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang for reviewing a previous edition of this specification.

--- back

# Test Vectors

## Seeded PRNG

For interoperability, the random number generator used for test vectors
is implemented using the SHAKE128 duplex sponge of {{fiat-shamir}},
absorbing a seed of 32 bytes.
The Seeded PRNG is for reproducible test vectors; production implementations MUST use a CSPRNG.

Random scalars are generated squeezing `Ns + 32` bytes, seen as a big-endian positive integer and reduced modulo `p`, as in the unsigned-integer decoding of {{fiat-shamir}}.

~~~
class SeededPRNG:
    def __init__(self, seed: bytes, order: int):
        assert(len(seed) == 32)
        self.order = order
        self.hash_state = SHAKE128(b"sigma-proofs/TestDRNG/SHAKE128".ljust(64, b"\x00"))
        self.hash_state.absorb(seed)

    def random_scalar(self) -> Scalar:
        Ns = (self.order.bit_length() + 7) // 8
        random_integer  = OS2IP(self.hash_state.squeeze(Ns + 32))
        return Scalar(random_integer % self.order)
~~~

The following sections contain test vectors for the Sigma Protocols specified in this document.

The test vectors are grouped by ciphersuite. Each vector includes a `Relation`
field naming the relation being proved and a `Ciphersuite` field identifying
the non-interactive instantiation used to generate the proof bytes.

## sigma-proofs(P-256, SHAKE128)

This section contains vectors for the ciphersuite identified as
`sigma-proofs_Shake128_P256`.

{::include ./poc/vectors/sigma-proofs_Shake128_P256.txt}

## sigma-proofs(BLS12-381, SHAKE128)

This section contains vectors for the ciphersuite identified as
`sigma-proofs_Shake128_BLS12381`.

{::include ./poc/vectors/sigma-proofs_Shake128_BLS12381.txt}
