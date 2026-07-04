---
title: "Sigma Proofs for Linear Relations"
category: info

docname: draft-irtf-cfrg-sigma-protocols-latest
submissiontype: IRTF
number:
date:
consensus: true
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
  NIST-SP-800-186:
    title: "Recommendations for Discrete Logarithm-based Cryptography"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)

informative:
  FIPS186-5:
    title: "Digital Signature Standard (DSS)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
    date: 2023
    seriesinfo:
      "FIPS": "186-5"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
  BDFLSZ11:
    title: "Random Oracles in a Quantum World"
    target: https://eprint.iacr.org/2010/428.pdf
    date: false
    author:
    -
      fullname: "Dan Boneh"
    -
      fullname: "Özgür Dagdelen"
    -
      fullname: "Marc Fischlin"
    -
      fullname: "Anja Lehmann"
    -
      fullname: "Christian Schaffner"
    -
      fullname: "Mark Zhandry"
  DFMS19:
    title: "Security of the Fiat-Shamir Transformation in the Quantum Random-Oracle Model"
    target: https://eprint.iacr.org/2019/190.pdf
    date: false
    author:
    -
      fullname: "Jelle Don"
    -
      fullname: "Serge Fehr"
    -
      fullname: "Christian Majenz"
    -
      fullname: "Christian Schaffner"
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
  BellareGR98:
    title: "Fast Batch Verification for Modular Exponentiation and Digital Signatures"
    target: https://doi.org/10.1007/BFb0054130
    date: 1998
    author:
      - fullname: "Mihir Bellare"
      - fullname: "Juan A. Garay"
      - fullname: "Tal Rabin"
  BDLSY11:
    title: "High-speed high-security signatures"
    target: https://doi.org/10.1007/978-3-642-23951-9_9
    date: 2011
    author:
      - fullname: "Daniel J. Bernstein"
      - fullname: "Niels Duif"
      - fullname: "Tanja Lange"
      - fullname: "Peter Schwabe"
      - fullname: "Bo-Yin Yang"
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
      - fullname: "Ivan Damgård"
      - fullname: "Berry Schoenmakers"
  Cramer97:
    title: "Modular Design of Secure yet Practical Cryptographic Protocols"
    target: https://ir.cwi.nl/pub/21438
    date: 1997
    author:
      - fullname: "Ronald Cramer"
  Maurer09:
    title: "Unifying Zero-Knowledge Proofs of Knowledge"
    target: https://doi.org/10.1007/978-3-642-02384-2_17
    date: 2009
    author:
      - fullname: "Ueli M. Maurer"
  Pedersen91:
    title: "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"
    target: https://doi.org/10.1007/3-540-46766-1_9
    date: 1991
    author:
      - fullname: "Torben Pryds Pedersen"
  ChaumP92:
    title: "Wallet Databases with Observers"
    target: https://doi.org/10.1007/3-540-48071-4_7
    date: 1992
    author:
      - fullname: "David Chaum"
      - fullname: "Torben Pryds Pedersen"
  Okamoto92:
    title: "Provably Secure and Practical Identification Schemes and Corresponding Signature Schemes"
    target: https://doi.org/10.1007/3-540-48071-4_3
    date: 1992
    author:
      - fullname: "Tatsuaki Okamoto"
  CamenischS97:
    title: "Efficient Group Signature Schemes for Large Groups"
    target: https://doi.org/10.1007/BFb0052252
    date: 1997
    author:
      - fullname: "Jan Camenisch"
      - fullname: "Markus Stadler"
  JakobssonSI96:
    title: "Designated Verifier Proofs and Their Applications"
    target: https://doi.org/10.1007/3-540-68339-9_13
    date: 1996
    author:
      - fullname: "Markus Jakobsson"
      - fullname: "Kazue Sako"
      - fullname: "Russell Impagliazzo"
  Pass03:
    title: "On Deniability in the Common Reference String and Random Oracle Model"
    target: https://doi.org/10.1007/978-3-540-45146-4_19
    date: 2003
    author:
      - fullname: "Rafael Pass"
  ARC: I-D.yun-privacypass-crypto-arc
  BBS: I-D.irtf-cfrg-bbs-signatures
  BBSBlind: I-D.irtf-cfrg-bbs-blind-signatures
  CVE-2022-21449:
    title: "CVE-2022-21449: Improper ECDSA signature verification in Java SE / GraalVM (Psychic Signatures)"
    target: https://nvd.nist.gov/vuln/detail/CVE-2022-21449
    date: 2022
  CVE-2022-23806:
    title: "CVE-2022-23806: crypto/elliptic Curve.IsOnCurve returns true for non-canonical field elements in Go"
    target: https://nvd.nist.gov/vuln/detail/CVE-2022-23806
    date: 2022
  CVE-2022-29566:
    title: "CVE-2022-29566: Fiat-Shamir hashing omits public values from the statement and the proof in Bulletproofs (Frozen Heart)"
    target: https://nvd.nist.gov/vuln/detail/CVE-2022-29566
    date: 2022
  CVE-2023-33252:
    title: "CVE-2023-33252: snarkjs accepts public signals not reduced modulo the field order"
    target: https://nvd.nist.gov/vuln/detail/CVE-2023-33252
    date: 2023
  CVE-2024-42461:
    title: "CVE-2024-42461: ECDSA signature malleability from BER-encoded signatures in the elliptic package"
    target: https://nvd.nist.gov/vuln/detail/CVE-2024-42461
    date: 2024
  CVE-2025-57801:
    title: "CVE-2025-57801: gnark in-circuit ECDSA/EdDSA verification accepts out-of-range S (signature malleability)"
    target: https://nvd.nist.gov/vuln/detail/CVE-2025-57801
    date: 2025
  SOLANA-ZK:
    title: "Post Mortem: ZK ElGamal Proof Program Bug"
    target: https://solana.com/news/post-mortem-may-2-2025
    date: 2025
    author:
      - org: "Solana Foundation"
  SOLANA-PHANTOM:
    title: "Uncovering the Phantom Challenge Soundness Bug in Solana's ZK ElGamal Proof Program"
    target: https://blog.zksecurity.xyz/posts/solana-phantom-challenge-bug/
    date: 2025
    author:
      - fullname: "Suneal Gong"
  JagerSS15:
    title: "Practical Invalid Curve Attacks on TLS-ECDH"
    target: https://doi.org/10.1007/978-3-319-24174-6_21
    date: 2015
    author:
      - fullname: "Tibor Jager"
      - fullname: "Jörg Schwenk"
      - fullname: "Juraj Somorovsky"
  PS3:
    title: "Console Hacking 2010: PS3 Epic Fail"
    target: https://fahrplan.events.ccc.de/congress/2010/Fahrplan/attachments/1780_27c3_console_hacking_2010.pdf
    date: 2010
    seriesinfo:
      "In": "27th Chaos Communication Congress (27C3)"
    author:
      - fullname: "fail0verflow"

--- abstract

This document describes Sigma Protocols for proving knowledge of preimages of linear maps in prime-order elliptic curve groups. These are sometimes also called "Maurer Proofs", for the preimage of a group homomorphism.

Examples include zero-knowledge proofs for discrete logarithm relations, ElGamal encryptions, Pedersen commitments, and range proofs.

--- middle

# Introduction

Zero-knowledge proofs of knowledge allow a prover to convince a verifier that a statement is true, without revealing anything else than what is already revealed by the statement itself. Many practically-relevant statements about discrete logarithm relations can be realized using Sigma Protocols. Introduced by Schnorr {{!RFC8235}}, they are now widely used in practice because of their simplicity, maturity, and versatility.

Sigma Protocols are an essential component of a number of cryptographic constructions, such as anonymous credentials {{ARC}} {{BBS}}, verifiable random functions {{?RFC9381}}, anonymous tokens {{?RFC9497}}, ring and blind signatures {{BBSBlind}}, and proofs of knowledge of the opening of a Pedersen commitment {{Pedersen91}}. This document specifies a single Sigma Protocol for proving knowledge of a preimage of a linear map over a prime-order group {{Cramer97}} {{Maurer09}}. A *linear relation* is a system of equations among group elements that is linear in the secret scalars.

A Sigma Protocol is an interactive proof with the following three-message flow:

~~~ aasvg
+----------------------+                  +----------------------+
|        Prover        |                  |       Verifier       |
|  witness, instance   |                  |       instance       |
+----------------------+                  +----------------------+
          |                                           |
          | ProverCommitment(witness, rng)            |
          | commitment                                |
          |------------------------------------------>|
          |                                           |
          |                                 challenge |
          |<------------------------------------------|
          |                                           |
          | ProverResponse(prover_state, challenge)   |
          | response                                  |
          |------------------------------------------>|
          |                                           |
          | Verifier(commitment, challenge, response) |
          |                    accept or reject       |
~~~
{: #fig-sigma-proofs title="Flow of an interactive sigma protocol."}

The messages are respectively called **commitment** (computed by the prover), **challenge** (randomly sampled by the verifier), and **response** (computed by the prover). The prover is stateful and maintains a single-use private state between the first and third messages. The **transcript** `(commitment, challenge, response)` is checked by the verifier.

Sigma Protocols can compose: several statements can be proven simultaneously (AND composition), disjunctively (OR composition {{CramerDS94}}), or thresholded. AND composition of linear relations is immediate in this document ({{relation-notation}}); OR and threshold composition, and composition across heterogeneous proof systems, are not part of this document, but possible via the interactive protocol interface. Composition carries soundness and zero-knowledge caveats; see {{security-considerations}} and {{privacy-considerations}}.

This document specifies proofs for discrete-logarithm relations that can be expressed as the preimage of a linear map. Affine relations with constant terms (e.g. verifiable encryption) are expressed directly, via multi-term images ({{representation}}); quadratic equations (e.g. range proofs) can still be reduced to this form.

# Terminology and conventions in this document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

The following notation is used throughout this document.

## Bytes and integers {#bytes-and-integers}

A byte is an 8-bit unsigned integer (an octet), and a *byte string* is a finite sequence of bytes. The empty byte string is written `""`, and `x || y` is the concatenation of the byte strings `x` and `y`. For any finite sequence `x`, `len(x)` is the number of elements in `x`; for a byte string, this is its length in bytes. Byte strings are indexed from zero: for integers `0 <= i <= j <= len(x)`, `x[i : j]` denotes the `(j - i)`-byte substring of `x` at positions `i, i+1, ..., j-1`, so that `x[0 : N]` is the first `N` bytes of `x` and `x[i : i]` is `""`.

`I2OSP(n, w)` and `OS2IP(x)` are the integer/byte-string conversion primitives used throughout this document, in big-endian byte order, as defined in {{Section 4 of !RFC8017}}. `I2OSP(n, w)` converts a non-negative integer `n` with `0 <= n < 256^w` into a `w`-byte, big-endian byte string, and fails if `n >= 256^w`; `OS2IP(x)` is its inverse, mapping a `w`-byte string to the integer in `[0, 256^w)` that it represents. `LE(n, w)` is the little-endian counterpart defined in {{fiat-shamir}}, converting `n` into a `w`-byte, little-endian byte string; it is used for the indices and counts of the instance encoding ({{serialize-linear-relations}}). Byte order and length of the scalar and group-element encodings are fixed by each ciphersuite ({{ciphersuites}}).

## Randomized algorithms {#rng-definition}

The prover commitment algorithm requires fresh, single-use randomness. This document denotes with `rng` a cryptographically secure random number generator (CSPRNG), and uses `rng.random_scalar()` to denote sampling a uniformly random element of the scalar field.

Sampling a random scalar takes two steps: obtaining high-quality entropy from the operating system's CSPRNG (e.g., `getrandom()` {{!RFC4086}}), and reducing the resulting bytes to a scalar. It is **RECOMMENDED** that the latter is done via `DecodeField` as in {{fiat-shamir}}, which is equivalent to wide reduction as in `hash_to_field` ({{Section 5.2 of ?RFC9380}}), and the integer conversion of Appendix A.4.1 of {{FIPS186-5}}. The "discard method" of Appendix A.4.2 of {{FIPS186-5}} **SHOULD NOT** be used {{constant-time}}. Different sampling mechanisms do not affect interoperability of proofs: correct proofs will verify identically.

## Group abstraction {#group-abstraction}

Elliptic curves are presented using additive notation.

In symbolic notation, group elements are written upper-case (`G`, `X`, `M`) and scalars lower-case (`x`, `s`). Pseudocode and interface names are descriptive (e.g. `commitment`, `image`, `witness`) and do not follow this rule.

### Group {#group}

`identity()` is the neutral element, `generator()` fixes the generator of the prime-order subgroup, and `order()` returns its order `p`. Addition, negation, equality, and scalar multiplication by a `Scalar` are written `+`, `-`, `==`, and `*`.

`serialize(elements: [Group; N])` and `deserialize(buffer)` convert `N` non-neutral group elements into fixed-length `Ne * N`-byte encoding, where `Ne` is fixed per ciphersuite ({{ciphersuites}}). Deserialization **MUST** raise an error in case of failure.

### Scalar {#scalar}

A `Scalar` is an element of the group's *scalar field*, the prime field of integers modulo the group order `p` ({{group}}).

`identity()` is the additive identity of the scalar field. Addition and multiplication are written `+` and `*` (via operator overloading, in place of `add`, `mul`).

`serialize(scalars: list[Scalar; N])` and `deserialize(buffer)` batch convert between `[Scalar; N]` and its canonical, fixed-length `Ns * N`-byte encoding.

A uniformly random scalar is sampled with `rng.random_scalar()` ({{rng-definition}}).

# Interface {#core-interface}

A Sigma Protocol provides the following interface:

- `ProverCommitment(instance, witness, rng)`: produces a pair `(commitment, prover_state)` consisting of the **commitment** comessage, and a private `prover_state`. The prover state **MUST** be used only once per proof. The random number generator `rng` is defined in {{rng-definition}}.
- `ProverResponse(prover_state, challenge)` produces the **response**.
- `Verifier(instance, commitment, challenge, response)`, the verification algorithm.

These are the *interactive* protocol's building blocks. Implementations **MAY** also provide the **zero-knowledge simulator**:

- `SimulateResponse(instance, rng)`, which returns a `simulated_response`, a vector of scalars distributed as an honest response would be.
- `SimulateCommitment(instance, response, challenge)`, which returns the `simulated_commitment` consistent with that `response` and `challenge`.

Both are specified concretely for the linear-map Sigma Protocol in {{simulator}}. The simulator is useful for proof composition (e.g. OR-composition {{CramerDS94}}) and for compact proof serialization {{narg-string-compact}}.

This interface allows for composition, and **SHOULD NOT** be exposed directly to consumers of the non-interactive argument. In particular, `ProverResponse` **MUST NOT** be invoked with a `challenge` that was not either sent by an honest interactive verifier or derived from the instance and commitment via the Fiat-Shamir transformation ({{non-interactive}}). Supplying an invalid challenge or an arbitrary prover state will compromise soundness and zero-knowledge.

# Proofs of preimage of a linear map {#sigma-protocol-group}

This section specifies proofs of knowledge for the preimage of a linear map over a group, also known as preimage of a linear homomorphism. These are sometimes also called _Maurer proofs_ {{Maurer09}} {{Cramer97}}.

## Linear map {#linear-map}

A linear map is a matrix-vector product `M * witness = image`, where `M` is a matrix of group elements and `witness` is a vector of scalars.

`M` and `image` together form the statement (the *instance*), while `witness` is the secret. The _relation_, i.e. the set of (statement, witness) pairs the prover demonstrates knowledge for, is:

~~~
R := { ((M, image), witness) : M * witness = image }
~~~

`image` is the result of the multi-scalar multiplication of each matrix row with the witness:

~~~
image[i] = sum(witness[j] * M[i][j]
               for j in 0, ..., num_scalars - 1)
           for i in 0, ..., num_equations - 1
~~~

`num_scalars` is the length of `witness` (the width of `M`), and `num_equations` is the number of group elements in `image` (the height of `M`).

As an example, Schnorr's identification protocol has `num_scalars = num_equations = 1` and `M = [G.generator()]`, proving knowledge of `x` such that `x * G.generator() = X` {{!RFC8235}}.

Another example is the Chaum-Pedersen relation {{ChaumP92}}: given group elements `G`, `H`, `X`, `Y`, the prover shows knowledge of a single scalar `x` such that `X = x * G` and `Y = x * H`. Here `num_scalars = 1`, `num_equations = 2`, and:

~~~
M = [[G],
     [H]]
~~~

Variants of the Chaum-Pedersen relation are widely used for VRFs {{?RFC9381}} and anonymous tokens {{?RFC9497}}. Proving knowledge of the opening `(m, r)` of a Pedersen commitment {{Pedersen91}} `C = m * G + r * H` are Okamoto-Schnorr proofs {{Okamoto92}}. Affine equations with constant terms can be expressed directly through multi-term images ({{representation}}); more elaborate relations (quadratic equations, arithmetic circuits, etc.) reduce to this same form.

The group elements and the shape of the matrix depend on the statement being proven, and constructing the wrong matrix will void the intended security guarantees. Each row of `M` (each equation) **MUST** have no known discrete-logarithm relation. Else, knowledge soundness pins down no specific scalars. For instance, the equation `x * G + y * 5G = X` collapses to `(x + 5y) * G = X`, and has `p` distinct witnesses `[x, y]`; from any one of them the rest are trivial to derive. Generating computationally-independent bases, sometimes also called _auxiliary generators_, or _nothing up my sleeve (NUMS) generators_, is the responsibility of the caller and requires care; one way is to hash to the curve ({{Section 3 of !RFC9380}}).

## Representation {#representation}

The discrete logarithm relations proven with Sigma Protocols are typically sparse. This document handles and serializes them in Yale/CSR sparse-matrix format, rather than as an array of group elements.

Each row of `M` is called an `Equation`, and consists of two term lists. The `image` terms (the left-hand side) are a non-empty list of element indices, whose sum is the output of the equation. The `terms` (the right-hand side) are a non-empty list of `(scalar_index, element_index)` pairs, each contributing `witness[scalar_index] * elements[element_index]`. A `LinearRelation` holds a set of group elements (each corresponding to an `element_index`) and a non-empty list of equations.

~~~
class Equation:
    image: list[int]
        # non-empty, element_index
    terms: list[(int, int)]
        # non-empty, (scalar_index, element_index)

class LinearRelation:
    Group: groups.Group
    elements: list[Group]        # non-empty
    equations: list[Equation]    # non-empty
~~~

There are no integer constants on either side of an equation: every term is a plain product of one witness scalar and one instance element, and every image is a plain sum of instance elements. A statement involving a constant multiple of an element (such as `3 * H`) registers the element `3 * H` itself as an instance element; {{relation-notation}} describes how such derived entries are constructed and why the encoding still binds the original element.

The image of each equation is kept as a list of terms, and **MUST NOT** be pre-computed into a single group element, so that the serialization of {{serialize-linear-relations}} binds every group element of the statement individually. For example, the verifiable-decryption statement `x * E0 = M + E1` has image terms `[M, E1]`; folding them into the single element `F = M + E1` would yield a proof that no longer binds the pair `(M, E1)`, and that verifies unchanged for any other pair `(M', E1')` with `M' + E1' = F` ({{sigma-ni-security}}).

A `LinearRelation` **MUST** have at least one equation, and every equation's `image` and `terms` **MUST** be non-empty. Every index **MUST** have an associated group element. Conversely, the elements list **MUST NOT** extend past the largest referenced index: `num_elements(instance)` **MUST** equal one plus the largest `element_index` appearing in the equations' terms or image terms, so that the number of group elements is determined by the equations alone. This requirement makes the serialization of {{serialize-linear-relations}} prefix-free. Scalar indices **MUST** be contiguous: every index in `[0, num_scalars(instance))` **MUST** appear in at least one term, so the corresponding response is checked by at least one equation.

The above structural requirements, together with those of {{relation-notation}}, are collected in `ValidateInstance` ({{instance-validation}}).

A `LinearRelation` is the instance for the Sigma Protocol. It fixes the linear map `M` and the image, that is, the statement `(M, image)` of the relation `R` ({{sigma-protocol-group}}), and not one of the `((M, image), witness)` pairs that make up `R`. The word *relation* is used here in the linear-algebra sense: a system of linear equations among group elements, while the witness is supplied separately to the prover ({{core-interface}}). The prover and the verifier each construct the same `LinearRelation`, and pass it to their respective algorithms. Disagreement on the instance are discussed in {{sigma-ni-security}}.

The following quantities are derived from a `LinearRelation`:

~~~
num_elements(instance)  = len(instance.elements)
num_equations(instance) = len(instance.equations)
num_scalars(instance)   = 1 + max(s for eq in instance.equations
                                    for (s, _) in eq.terms)
~~~

The size of the group-elements set `num_elements` is independent of `num_equations`. For instance, in Chaum-Pedersen, `num_elements = 4` (`G`, `H`, `X`, `Y`), while `num_equations = 2`.

This document writes `map(instance, scalars)` for the function that evaluates `M` at `scalars`:

~~~
map(instance, scalars) -> list[Group]

1. out = []
2. for equation in instance.equations:
3.     acc = instance.Group.identity()
4.     for (scalar_index, element_index) in equation.terms:
5.         acc = acc + scalars[scalar_index] \
                       * instance.elements[element_index]
6.     out.append(acc)
7. return out
~~~

and `image(instance)` for the evaluation of each equation's left-hand side: the list of `num_equations(instance)` group elements whose `i`-th entry is the sum of `instance.elements[element_index]` over the image entries of the `i`-th equation.

## Instance validation {#instance-validation}

For an instance to be valid, it **MUST** satisfy all of the conditions below:

1. The instance has at least one equation: `num_equations(instance) > 0`.
2. Every equation in `instance.equations` has a non-empty `terms` list and a non-empty `image` list.
3. Every `scalar_index`, every `element_index`, and every equation's term count is less than `2^32`.
4. Every `element_index` is less than `num_elements(instance)`.
5. `num_elements(instance)` is exactly one more than the largest element index appearing in the equations' terms or image entries.
6. No element of `instance.elements` is the identity element.
7. No element of `image(instance)` is the identity element.
8. Every scalar index in `[0, num_scalars(instance))` appears in the terms of at least one equation.

Checks 1-5 guarantee that every index dereferences to a group element, and that the serialization of {{serialize-linear-relations}} is prefix-free. Check 6 rejects the identity element wherever it appears ({{relation-notation}}). Check 7 rejects equations whose image evaluates to the identity: such an equation is satisfied by the all-zero witness, so a proof of it attests nothing. Check 8 is the scalar-contiguity rule of {{representation}}, and guarantees that every response scalar is constrained by at least one verification equation. The consequences of skipping checks 6-8 in the non-interactive setting are described in {{sigma-ni-security}}.

With `ValidateInstance(instance)` (in pseudocode) we denote the function returning `true` if all above predicates are met.

Validity is a property of the instance alone, not of any particular proof. The prover **SHOULD** reject an invalid instance, and **MAY** additionally check that `map(instance, witness) == image` before proving. The verifier **MUST** fail on an invalid instance ({{verifier}}, {{non-interactive}}), either at instance generation or during the actual verification.

## Specifying the instance {#relation-notation}

This section defines a symbolic notation in the spirit of {{CamenischS97}} for declaring scalars, elements, and equations.

A linear relation is declared as a named block:
{: #relations-in-other-specs}

~~~
Relation NAME(params...):
    Scalars: s[0], ..., s[k-1]
    Elements: E[0], ..., E[n-1]
    Equations:
        E[i] = <linear combination of scalars and elements>
        ...
~~~

`Scalars:` and `Elements:` each list names in the order the compiled `LinearRelation` assigns them indices: the `j`-th name under `Scalars:` becomes scalar index `j`, and the `j`-th name under `Elements:` becomes `instance.elements[j]` ({{representation}}). Vectors of indices (for example, declaring `D_0, ..., D_{n-1}`) unroll in order. Each equation has the form `image = term + term + ...` ({{representation}}), where `image` is a sum of element names and each `term` is a `scalar_name * element_name` product. Each `term` compiles to a `(scalar_index, element_index)` pair, in the order written, and each image entry to an element index of the compiled equation.

In pseudocode, `NAME(...)` indicates the compiled `LinearRelation` with the named parameters substituted on the matching `Elements:` entries. The prover and the verifier can use it as input to the prover or verifier algorithm.

For example, the Chaum-Pedersen relation of {{sigma-protocol-group}} is declared as:

~~~
Relation ChaumPedersen(G, H, X, Y):
    Scalars: x
    Elements: G, H, X, Y
    Equations:
        X = x * G
        Y = x * H
~~~

which compiles to the `LinearRelation` with `elements = [G, H, X, Y]` and `equations = [Equation(image=[2], terms=[(0, 0)]), Equation(image=[3], terms=[(0, 1)])]`.

As an example with a multi-term image, the following declares a proof of correct ElGamal decryption: the ciphertext `(E0, E1)`, with `E1 = r * X - M`, decrypts to `M` under the decryption key `x` of `X`:

~~~
Relation ElGamalDecryption(G, X, E0, E1, M):
    Scalars: x
    Elements: G, X, E0, E1, M
    Equations:
        X = x * G
        M + E1 = x * E0
~~~

The second equation compiles to `Equation(image=[4, 3], terms=[(0, 2)])`: both `M` and `E1` are instance elements, individually bound by the serialization of {{serialize-linear-relations}}.

Both lists **MUST** enumerate every name used in `Equations:`, and **MUST NOT** repeat a name. Conversely, every listed name **MUST** appear in `Equations:`: a declared scalar or element that is never used compiles to a `LinearRelation` violating the index requirements of {{representation}}. Indices and term counts **MUST** be less than `2^32`. Every term **MUST** be a single `scalar_name * element_name` product: the notation has no integer constants, and no scalar-scalar or element-element products. Element-only entries (no scalar) appear only on the image side of an equation. There is no negation and there are no constant multiples: a subtracted element is expressed by supplying its negated value as an `Elements:` entry, and a constant multiple such as `3 * H` by supplying the element `3 * H` itself. Both derivations are injective -- multiplication by any fixed nonzero scalar is, since the group has prime order -- so the encoding still binds the original element. A derived entry is part of constructing the statement: each party **MUST** compute it locally from the original element, and **MUST NOT** accept it as a separate input, since no algebraic relation between instance elements is checked by `ValidateInstance` ({{instance-validation}}) or by the verifier ({{instance-agreement}}). An element and an entry derived from it used as bases of the same equation form a known discrete-logarithm relation, forbidden by {{linear-map}}. Each element **MUST NOT** be the identity element. A constant base is expressed as an `Elements:` entry multiplied by a scalar fixed to `1`; quadratic statements reduce to this product form as described in {{sigma-protocol-group}}.

Because a `LinearRelation` may hold any number of equations over shared or disjoint variables, AND composition comes for free, by concatenating the `Scalars:`, `Elements:`, and `Equations:` of each sub-relation.

In a real protocol, some elements of the instance might be attacker-controlled. Each element supplied from untrusted parties **MUST** pass the same deserialization validation as any untrusted group element ({{group-abstraction}}, {{sigma-ni-security}}) before it is used.

## Serialization {#serialize-linear-relations}

A `LinearRelation` is serialized as a sparse matrix in row-major order, followed by the group elements set. Each row is serialized encoding its image terms (their count, followed by the element index of each term), and then its right-hand side terms (their count, followed by the `(scalar index, element index)` pair of each term) ({{representation}}). Counts and indices are encoded in 4 bytes, via `LE` ({{bytes-and-integers}}). Then, the group elements are serialized using the group serialization function.

~~~
SerializeLinearRelation(instance)

Input:

- instance, a LinearRelation.

Output:

- a byte string

Procedure:

 1. out = ""
 2. out = out || LE(num_equations(instance), 4)
 3. for i in 0, ..., num_equations(instance) - 1:
 4.     image_terms = instance.equations[i].image
 5.     out = out || LE(len(image_terms), 4)
 6.     for element_index in image_terms:
 7.         out = out || LE(element_index, 4)
 8.     terms = instance.equations[i].terms
 9.     out = out || LE(len(terms), 4)
10.     for (scalar_index, element_index) in terms:
11.         out = out || LE(scalar_index, 4)
12.         out = out || LE(element_index, 4)
13. return out || Group.serialize(instance.elements)
~~~

Here each image term is the index of a group element summed on the left-hand side of the `i`-th equation ({{representation}}), and each right-hand side term `(scalar_index, element_index)` associates a scalar (witness) index with a group-element index. The image is encoded through its terms, never as a pre-computed sum, so that every statement element is bound individually ({{representation}}, {{sigma-ni-security}}).

`SerializeLinearRelation` operates on a `LinearRelation` as compiled from its declaration ({{relation-notation}}). Implementations **MUST** preserve ordering during serialization. The same relation expressed in two different ways (for example, swapping two rows of `M`) will yield different serializations.

The encoding binds the entire statement: the shape of the linear map (the number of equations, and the indices wired into each one) together with every group element of the instance. Because `num_equations(instance) >= 1` and every equation has at least one image term and one right-hand side term ({{representation}}), the output is always non-empty.

The encoding is prefix-free over well-formed instances, as required of the instance encoding by {{fiat-shamir}}. The sparse-matrix header is self-delimiting: `num_equations` is read first, and each row carries its own image-term and term counts. Because `num_elements(instance)` equals one plus the largest element index referenced in the header ({{representation}}), the number of trailing group elements -- and therefore the total encoding length -- is a function of the header alone. If the encoding of one instance were a prefix of another's, the two headers would coincide byte for byte, forcing the same element count, the same total length, and hence the same encoding.

## Prover

The prover of a Sigma Protocol is stateful and will send two messages, described below.

### Prover commitment

~~~
ProverCommitment(instance, witness, rng)

Inputs:

- instance, the LinearRelation being proven
- witness, an array of scalars satisfying the linear relation
- rng, a cryptographically secure random number generator

Outputs:

- A (private) prover state
- A commitment message (a vector of group elements)

Procedure:

1. fail if len(witness) != num_scalars(instance)
2. nonces = [rng.random_scalar()
             for j in 0, ..., num_scalars(instance) - 1]
3. commitment = map(instance, nonces)
4. return (prover_state := (witness, nonces), commitment)
~~~

The prover **MUST** fail if the witness length does not match `num_scalars(instance)`: a mismatch cannot yield a valid proof and, depending on the implementation language, may otherwise read out of bounds in `ProverResponse`. The prover **MAY** fail if the witness is not valid for the instance provided.

### Response

~~~
ProverResponse(prover_state, challenge)

Inputs:

    - prover_state, the current state of the prover
    - challenge, the verifier challenge scalar

Output: The response message, an array of scalars

Procedure:

1. witness, nonces = prover_state
2. return [nonces[i] + witness[i] * challenge
           for i in 0, ..., len(nonces) - 1]
~~~

## Verifier {#verifier}

The **challenge** is a scalar drawn uniformly at random from the scalar field of order `p`; in the interactive protocol the verifier samples it directly ({{rng-definition}}), while non-interactive deployments derive it deterministically from the transcript via the Fiat-Shamir transformation ({{non-interactive}}), and its serialization is the canonical fixed-length scalar encoding of {{scalar}}. The verification equation is as follows:

~~~
Verifier(instance, commitment, challenge, response)

Inputs:

- instance, the LinearRelation being verified
- commitment, the commitment generated by the prover
- challenge, the challenge generated by the verifier
- response, the response generated by the prover

Output: a boolean indicating whether the verification succeeded

Procedure:

1. fail if ValidateInstance(instance) fails
2. fail if len(commitment) != num_equations(instance) or \
           len(response) != num_scalars(instance)
3. expected = map(instance, response)
5. got = [commitment[i] + image(instance)[i] * challenge
          for i in 0, ..., num_equations(instance) - 1]
6. return got == expected
~~~

Step 1 enforces instance validity ({{instance-validation}}); as discussed there, implementations that guarantee validity when the instance is constructed **MAY** omit it here. Step 2 checks the shape of the transcript against the instance; the remaining steps check the verification equation itself.

## Simulator {#simulator}

Implementations that expose the zero-knowledge simulator ({{core-interface}}) provide the two algorithms below; they are also what the compact verifier ({{non-interactive}}) relies on to recover the prover's commitment from `(challenge, response)`.

~~~
SimulateResponse(instance, rng)

Inputs:

- instance, the LinearRelation
- rng, a cryptographically secure random number generator

Output: a vector of num_scalars(instance) scalars

Procedure:

1. return [rng.random_scalar()
           for j in 0, ..., num_scalars(instance) - 1]
~~~

~~~
SimulateCommitment(instance, response, challenge)

Inputs:

- instance, the LinearRelation
- response, a vector of num_scalars(instance) scalars
- challenge, a challenge scalar

Output: a vector of num_equations(instance) group elements

Procedure:

1. expected = map(instance, response)
2. img = image(instance)
3. return simulated_commitment := [
       expected[i] - challenge * img[i]
       for i in 0, ..., num_equations(instance) - 1]
~~~

Drawing `response` uniformly at random with `SimulateResponse` and then computing `commitment` with `SimulateCommitment` yields a transcript `(commitment, challenge, response)` with the same distribution as an honest one. This is the honest-verifier zero-knowledge property ({{security-considerations}}).

# Non-interactive Sigma Protocols {#non-interactive}

The Fiat-Shamir transformation applied to Sigma Protocols yields a non-interactive zero-knowledge argument of knowledge.

{{fiat-shamir}} describes how to instantiate the transformation, for the group and field codecs given. The security requirements of the session identifier `session_id` are discussed in {{sigma-proofs-tag}}. The actual choices of `DecodeField` are discussed in {{ciphersuites}}. Two serializations (two NARG string formats) are possible.

## Non-interactive argument string serialization {#sigma-narg}

Two serialization flavors are possible:

- A **batchable** NARG string serializes the prover messages `(commitment, response)`, as in {{fiat-shamir}}, and it permits amortized verification costs.
- A **compact** NARG string serializes `(challenge, response)`. It is preferable in the common case, whenever the commitment (`num_equations` group elements) is larger than a single challenge scalar.

A batchable NARG string is a `(Ne * num_equations + Ns * num_scalars)`-byte string, while a compact NARG string is a `(Ns * (num_scalars + 1))`-byte string.

## Batchable

A **batchable** NARG string is the NARG string of {{fiat-shamir}}, consisting of the concatenation of the serialized prover messages using their respective serialization functions:

~~~
Group.serialize(commitment) || Scalar.serialize(response)
~~~

`ProveBatchable` and `VerifyBatchable` are the NARG prover and verifier of {{fiat-shamir}} instantiated with the Sigma Protocol of {{sigma-protocol-group}}.

- `ProveBatchable(tag, instance, witness, rng)` computes the commitment message with `ProverCommitment`, derives the challenge via `DecodeField` from a duplex sponge initialized with `DeriveSessionID(tag)` that absorbs `SerializeLinearRelation(instance)` followed by `Group.serialize(commitment)`, computes the response with `ProverResponse(prover_state, challenge)`. Finally, it outputs the NARG string above.
- `VerifyBatchable(tag, instance, proof)` fails unless `ValidateInstance(instance)` succeeds and `len(proof)` is exactly `Ne * num_equations(instance) + Ns * num_scalars(instance)`; it deserializes `commitment` and `response` with `Group.deserialize` and `Scalar.deserialize`, recomputes the challenge from the instance and the commitment bytes exactly as the prover does, and returns `Verifier(instance, commitment, challenge, response)`.

Verification of multiple batchable NARG strings **MAY** be done more efficiently than verifying each proof on its own.

Batch verification is done by re-computing the verifier challenge of each proof individually, and then checking a single random linear combination of the verification equations of the whole batch. See {{Section 8.2 of ?RFC8032}} for additional concerns, in the literature {{BDLSY11}} {{BellareGR98}}. It is a local verifier-side optimization: it changes neither the prover nor the NARG string.

For `Nt` transcripts `(commitment, challenge, response)`, the `i`-th one is valid if, for every equation index `j`:

~~~
commitment[i][j] + challenge[i] * image(instances[i])[j]
                 == map(instances[i], response[i])[j]
~~~

The batch verifier may instead sample uniformly random coefficients `batching_randomness[i][j]` (for `i = 0, ..., Nt - 1` and `j = 0, ..., num_equations(instances[i]) - 1`) and check the single equation:

~~~
sum(
  batching_randomness[i][j] * commitment[i][j]
  + batching_randomness[i][j] * challenge[i] * image(instances[i])[j]
  - batching_randomness[i][j] * map(instances[i], response[i])[j]
  for i in 0, ..., Nt - 1
  for j in 0, ..., num_equations(instances[i]) - 1
) == Group.identity()
~~~

Similarly to batch verification of Ed25519 signatures {{BDLSY11}}, a false proof will be accepted with probability at most 2^-128, which is neglible. In general, for `batching_randomness` elements drawn uniformly from a set of `2^t` scalars, a false proof will be accepted with probability at most `2^-t`.

The independent coefficients **MAY** be replaced by the successive powers `1, mu, mu^2, ...` of a single uniformly random scalar `mu`, assigned in a fixed order to the pairs `(i, j)`. In this case, an invalid batch is accepted with probability at most `(Nt - 1)/p` rather than `1/p`, where `Nt` is the number of transcripts in the batch.

It is **RECOMMENDED** the batch randomness be generated deterministically, with the duplex sponge of {{fiat-shamir}} as follows:

~~~
1. batching_sid = DeriveSessionID(
       "irtf-cfrg-sigma-protocols/batch-verify")
2. state = DS.Init(batching_sid)
3. for i in 0, ..., Nt - 1:
4.     state.Absorb(session_ids[i])
5.     state.Absorb(SerializeLinearRelation(instances[i]))
6.     state.Absorb(narg_strings[i])
7. state.Squeeze(128 * sum(num_equations(instances[i])
                           for i in 0, ..., Nt - 1))
~~~

The verifier **MUST** perform instance validation for each instance, and **MUST** compute each of the verifier challenges as in {{fiat-shamir}}.

The verifier **MUST NOT** use the duplex sponge of a NARG verifier {{SOLANA-ZK}}: the batching randomness is not a verifier message of the proof system. If even one NARG string or instance is not absorbed, an attacker can choose the omitted value afterwards so that the combined check passes on otherwise-invalid proofs. As an example, in OR composition {{CramerDS94}} the response message contains the prover-chosen challenge share `c_2`, with `c_1 = challenge - c_2`; if it is not absorbed, soundness is lost {{SOLANA-PHANTOM}}.

When it fails, batch verification does not identify the offending proof; an application may fall back to verifying the proofs individually. Empty batches are accepted as valid; the batch size **MUST** be less than `2^32`.

## Compact {#narg-string-compact}

A **compact** proof serializes `serialize(challenge) || serialize(response)`. The Sigma Protocol transcript is recovered by invoking the simulator.

~~~
ProveCompact(tag, instance, witness, rng)

Inputs:

- tag, a byte string uniquely identifying the session
- instance, the LinearRelation to be proven
- witness, the prover's secret witness
- rng, a cryptographically secure random number generator

Output: the compact proof, a byte string

Procedure:

1. (commitment, prover_state) =
       ProverCommitment(instance, witness, rng)
2. commitment_bytes = Group.serialize(commitment)
3. session_id = DeriveSessionID(tag)
4. duplex_sponge = DS.Init(session_id)
5. duplex_sponge.Absorb(SerializeLinearRelation(instance))
6. duplex_sponge.Absorb(commitment_bytes)
7. challenge = DecodeField(duplex_sponge.Squeeze(Ns + 16), p, 1)
8. response = ProverResponse(prover_state, challenge)
9. return Scalar.serialize([challenge]) || Scalar.serialize(response)
~~~

Here `commitment_bytes` is serialized only to derive the challenge; unlike in the batchable proof, the commitment is not part of the compact NARG string, which carries `(challenge, response)`. The compact commitment is therefore a hash-only value: it is absorbed but never appears on the wire.

The verifier recomputes the commitment from the challenge and response via `SimulateCommitment` ({{simulator}}), then recomputes the challenge from that commitment and accepts only if it matches the one in the proof.

~~~
VerifyCompact(tag, instance, proof)

Inputs:

- tag, a byte string uniquely identifying the session
- instance, the LinearRelation to be proven
- proof, the compact proof byte string

Output: a boolean indicating whether the proof is valid

Procedure:

 1. fail if ValidateInstance(instance) fails
 2. Nr = num_scalars(instance) * Ns
 3. fail if len(proof) != Ns + Nr
 4. challenge = Scalar.deserialize(proof[0 : Ns])[0]
 5. response = Scalar.deserialize(proof[Ns : Ns + Nr])
 6. commitment = SimulateCommitment(instance, response, challenge)
 7. fail if any element of commitment is the identity element
 8. session_id = DeriveSessionID(tag)
 9. duplex_sponge = DS.Init(session_id)
10. duplex_sponge.Absorb(SerializeLinearRelation(instance))
11. duplex_sponge.Absorb(Group.serialize(commitment))
12. expected_challenge = DecodeField(
        duplex_sponge.Squeeze(Ns + 16), p, 1)
13. return challenge == expected_challenge
~~~

Note that since the simulator always outputs accepting transcripts, there is no need to run `Verifier` in this case.

Step 7 is needed because the simulated commitment, unlike a deserialized one, never passes through `Group.deserialize`: it is recomputed from attacker-controlled scalars and can be forced to the identity element, for which `Group.serialize` is not defined ({{group}}). For example, the all-zero proof -- `challenge = 0` and an all-zero `response`, both canonical scalar encodings -- simulates to an all-identity commitment. An honest prover produces an identity commitment element only with negligible probability, so completeness is unaffected.

## Tag and session identifier {#sigma-proofs-tag}

The session identifier `session_id` is a 32-byte string. It **SHOULD** be derived from a string `tag` using `DeriveSessionID` of {{fiat-shamir}}. The prover and verifier initialize their duplex sponge state from it ({{non-interactive}}).

The `tag` is a byte string following the security requirements on the session identifier in {{fiat-shamir}}.

As an example, consider a fictional application named Foo. A reasonable choice of `tag` is:

~~~
FOO-{xx}-{tttt}-{flavor}-{hashID}-SIGMA-PROOFS-{yy}
~~~

where `xx` is the two-digit number indicating the version, `tttt` is a 32-bit integer identifying the epoch, `flavor` is `DSFS` for a _batchable proof_ or `CMPT` for a _compact proof_ ({{sigma-narg}}), `hashID` is the hash identifier, and `yy` is the two-digit number indicating the elliptic-curve ciphersuite.

# Efficiency Considerations {#efficiency-considerations}

Implementations **SHOULD** evaluate `map(instance, scalars)` ({{representation}}) using a multi-scalar multiplication (MSM) algorithm for each equation, rather than computing and summing each term individually; this matters most for equations with many terms.

The verifier of {{verifier}} is specified as the equality `map(instance, response) == commitment + challenge * image(instance)`, evaluated as two separate vectors for clarity. Implementations **MAY** instead verify each equation `i` by checking that `commitment[i] + challenge * img[i] - sum(response[j] * M[i][j] for j in 0, ..., num_scalars(instance) - 1)` is `identity()`, accumulating all terms in a single MSM per equation. Each image term enters this MSM with coefficient `challenge`, so the summed image is never materialized as a separate point. This folds the image scalar multiplications into the same MSM as the row terms, sharing its point doublings, and negation is free on these curves; the arithmetic is otherwise identical to the equality above.

As observed in the efficiency considerations of {{fiat-shamir}}, `DS.Init(session_id)` followed by `Absorb(encode[0](instance))` depends only on the `tag` and `instance`, not on the witness or randomness of any particular proof. Implementations that produce or verify many proofs for the same instance can precompute and reuse the duplex sponge state resulting from these two steps of the challenge derivation ({{non-interactive}}) across proofs. `ValidateInstance` ({{instance-validation}}) likewise depends only on the instance, and can be checked once per instance rather than once per proof.

# Security Considerations {#security-considerations}

A Sigma Protocol run interactively provides the guarantees of {{interactive-security-properties}}. In practice, however, Sigma Protocols are almost always deployed non-interactively via the Fiat-Shamir transformation ({{non-interactive}}); {{sigma-ni-security}} describes how these guarantees carry over and what additional care the non-interactive setting requires.

## Instance agreement {#instance-agreement}

The prover and verifier construct the instance from values they independently hold and trust ({{relation-notation}}). Prover-supplied elements ({{relation-notation}}) are thus untrusted input and **MUST** pass the validation of {{group-abstraction}} before use. An instance where all group elements are adversarially-chosen holds no meaning. A proof certifies the statement only as the verifier constructed it.

Entries derived from other instance elements, such as the negated or constant-multiple entries of {{relation-notation}}, **MUST** be recomputed locally from the already-validated original, never received pre-computed: the verifier has no means to check that one entry is derived from another, and a proof over a mismatched pair soundly certifies a statement other than the intended one. The same caution applies within a single implementation: a sign error made consistently by prover and verifier still verifies, while proving a different statement; test vectors and cross-implementation checks are the effective defense.

## Prover randomness

Draw fresh nonces from `rng` for every proof. A nonce reused under two different challenges `c1`, `c2` reveals the witness as `(s1 - s2) / (c1 - c2)`, where `s1`, `s2` are the corresponding responses -- the failure behind well-known Schnorr and ECDSA key recoveries, such as the recovery of the PlayStation 3 code-signing key from ECDSA signatures produced with a static nonce {{PS3}}. Deterministic nonce derivation is a common choice in environments without a reliable local entropy source; it is safe only if every input affecting the challenge (`tag`, `instance`, `commitment`) is bound into the derivation ({{core-interface}}, {{fiat-shamir}}).

## Interactive security properties {#interactive-security-properties}

The interactive Sigma Protocol of {{sigma-protocol-group}} has special soundness {{Cramer97}} {{Maurer09}}: two accepting transcripts with the same commitment and distinct challenges yield a witness, so a prover that convinces the verifier must know a witness satisfying the proof statement. Knowledge of a witness is meaningful only when the relation is computationally hard: if witnesses are easy to find, the proof conveys nothing.

The interactive Sigma Protocol of {{sigma-protocol-group}} is honest-verifier zero knowledge: the prover messages do not reveal any information beyond what can be directly inferred from the statement itself, so an honest verifier gains no knowledge about the witness {{Cramer97}}.

Because interactive Sigma Protocols do not have transferable message authenticity, a third party (neither the prover nor the verifier) cannot be convinced that the prover made the proof. The interaction is thus not transferable as evidence to a third party {{JakobssonSI96}} {{Pass03}}.

## Fiat-Shamir transformation {#sigma-ni-security}

In practice, Sigma Protocols are almost always deployed non-interactively via the Fiat-Shamir transformation ({{non-interactive}}), so the security considerations of {{fiat-shamir}} apply here as well. The following points deserve particular attention.

Soundness holds only if the encoded instance binds the entire statement ({{serialize-linear-relations}}). Omitting any generator or image element will compromise knowledge soundness of the resulting non-interactive argument, the failure documented for the Bulletproofs proof system as {{CVE-2022-29566}}.

Pre-computing an equation's image also breaks this binding, even though no element is omitted outright. If the verifiable-decryption statement `x * E0 = M + E1` is encoded with the single folded image element `F = M + E1` instead of the two image terms `(1, M), (1, E1)` ({{representation}}), then `M` and `E1` never enter the transcript, and the resulting proof is malleable across statements: it verifies unchanged for every pair `(M', E1')` with `M' + E1' = F`. An attacker can thus present a proof generated for one plaintext-ciphertext pair as a proof for a different one. Image terms **MUST** therefore reference each statement element individually.

### Verifier input validation

The session identifier, the NARG string, and the instance are all untrusted input. Verifiers **MUST** check the proof length (no trailing bytes) and reject malformed encodings before performing any algebraic check.

For group elements, deserialization **MUST** verify that each point is canonically encoded, lies on the curve, and lies in the prime-order group; the last of these requires a subgroup-membership check when the group cofactor is greater than one ({{group-abstraction}}). Skipping the on-curve or subgroup check enables invalid-curve attacks {{JagerSS15}}, and accepting non-canonical field elements has caused real vulnerabilities {{CVE-2022-23806}}. The identity element **MUST** be rejected wherever it appears: in any deserialized prover message, and in any instance element, including elements the verifier derives from prover-supplied values ({{group-abstraction}}).

For scalars, deserialization **MUST** reject any value that is not the canonical representative in `[0, p)` {{CVE-2023-33252}}. Failing to check that signature or response components are in range and nonzero is the validation-skip class behind {{CVE-2022-21449}} {{CVE-2025-57801}}, and admitting non-canonical encodings of the same value yields proof malleability {{CVE-2024-42461}}.

Beyond these element-wise checks, the shape of the instance itself is validated by `ValidateInstance` ({{instance-validation}}). In the interactive protocol an instance failing it is merely degenerate; under Fiat-Shamir, two of its failure modes become attacks. An equation whose image evaluates to the identity element is trivially true -- the all-zero witness satisfies it -- so anyone can produce an accepting proof of it, the proof-system analogue of accepting the all-zero signature {{CVE-2022-21449}}. A scalar index appearing in no equation leaves the corresponding response scalar unconstrained by every verification equation; since the response is never absorbed when deriving the challenge, those bytes can be replaced by any canonical scalar without invalidating the proof, so every accepting NARG string for such an instance is malleable, in either serialization.

For compact proofs, the verifier **MUST** recompute the challenge and compare it before accepting.

### Post-quantum security considerations {#sigma-ni-post-quantum}

The discrete logarithm assumption underlying the proved relations does not hold against quantum adversaries; see {{post-quantum-security-considerations}}.

## Privacy Considerations {#privacy-considerations}

Interactive Sigma Protocols only guarantee zero-knowledge against honest verifiers ({{security-considerations}}); a malicious verifier may extract information from the interaction, so this interactive setting **SHOULD NOT** be used where verifiers cannot be trusted. The non-interactive Fiat-Shamir transformation removes this restriction, yielding publicly verifiable (transferable) proofs that are statistically zero-knowledge.

## Constant-Time Requirements {#constant-time}

The prover's control flow and memory access patterns are typically influenced by the witness. All group and field operations over private inputs -- scalar multiplication, modular reduction, random-value generation, and so on -- **MUST** be constant-time to avoid side-channel leakage of the witness; in applications such as keyed-verification credentials, the verifier's operations require the same treatment.

Implementations **MUST** securely delete prover state as soon as it is no longer needed, and **SHOULD** minimize the lifetime of sensitive material (witness and instance), explicitly zeroize temporary buffers after proof generation, and reduce exposure in crash dumps, swap/page files, and diagnostic logging.

## Post-Quantum Considerations {#post-quantum-security-considerations}

Sigma Protocols for linear relations provide statistical zero-knowledge, and the witness will be hidden even facing an adversary with unbounded computational power. Therefore, they are suitable for privacy properties such as post-quantum anonymity, unlinkability, blindness, and protection against "harvest now, decrypt later" attacks.

The special soundness of these Sigma Protocols holds unconditionally. Nonetheless, the relations themselves will rely on the hardness of the discrete logarithm assumption over the curves of {{ciphersuites}}. So, against a quantum adversary, a proof of knowledge for these relations no longer attests anything that the adversary could not compute on its own. Statements that are meaningful independently of the hardness of the relation (for example, discrete logarithm equality) retain their soundness guarantee even against quantum provers. For relations whose value rests on discrete logarithm hardness, other families of Sigma Protocols, e.g. MPC-in-the-Head {{GiacomelliMO16}}, lattice-based {{AttemaCK21}}, or code-based {{Stern93}} approaches can provide post-quantum guarantees, but are not specified in this document.

The quantum random-oracle model (QROM) {{BDFLSZ11}}, where the adversary may query the hash function in superposition, is not considered in this document. An analysis of the Fiat-Shamir transformation in the QROM can be found in {{DFMS19}}.

A generic AND composition of a classical-sound and a post-quantum-sound proof retains soundness if **both** underlying problems remain hard; unlike the free composition of linear relations described in {{relation-notation}}, such composition across heterogeneous proof systems is not addressed in this specification, but examples may be found in the proof-of-concept implementation and in {{BonehS23}}.

# Ciphersuites {#ciphersuites}

A ciphersuite for the non-interactive Sigma Protocol ({{non-interactive}}) is composed of the following parameters:

- an elliptic curve group, over which the Sigma Protocol of {{sigma-protocol-group}} is run,
- a duplex sponge {{fiat-shamir}}.

The ciphersuites defined by this document, and the identifiers used by the test vectors, are:

| Identifier | Group | Ne | Ns | Duplex Sponge | Security |
|---|---|---|---|---|---|
| `sigma-proofs_Shake128_P256` | P-256 (secp256r1) | 33 | 32 | SHAKE128 | 128-bit pre-quantum |
| `sigma-proofs_Shake128_BLS12381` | BLS12-381 (G1) | 48 | 32 | SHAKE128 | 128-bit pre-quantum |
{: #tab-ni-ciphersuites title="Non-interactive Sigma Protocol ciphersuites"}

Each row uses the Sigma Protocol of {{sigma-protocol-group}} over the named group. `Ne` and `Ns` are the element and scalar byte lengths of that group. The ciphersuite identifier is a natural component of the `tag` {{fiat-shamir}}, since it fixes the group, the codecs, and the hash instantiation.

The groups are prime-order elliptic curve groups, defined as follows.

## P-256 (secp256r1)

This ciphersuite uses P-256 {{NIST-SP-800-186}} for the Group.

### Elliptic curve group of P-256 (secp256r1) {{NIST-SP-800-186}}

- `order()`: `115792089210356248762697446949407573529996955224135760342422259061068512044369`.
- `serialize([A])`: the compressed Elliptic-Curve-Point-to-Octet-String conversion of {{SEC1}} (`Ne = 33`).
- `deserialize(buf)`: inverts the conversion above. It **MUST** perform partial public-key validation as defined in Section 5.6.2.3.4 of {{!NIST-SP-800-56A=DOI.10.6028/NIST.SP.800-56Ar3}} -- the coordinates are in range, the point is on the curve, and it is not the point at infinity -- and **MUST** fail otherwise.

### Scalar Field of P-256

- `serialize(s)`: the big-endian fixed-length integer encoding `I2OSP` ({{bytes-and-integers}}) (`Ns = 32`).
- `deserialize(buf)`: `OS2IP` ({{bytes-and-integers}}); it **MUST** fail unless the result is in `[0, order() - 1]`.

## BLS12-381 (G1)

This ciphersuite uses the prime-order subgroup G1 of the BLS12-381 elliptic curve {{!RFC9380}} for the Group.

### Elliptic curve group of BLS12-381 (G1) {{!RFC9380}}

- `order()`: `52435875175126190479447740508185965837690552500527637822603658699938581184513`.
- `serialize([A])`: the compressed G1 serialization of Appendix C of {{!PAIRING=I-D.irtf-cfrg-pairing-friendly-curves}} (`Ne = 48`).
- `deserialize(buf)`: inverts the serialization above. It **MUST** perform full point validation -- the encoding is canonical (the x-coordinate is less than the field characteristic and the metadata bits are consistent), the point is on the curve, and it lies in the prime-order subgroup G1 -- and **MUST** reject the point at infinity, failing otherwise.

### Scalar Field of BLS12-381

- `serialize(s)`: the big-endian fixed-length integer encoding `I2OSP` ({{bytes-and-integers}}) (`Ns = 32`).
- `deserialize(buf)`: `OS2IP` ({{bytes-and-integers}}); it **MUST** fail unless the result is in `[0, order() - 1]`.

# Acknowledgments
{:numbered="false"}

The authors thank Jan Bobolz, Vishruti Ganesh, Stephan Krenn, Mary Maller, Ivan Visconti, and Yuwen Zhang for reviewing a previous edition of this specification.

--- back

# Imperative construction of a linear relation {#imperative-construction}

The declarative notation of {{relation-notation}} assumes the shape of a relation -- its scalars, elements, and equations -- is known when the specification is written. Some relations are only fully known at run time (for instance, a range proof over a caller-supplied number of bits); {{relation-notation}}'s loop form already covers this by unrolling in the order the loop executes, but an implementation may instead prefer to build the `LinearRelation` incrementally. This appendix gives one such imperative construction API, informative only: it is one way to implement the compiler underlying {{relation-notation}} and {{relations-in-other-specs}}, not a normative interface.

~~~
class LinearRelationBuilder:
    def allocate_scalars(self, n: int) -> list[int]
    def allocate_elements(self, n: int) -> list[int]
    def append_equation(self,
                        lhs: list[int],
                        rhs: list[(int, int)]) -> None
    def set_elements(self, elements: list[(int, Group)]) -> None
    def build(self) -> LinearRelation
~~~

`allocate_scalars(n)`/`allocate_elements(n)` reserve `n` new scalar/element indices and return them. `append_equation(lhs, rhs)` appends one `Equation` ({{representation}}) with the given image element indices and `(scalar_index, element_index)` right-hand side terms; an implementation may accept a single element index in place of `lhs`, as a shorthand for a one-term image. `set_elements` assigns concrete `Group` values to previously allocated element indices; every allocated element **MUST** be set before `build()` is called. `build()` returns the `LinearRelation` accumulated so far.

The Chaum-Pedersen relation of {{sigma-protocol-group}} is built this way as:

~~~
builder = LinearRelationBuilder(group)
[var_x] = builder.allocate_scalars(1)
[var_G, var_H, var_X, var_Y] = builder.allocate_elements(4)
builder.append_equation([var_X], [(var_x, var_G)])
builder.append_equation([var_Y], [(var_x, var_H)])
builder.set_elements([(var_G, G), (var_H, H),
                      (var_X, X), (var_Y, Y)])
relation = builder.build()
~~~

# Test Vectors

## Seeded PRNG

The random number generator used for test vectors is implemented using SHAKE128 duplex sponge {{fiat-shamir}} with session identifier `__sigma-proofs/TestDRNG/SHAKE128`. Random scalars are generated via `DecodeField` of {{fiat-shamir}}.

The following sections contain test vectors for the Sigma Protocols specified in this document.

Test vectors are grouped by ciphersuite. Each vector includes a `Relation`
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
