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
    title: "Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
    date: 2023
    seriesinfo:
      "NIST SP": "800-186"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography, Version 2.0"
    target: https://www.secg.org/sec1-v2.pdf
    date: 2009
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
  IKOS07:
    title: "Zero-Knowledge from Secure Multiparty Computation"
    target: https://doi.org/10.1145/1250790.1250794
    date: 2007
    author:
    -
      fullname: "Yuval Ishai"
    -
      fullname: "Eyal Kushilevitz"
    -
      fullname: "Rafail Ostrovsky"
    -
      fullname: "Amit Sahai"
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
  ChalkiasGN20:
    title: "Taming the Many EdDSAs"
    target: https://eprint.iacr.org/2020/1244.pdf
    date: 2020
    author:
      - fullname: "Konstantinos Chalkias"
      - fullname: "François Garillot"
      - fullname: "Valeria Nikolaenko"
  AttemaCK21:
    title: "A Compressed Sigma-Protocol Theory for Lattices"
    target: https://doi.org/10.1007/978-3-030-84245-1_19
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
      date: 2023
      author:
      -
        fullname: Dan Boneh
      -
        fullname: Victor Shoup
  Stern93:
    title: "A New Identification Scheme Based on Syndrome Decoding"
    target: https://doi.org/10.1007/3-540-48329-2_2
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
  Schnorr91:
    title: "Efficient Signature Generation by Smart Cards"
    target: https://doi.org/10.1007/BF00196725
    date: 1991
    author:
      - fullname: "Claus-Peter Schnorr"
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
  PointchevalS00:
    title: "Security Arguments for Digital Signatures and Blind Signatures"
    target: https://doi.org/10.1007/s001450010003
    date: 2000
    author:
      - fullname: "David Pointcheval"
      - fullname: "Jacques Stern"
  Orru24:
    title: "Revisiting Keyed-Verification Anonymous Credentials"
    target: https://eprint.iacr.org/2024/1552
    date: 2024
    author:
      - fullname: "Michele Orrù"
  ARC: I-D.ietf-privacypass-arc-crypto
  BBS: I-D.irtf-cfrg-bbs-signatures
  BBSBlind: I-D.irtf-cfrg-bbs-blind-signatures
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
  HowgraveGrahamS01:
    title: "Lattice Attacks on Digital Signature Schemes"
    target: https://doi.org/10.1023/A:1011214926272
    date: 2001
    author:
      - fullname: "Nick Howgrave-Graham"
      - fullname: "Nigel P. Smart"
  JancarSSS20:
    title: "Minerva: The curse of ECDSA nonces"
    target: https://doi.org/10.46586/tches.v2020.i4.281-308
    date: 2020
    author:
      - fullname: "Jan Jancar"
      - fullname: "Vladimir Sedlacek"
      - fullname: "Petr Svenda"
      - fullname: "Marek Sys"
  PS3:
    title: "Console Hacking 2010: PS3 Epic Fail"
    target: https://fahrplan.events.ccc.de/congress/2010/Fahrplan/attachments/1780_27c3_console_hacking_2010.pdf
    date: 2010
    seriesinfo:
      "In": "27th Chaos Communication Congress (27C3)"
    author:
      - fullname: "fail0verflow"

--- abstract

This document describes Sigma Protocols for proving knowledge of preimages of linear maps in prime-order elliptic curve groups. These are sometimes also called _Maurer Proofs_, or _proofs of knowledge of a preimage of a group homomorphism_.

Examples include zero-knowledge proofs for discrete logarithm relations, ElGamal encryptions, Pedersen commitments, and range proofs.

--- middle

# Introduction

Zero-knowledge proofs of knowledge allow a prover to convince a verifier that a statement is true, without revealing anything other than what is already revealed by the statement itself.

Sigma Protocols are an essential component of a number of cryptographic constructions, such as anonymous credentials {{ARC}} {{BBS}}, verifiable random functions {{?RFC9381}}, anonymous tokens {{?RFC9497}}, blind signatures {{BBSBlind}}, and proofs of knowledge of the opening of a Pedersen commitment {{Pedersen91}}. This document specifies a single Sigma Protocol for proving knowledge of a preimage of a linear map over a prime-order group {{Cramer97}} {{Maurer09}}. A *linear relation* is a system of equations among group elements that is linear in the secret scalars; affine relations with constant terms (e.g. verifiable encryption) and quadratic equations (e.g. range proofs) can also be expressed as the preimage of a linear map ({{linear-map}}).

A Sigma Protocol is an interactive proof with the following three-message flow:

~~~ aasvg
+----------------------+                            +----------------------+
|        Prover        |                            |       Verifier       |
|  witness, instance   |                            |       instance       |
+----------------------+                            +----------------------+
          |                                                     |
          | ProverCommitment(instance, witness, rng)            |
          | commitment                                          |
          |---------------------------------------------------->|
          |                                                     |
          |                                           challenge |
          |<----------------------------------------------------|
          |                                                     |
          | ProverResponse(prover_state, challenge)             |
          | response                                            |
          |---------------------------------------------------->|
          |                                                     |
          | Verifier(instance, commitment, challenge, response) |
          |                              accept or reject       |
~~~
{: #fig-sigma-proofs title="Flow of an interactive sigma protocol."}

The messages are respectively called **commitment** (computed by the prover), **challenge** (randomly sampled by the verifier), and **response** (computed by the prover). The prover is stateful and maintains a single-use private state between the first and third messages. The **transcript** `(commitment, challenge, response)` is checked by the verifier.

Sigma Protocols can compose: several statements can be proven simultaneously (AND composition), disjunctively (OR composition {{CramerDS94}}), or thresholded. AND composition of linear relations is immediate in this document ({{relation-notation}}); OR and threshold composition, and composition across heterogeneous proof systems, are not part of this document, but possible via the Sigma Protocol interface. Composition carries soundness and zero-knowledge caveats; see {{security-considerations}} and {{privacy-considerations}}.

# Terminology and conventions in this document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

The following notation is used throughout this document.

## Bytes and integers {#bytes-and-integers}

A byte is an 8-bit unsigned integer (an octet), and a *byte string* is a finite sequence of bytes. The empty byte string is written `""`, and `x || y` is the concatenation of the byte strings `x` and `y`. For any finite sequence `x`, `len(x)` is the number of elements in `x`; for a byte string, this is its length in bytes. Byte strings are indexed from zero: for integers `0 <= i <= j <= len(x)`, `x[i : j]` denotes the `(j - i)`-byte substring of `x` at positions `i, i+1, ..., j-1`, so that `x[0 : N]` is the first `N` bytes of `x` and `x[i : i]` is `""`.

`I2OSP(n, w)` and `OS2IP(x)` are the integer/byte-string conversion primitives used throughout this document, in big-endian byte order, as defined in {{Section 4 of !RFC8017}}. `I2OSP(n, w)` converts a non-negative integer `n` with `0 <= n < 256^w` into a `w`-byte, big-endian byte string, and fails if `n >= 256^w`; `OS2IP(x)` is its inverse, mapping a `w`-byte string to the integer in `[0, 256^w)` that it represents. `LE(n, w)` is the little-endian counterpart defined in {{fiat-shamir}}. `LE2IP(x)`, also defined in {{fiat-shamir}}, converts a little-endian byte string back into a non-negative integer. Byte order and length of the scalar and group-element encodings are fixed by each ciphersuite ({{ciphersuites}}).

## Randomized algorithms {#rng-definition}

The prover commitment algorithm requires fresh, single-use randomness to ensure privacy of the witness. This document denotes with `rng` a cryptographically secure random number generator (CSPRNG), and uses `Group.random_scalar(rng)` to denote sampling a uniformly random element of the scalar field, similarly to `RandomScalar()` of {{Section 2.1 of ?RFC9497}}.

## Group abstraction {#group-abstraction}

Elliptic curves are presented using additive notation.

Group elements are upper-case (`G`, `X`, `M`) and scalars lower-case (`x`, `s`). The name `G` denotes the group generator `Group.generator()` ({{group}}). Pseudocode and interface names are descriptive (e.g. `commitment`, `image`, `witness`) and do not follow this rule.

### Group elements {#group}

`identity()` is the neutral element, `generator()` returns the canonical generator of the prime-order subgroup ({{ciphersuites}}), and `order()` returns its order `p`. Addition, negation, equality, and scalar multiplication by a `Scalar` are written `+`, `-`, `==`, and `*`.

`serialize(elements: [Group; N])` and `deserialize(buffer)` convert `N` non-neutral group elements into a fixed-length `Ne * N`-byte encoding, where `Ne` is fixed per ciphersuite ({{ciphersuites}}).

Both `serialize` and `deserialize` are defined only on non-neutral elements. Serialization **MUST** fail on the identity element, and deserialization **MUST** fail for invalid encodings, including on the encoding of the identity. An honest prover statistically hits this event only with negligible probability. See {{Section 10.1 of RFC9380}}, Appendix C of {{PAIRING}}, {{Section 2.1 of ?RFC9497}}, {{ARC}}.

### Scalars {#scalar}

A `Scalar` is an element of the group's *scalar field*, the prime field of integers modulo the group order `p`. Addition and multiplication are written `+` and `*` via operator overloading.

`serialize(scalars: list[Scalar; N])` and `deserialize(buffer)` batch convert between `[Scalar; N]` and its canonical, fixed-length `Ns * N`-byte encoding.

Sampling a random scalar takes two steps: obtaining high-quality entropy via a CSPRNG (e.g., `getrandom()`; see {{?RFC4086}} for randomness requirements), and reducing the resulting bytes to a scalar. It is **RECOMMENDED** that the latter be done via `DecodeField` as in {{fiat-shamir}}. Different sampling mechanisms, such as the wide reduction of `hash_to_field` ({{Section 5.2 of ?RFC9380}}) and the integer conversion of Appendix A.4.1 of {{FIPS186-5}} do not affect interoperability of proofs. The "discard method" of Appendix A.4.2 of {{FIPS186-5}} **SHOULD NOT** be used {{constant-time}}.

# Linear relations {#linear-relations}

This section specifies the statement being proven: the preimage of a linear map over a group, also known as the preimage of a group homomorphism. The Sigma Protocol proving knowledge of a preimage is specified in {{sigma-protocol-group}}.

## Linear map {#linear-map}

A linear map is a matrix-vector product `image = M * witness`, where `M` is a matrix of group elements and `witness` is a vector of scalars.

`M` and `image` together form the statement (the *instance*), while `witness` is the secret. The _relation_ (the set of instance-witness pairs of which knowledge is proven) is:

~~~
R := { ((M, image), witness) : image = M * witness }
~~~

`image` is the result of the multi-scalar multiplication of each matrix row with the witness. For `i` in `0, ..., num_equations - 1`

~~~
image[i] = sum(witness[j] * M[i][j] for j in 0, ..., num_scalars - 1)
~~~

`num_scalars` is the length of `witness` (the width of `M`), and `num_equations` is the number of group elements in `image` (the height of `M`).

As an example, Schnorr's identification protocol has `num_scalars = num_equations = 1` and `M = [[G]]`, where `G` is the group generator, proving knowledge of the scalar `x` such that the group element `X` satisfies `X = x * G` {{?RFC8235}}.

Another example is the Chaum-Pedersen relation {{ChaumP92}}: given the group generator `G` and group elements `H`, `X`, `Y`, the prover shows knowledge of a single scalar `x` such that `X = x * G` and `Y = x * H`. Here `num_scalars = 1`, `num_equations = 2`, and:

~~~
M = [[G],
     [H]]
~~~

Variants of the Chaum-Pedersen relation are widely used for VRFs {{?RFC9381}} and anonymous tokens {{?RFC9497}}. Proofs of knowledge of the opening `(m, r)` of a Pedersen commitment {{Pedersen91}} `C = m * G + r * H` are Okamoto-Schnorr proofs {{Okamoto92}}.

Affine equations with constant terms can be expressed directly through image terms and coefficients ({{representation}}); more elaborate relations, such as quadratic equations, reduce to this same form by letting instance elements themselves serve as bases ({{relation-notation}}).

The group `Group`, and its generator, are provided by the ciphersuite {{ciphersuites}}. The statement author has the responsibility to select the appropriate `M`, and this requires care. Computationally-independent bases, sometimes also called _auxiliary generators_, or _nothing up my sleeve (NUMS) generators_, may be computed via hash to the curve ({{Section 3 of !RFC9380}}).

## Representation {#representation}

The linear relations proven with Sigma Protocols are typically sparse: most entries of `M` are zero. This document handles and serializes them in a sparse, symbolic form rather than as a 2-dimensional vector of group elements.

A `LinearRelation` is the instance for the Sigma Protocol. It fixes the linear map `M` and the image, that is, the instance `(M, image)` of the relation `R` ({{linear-map}}). There might be multiple witnesses for the same `(M, image)`, or no valid witness. The word *relation* is used here in the linear-algebra sense: a system of linear equations among group elements. A `LinearRelation` is held and evaluated by both prover and verifier ({{map-evaluation}}).

~~~
class LinearRelation:
  elements: list[Group]
    # non-empty; elements[0] is fixed to Group.generator()
  equations: list[Equation]    # non-empty

class Equation:
  image: list[(int, Scalar)]
    # non-empty, (element_index, coeff)
  terms: list[(int, int, Scalar)]
    # non-empty, (scalar_index, element_index, coeff)
~~~

A `LinearRelation` holds a set of group elements (each corresponding to an `element_index`) and a list of equations. Each row of `M` is called an `Equation`, and consists of two lists of terms.

The `image` terms (the left-hand side) are pairs `(element_index, coeff)`. The image is the sum of `coeff * elements[element_index]`.

The `terms` (the right-hand side) are triplets `(scalar_index, element_index, coeff)`. Each `coeff` is a scalar ({{scalar}}) fixed by the instance.

A `LinearRelation` **MUST** have at least one equation, and every equation's `image` and `terms` **MUST** be non-empty. A constant of the statement (an element carrying no witness scalar) is encoded as an image term ({{relation-notation}}). It **MUST NOT** be encoded as a right-hand side term whose witness scalar is "fixed" to `1`. A coefficient **MAY** be zero.

The instance **MUST** contain, as individually-indexed elements, every group element on which the statement depends. In particular, all group elements processed by the verifier **MUST** appear in the statement, else the resulting argument is malleable across its preimages ({{sigma-ni-security}}).

For instance, the verifiable-decryption statement `M + E1 = x * E0` is encoded with the two image terms `(M, 1), (E1, 1)`, never as the single element `F = M + E1`. Otherwise, the same proof will verify for any `F = M' + E1'`, even when `M' != M`. As another example, a statement multiplying a scalar by a sum of elements, such as `Y = x * (E0 + E1)`, is expressed by repeating the scalar index across terms, as `terms = [(0, 1, 1), (0, 2, 1)]`, never as the single element `K = E0 + E1`. An element may appear multiple times in the same equation, even with the same coefficient and scalar.

Every group element index **MUST** have an associated group element. Every element **MUST** appear in the terms or image terms of at least one equation, except for the generator (index 0), which is present in every instance whether or not an equation uses it. Every scalar index **MUST** appear in at least one term, else the corresponding response is accepted unchecked.

For a valid instance, let:

~~~
num_elements(instance)  = len(instance.elements)
num_equations(instance) = len(instance.equations)
num_scalars(instance)   = 1 + max(s for eq in instance.equations
                                    for (s, _, _) in eq.terms)
~~~

The number of group elements is independent of the number of equations. For instance, Chaum-Pedersen has `num_elements = 4`, `num_equations = 2`.

## Map evaluation {#map-evaluation}

This document writes `map(instance, scalars)` for the function that evaluates `M` at `scalars`:

~~~
map(instance, scalars) -> list[Group]

1. out = []
2. for equation in instance.equations:
3.   acc = Group.identity()
4.   for (scalar_index, element_index, coeff) in equation.terms:
5.     acc = acc + (coeff * scalars[scalar_index]) \
                   * instance.elements[element_index]
6.   out.append(acc)
7. return out
~~~

`image(instance)` denotes the evaluation of each equation's left-hand side: the list of `num_equations(instance)` group elements whose `i`-th entry is the sum of `coeff * instance.elements[element_index]` over the image terms of the `i`-th equation.

## Specifying the relation {#relation-notation}

This section defines a symbolic notation in the spirit of {{CamenischS97}} for declaring scalars, elements, and equations.

The notation is a specification convention, not a wire format. Prover and verifier must agree on the compiled `LinearRelation` ({{representation}}) and its serialization ({{serialize-linear-relations}}). The notation of this section is the **RECOMMENDED** way to present a relation.
{: #relations-in-other-specs}

A linear relation is declared as a US-ASCII block:

~~~
Relation NAME(P[0], ..., P[n-1]):
  Witness: s[0], ..., s[k-1]
  Equations:
    <linear combination> = <linear combination>
    ...
~~~

As a first example, the Chaum-Pedersen relation of {{linear-map}} is:

~~~
Relation ChaumPedersen(H, X, Y):
  Witness: x
  Equations:
    X = x * G
    Y = x * H
~~~

The relation parameters are the public values of the statement. A parameter whose name begins with an upper-case letter is a group element, and one whose name begins with a lower-case letter is a public scalar (following {{group-abstraction}}); the names under `Witness:` are the secret scalars. `G` denotes the group generator at element index `0`, and **MUST NOT** appear among the relation parameters. Every other name used in `Equations:` is declared exactly once, as a parameter or under `Witness:`. A declaration **MUST** compile to a valid instance ({{instance-validation}}). All elements and witness scalars **MUST** be used ({{representation}}).

Each equation is an equality between two linear combinations. Each term is the product of an optional *coefficient*, an optional witness scalar, and exactly one element name. Every equation **MUST** be linear in the witness. A coefficient is a public constant of the statement evaluated in the scalar field before compilation. An omitted coefficient is `1`, and a leading `-` on a term negates its coefficient. Expressions in parentheses distribute before the term rules apply: `2 * r * (X1 - X2)` denotes `2 * r * X1 - 2 * r * X2`.

As an example with two witness scalars in a single equation, the Okamoto-Schnorr proof proves knowledge of the opening of a Pedersen commitment {{Pedersen91}}:

~~~
Relation PedersenOpening(H, C):
  Witness: m, r
  Equations:
    C = m * G + r * H
~~~

`ChaumPedersen` compiles to `elements = [G, H, X, Y]` and `equations = [Equation(image=[(2, 1)], terms=[(0, 0, 1)]), Equation(image=[(3, 1)], terms=[(0, 1, 1)])]`, while `PedersenOpening` is compiled to a `LinearRelation` with `elements = [G, H, C]` and `equations = [Equation(image=[(2, 1)], terms=[(0, 0, 1), (1, 1, 1)])]`.

The compiled `LinearRelation` assigns indices in declaration order. Vectors of names (for example, `C_0, ..., C_{n-1}`) and families of equations stated over an index range unroll, in index order, to names and equations of the ordinary form.

Terms compile to the two lists of {{representation}}. A term carrying a witness scalar compiles to the right-hand side term (homomorphism) `(scalar_index, element_index, coeff)`; a term without one (a *constant term*) compiles to the left-hand side term (image) `(element_index, coeff)`, with its coefficient negated when the term is written on the right-hand side. Terms appear in the order written, left-hand side first; equations compile in the order they are written under `Equations:`. Indices attach to names: every occurrence of a name, within or across equations, denotes the same scalar or element index, and every occurrence of a scalar parameter denotes the same public value.

As an example with a public scalar parameter, below is the relation stating that `C` opens to the *public* value `m`, that is, `C - m * G = r * H`:

~~~
Relation OpensTo(m, H, C):
  Witness: r
  Equations:
    C = m * G + r * H
~~~

`m` is now a scalar parameter, so `m * G` is a constant term. The relation compiles to `elements = [G, H, C]` and `equations = [Equation(image=[(2, 1), (0, -m)], terms=[(0, 1, 1)])]`.

As an example with a constant term crossing sides, correct ElGamal decryption states that the ciphertext `(E0, E1)`, with `E1 = r * X - M`, decrypts to `M` under the decryption key `x` of `X`:

~~~
Relation ElGamalDecryption(X, E0, E1, M):
  Witness: x
  Equations:
    X = x * G
    M = x * E0 - E1
~~~

The constant term `- E1` crosses to the image with its coefficient negated: the second equation compiles to `Equation(image=[(4, 1), (3, 1)], terms=[(0, 2, 1)])`, identically to the spelling `M + E1 = x * E0`, and both `M` and `E1` are bound individually by the serialization of {{serialize-linear-relations}}.

As yet another example with a distributed scalar, the following proves correct encryption of a public message `M` under the aggregate key `X1 + X2`, as arises in threshold decryption: the ciphertext is `(E0, E1)`, with `E0 = r * G` and `E1 = r * (X1 + X2) - M`:

~~~
Relation AggregateEncryption(X1, X2, M, E0, E1):
  Witness: r
  Equations:
    E0 = r * G
    M + E1 = r * (X1 + X2)
~~~

The scalar `r` distributes over the parenthesized sum, so the second equation compiles to `Equation(image=[(3, 1), (5, 1)], terms=[(0, 1, 1), (0, 2, 1)])`.

As a last example, the following proves that the value committed by `C` is a bit, the building block of range proofs:

~~~
Relation Bit(H, C):
  Witness: b, r, s
  Equations:
    C = b * G + r * H
    C = b * C + s * H
~~~

`Bit` compiles to `elements = [G, H, C]` and `equations = [Equation(image=[(2, 1)], terms=[(0, 0, 1), (1, 1, 1)]), Equation(image=[(2, 1)], terms=[(0, 2, 1), (2, 1, 1)])]`: the element index `2` (the commitment `C`) appears both in each equation's image and among the bases of the second equation.

AND composition comes for free for this relation family. To do so, concatenate the parameter lists, `Witness:`, and `Equations:` of each sub-relation. Under concatenation, a name kept in common should denote the same scalar or element in every sub-relation, and is declared exactly once in the combined declaration. Names not intended to be shared **MUST** be renamed apart before concatenating.

## Instance validation {#instance-validation}

For an instance to be valid, it **MUST** satisfy all below conditions:

1. The instance has at least one equation: `num_equations(instance) > 0`.
2. Every equation in `instance.equations` has a non-empty `terms` list and a non-empty `image` list.
3. Every `scalar_index` and every `element_index` is a non-negative integer less than `2^32`; so are `num_equations(instance)`, and each equation's term count and image-term count.
4. Every element index is less than `num_elements(instance)`. In other words, every index references a group element.
5. Every element index other than `0` appears in the terms or image terms of at least one equation; the generator (index `0`) is present in every instance whether or not an equation uses it ({{representation}}).
Together with check 4, this ensures `num_elements(instance)-1` is the largest referenced element index.
6. Every scalar index appears in the terms of at least one equation.
7. `num_elements(instance) > 0`, and `instance.elements[0]` is the group generator `Group.generator()` ({{representation}}).
8. No element of `instance.elements` is the identity element.
9. No element of `image(instance)` is the identity element: an equation whose image evaluates to the identity is satisfied by the all-zero witness, so a proof of it attests nothing.
10. No column of the matrix `M` is the identity. That is, for every scalar index, there is at least one equation for which the sum of `coeff * elements[element_index]` over the terms carrying that scalar index is not the identity.

The prover **SHOULD** reject an invalid instance, and **MAY** additionally check that `image == map(instance, witness)` before proving; {{privacy-considerations}} and {{instance-security}} state when this check, or a stronger precaution, is required. The verifier **MUST** fail on an invalid instance ({{verifier}}, {{non-interactive}}), either when the instance is constructed or during verification itself.

`ValidateInstance(instance)` denotes the function returning `true` if all above predicates are met. Instance validation won't flag all violations of {{representation}} (for instance, a registered element obtained as a precomputed linear combination from one obtained independently) because the instance generation can't know how a group element is obtained. A structurally valid instance may still yield an unsound argument.

## Serialization {#serialize-linear-relations}

A `LinearRelation` is serialized as a sparse matrix encoded in row-major order: each equation's image terms, then its right-hand side terms, each list preceded by its count ({{representation}}), followed by the group elements at indices `1` onwards. Counts and indices are encoded in 4 bytes via `LE` ({{bytes-and-integers}}). Coefficients are encoded with the scalar serialization function (`Ns` bytes each, {{ciphersuites}}). The encoding is unambiguous and prefix-free.

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
 4.   image_terms = instance.equations[i].image
 5.   out = out || LE(len(image_terms), 4)
 6.   for (element_index, coeff) in image_terms:
 7.     out = out || LE(element_index, 4) || Scalar.serialize([coeff])
 8.   terms = instance.equations[i].terms
 9.   out = out || LE(len(terms), 4)
10.   for (scalar_index, element_index, coeff) in terms:
11.     out = out || LE(scalar_index, 4)
12.     out = out || LE(element_index, 4) || Scalar.serialize([coeff])
13. return out || Group.serialize(
      instance.elements[1 : num_elements(instance)])
~~~

For example, the compiled `ChaumPedersen` relation of {{relation-notation}} serializes to

~~~
LE(2, 4)                                        # 2 equations
LE(1, 4) || LE(2, 4) || Scalar.serialize([1])   # image: X
LE(1, 4) || LE(0, 4) || LE(0, 4)
         || Scalar.serialize([1])               # term: x * G
LE(1, 4) || LE(3, 4) || Scalar.serialize([1])   # image: Y
LE(1, 4) || LE(0, 4) || LE(1, 4)
         || Scalar.serialize([1])               # term: x * H
Group.serialize([H, X, Y])                      # statement elements
~~~

`SerializeLinearRelation` operates on a `LinearRelation` as compiled from its declaration, following its equation and term order ({{relation-notation}}). The same relation expressed in two different ways (for example, swapping two rows of `M`) will yield different serializations.

# The Sigma Protocol {#sigma-protocol-group}

This section specifies the proof of knowledge for the preimage of a linear map ({{linear-relations}}). These proofs are sometimes also called _Maurer proofs_ {{Maurer09}} {{Cramer97}}.

## Interface {#core-interface}

A Sigma Protocol provides the following interface:

- `ProverCommitment(instance, witness, rng)`: produces a pair `(commitment, prover_state)` consisting of the **commitment** message, and a private `prover_state`. The prover state **MUST** be used at most once. The random number generator `rng` is defined in {{rng-definition}}.
- `ProverResponse(prover_state, challenge)` produces the **response**.
- `Verifier(instance, commitment, challenge, response)`, the verification algorithm.

These are the *interactive* protocol's building blocks. Implementations **MAY** also provide the **zero-knowledge simulator**:

- `SimulateResponse(instance, rng) -> (response, state)`, which returns a simulated response, and a simulator state.
- `SimulateCommitment(state, response, challenge) -> simulated_commitment`, which returns the `simulated_commitment` such that `Verifier(instance, simulated_commitment, challenge, response)` accepts.

Both are specified concretely for the linear-map Sigma Protocol in {{simulator}}. The simulator is useful for proof composition (e.g. OR-composition {{CramerDS94}}) and for compact serialization {{narg-string-compact}}.

This interface allows for composition, and **SHOULD NOT** be exposed directly to consumers of the non-interactive argument. In particular, `ProverResponse` **MUST NOT** be invoked with a `challenge` that was not either sent by an honest interactive verifier or derived from the instance and commitment via the Fiat-Shamir transformation ({{non-interactive}}). Supplying an invalid challenge or an arbitrary prover state will compromise soundness and zero-knowledge.

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

- A commitment message (a vector of group elements)
- A (private) prover state

Procedure:

1. fail if len(witness) != num_scalars(instance)
2. nonces = [Group.random_scalar(rng)
             for j in 0, ..., num_scalars(instance) - 1]
3. commitment = map(instance, nonces)
4. return (commitment, prover_state := (witness, nonces))
~~~

The prover **MAY** produce an output (and not fail) if the witness is not valid for the instance provided. The prover **MUST** fail if the witness length does not match `num_scalars(instance)`: a mismatch cannot yield a valid proof.

### Prover response

~~~
ProverResponse(prover_state, challenge)

Inputs:

- prover_state, the current state of the prover
- challenge, the verifier challenge scalar

Output: the response message, an array of scalars

Procedure:

1. witness, nonces = prover_state
2. fail if len(witness) != len(nonces)
3. return [nonces[i] + witness[i] * challenge
           for i in 0, ..., len(nonces) - 1]
~~~

The prover **MUST** fail if the lengths of witness and nonces mismatch.

## Verifier {#verifier}

The **challenge** is a scalar drawn uniformly at random from the scalar field. Non-interactive Sigma Protocols derive the challenge via the Fiat-Shamir transformation ({{non-interactive}}).

The verification equation is as follows:

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
4. got = [commitment[i] + challenge * image(instance)[i]
          for i in 0, ..., num_equations(instance) - 1]
5. fail if got != expected
~~~

The verifier **MUST** enforce instance validity (Step 1, see {{instance-validation}}), and that the shape of the transcript matches that of the instance.

## Simulator {#simulator}

Implementations that expose the zero-knowledge simulator ({{core-interface}}) provide the two algorithms below; they are also what the compact verifier ({{non-interactive}}) relies on to recover the prover's commitment from `(challenge, response)`.

`SimulateResponse(instance, rng)` returns as simulated response a vector of `num_scalars(instance)` uniformly random scalars, and as simulator state the instance itself.

`SimulateCommitment(state, response, challenge)` solves the verification equation ({{verifier}}) for the commitment, returning the vector of `num_equations(state)` group elements

~~~
simulated_commitment[i] = map(state, response)[i]
                              - challenge * image(state)[i]
~~~

Drawing `response` uniformly at random with `SimulateResponse` and then computing `commitment` with `SimulateCommitment` yields a transcript `(commitment, challenge, response)` with the same distribution as an honest one. This is the honest-verifier zero-knowledge property ({{security-considerations}}).

# Non-interactive Sigma Protocols {#non-interactive}

The Fiat-Shamir transformation applied to Sigma Protocols yields a non-interactive zero-knowledge argument of knowledge.

{{fiat-shamir}} describes how to instantiate the transformation, for the group and field codecs given. This section specifies the session identifier binding a proof to its application ({{sigma-proofs-tag}}), the challenge derivation shared by prover and verifier ({{challenge-derivation}}), the two non-interactive argument (NARG) string serializations ({{sigma-narg}}), and batch verification ({{batch-verification}}).

## Tag and session identifier {#sigma-proofs-tag}

The session identifier `session_id` is a 32-byte string. It **SHOULD** be derived from a string `tag` using `DeriveSessionID` of {{fiat-shamir}}. The prover and verifier initialize their duplex sponge state from it ({{challenge-derivation}}).

The `tag` is a byte string following the security requirements on the session identifier in {{fiat-shamir}}. It **MUST** contain, verbatim, the *flavor* (`DSFS` for batchable NARG strings, `CMPT` for compact NARG strings), and the ciphersuite identifier ({{ciphersuites}}). Following the domain-separation conventions of {{Section 3.1 of !RFC9380}}, an application concatenates its own name, version, and epoch with these two components. As an example, a reasonable choice of `tag` for a fictional application named Foo is:

~~~
FOO-V{xx}-{tttt}-{flavor}-with-{ciphersuiteID}
~~~

where `xx` is the two-digit number indicating the version, `tttt` is the four-digit number identifying the epoch, `flavor` is the serialization flavor marker, and `ciphersuiteID` is the ciphersuite identifier of {{ciphersuites}}. For instance, for batchable NARG strings:

~~~
FOO-V01-0001-DSFS-with-sigma-proofs_Shake128_P256
~~~

The corresponding tag for compact NARG strings replaces the flavor marker `DSFS` (duplex sponge Fiat-Shamir) with `CMPT`.

The prover and the verifier each construct the tag (or session identifier). Neither should accept a session identifier supplied by a third party. An adversary who controls the entire session identifier can cause a proof to be accepted where it was never intended.

## Challenge derivation {#challenge-derivation}

The prover derives the challenge from the tag ({{sigma-proofs-tag}}), the instance being proven, and the serialized commitment message; the verifier re-derives it from the same values, exactly as the prover does. Both compute `DeriveChallenge`, which outputs the challenge, a scalar:

~~~
DeriveChallenge(tag, instance, commitment_bytes)

Inputs:

- tag, a byte string uniquely identifying the session
- instance, the LinearRelation being proven
- commitment_bytes, the serialized commitment message

Output: the challenge, a scalar

1. session_id = DeriveSessionID(tag)
2. duplex_sponge = DS.Init(session_id)
3. duplex_sponge.Absorb(SerializeLinearRelation(instance))
4. duplex_sponge.Absorb(commitment_bytes)
5. return DecodeField(duplex_sponge.Squeeze(Ns + 16), p, 1)
~~~

`DS`, `DeriveSessionID`, and `DecodeField` are defined in {{fiat-shamir}}; `Ns + 16` is the input length `DecodeField` requires over a prime field, and the choices of `DecodeField` for the ciphersuites of this document are discussed in {{ciphersuites}}. The challenge is drawn from the full scalar field ({{sigma-ni-security}}).

## Non-interactive argument string serialization {#sigma-narg}

Two serialization flavors are possible:

- A **batchable** NARG string serializes the prover messages `(commitment, response)`, as in {{fiat-shamir}}, and it permits amortized verification costs ({{batch-verification}}).
- A **compact** NARG string serializes `(challenge, response)`. It is preferable in the common case, whenever the commitment (`num_equations` group elements) is larger than a single challenge scalar.

A batchable NARG string is a `(Ne * num_equations + Ns * num_scalars)`-byte string, while a compact NARG string is a `(Ns * (num_scalars + 1))`-byte string. A NARG string verifies only under the flavor it was produced for: the flavor marker is a mandatory tag component ({{sigma-proofs-tag}}). Both flavors have the same soundness guarantees.

NARG strings are not deterministic, and so applications **MUST NOT** rely on the uniqueness of the NARG string for replay protection or as a nullifier.

## Batchable NARG strings {#narg-string-batchable}

A **batchable** NARG string is the NARG string of {{fiat-shamir}}, consisting of the concatenation of the serialized prover messages using their respective serialization functions:

~~~
Group.serialize(commitment) || Scalar.serialize(response)
~~~

`ProveBatchable` and `VerifyBatchable` are the NARG prover and verifier of {{fiat-shamir}} instantiated with the Sigma Protocol of {{sigma-protocol-group}}.

- `ProveBatchable(tag, instance, witness, rng)` computes the commitment message with `ProverCommitment`, derives the challenge as `DeriveChallenge(tag, instance, Group.serialize(commitment))` ({{challenge-derivation}}), computes the response with `ProverResponse(prover_state, challenge)`, and outputs the NARG string above.
- `VerifyBatchable(tag, instance, narg_string)` checks:
  1.  `ValidateInstance(instance)`
  2.  `len(narg_string)` is exactly `Ne * num_equations(instance) + Ns * num_scalars(instance)`
  3.  deserialization succeeds
  4.  `Verifier(instance, commitment, challenge, response)` accepts.

## Compact NARG strings {#narg-string-compact}

A **compact** NARG string serializes `serialize(challenge) || serialize(response)`. The Sigma Protocol transcript is recovered by invoking the simulator.

~~~
ProveCompact(tag, instance, witness, rng)

Inputs:

- tag, a byte string uniquely identifying the session
- instance, the LinearRelation to be proven
- witness, the prover's secret witness
- rng, a cryptographically secure random number generator

Output: the compact NARG string

Procedure:

1. (commitment, prover_state) = ProverCommitment(instance, witness, rng)
2. commitment_bytes = Group.serialize(commitment)
3. challenge = DeriveChallenge(tag, instance, commitment_bytes)
4. response = ProverResponse(prover_state, challenge)
5. return Scalar.serialize([challenge]) || Scalar.serialize(response)
~~~

The verifier recomputes the commitment from the challenge and response via `SimulateCommitment` ({{simulator}}), then recomputes the challenge from that commitment and accepts only if it matches the one in the NARG string.

~~~
VerifyCompact(tag, instance, narg_string)

Inputs:

- tag, a byte string uniquely identifying the session
- instance, the LinearRelation to be proven
- narg_string, the compact NARG string

Output: a boolean indicating whether the NARG string is valid

Procedure:

1. fail if ValidateInstance(instance) fails
2. Nr = num_scalars(instance) * Ns
3. fail if len(narg_string) != Ns + Nr
4. challenge = Scalar.deserialize(narg_string[0 : Ns])[0]
5. response = Scalar.deserialize(narg_string[Ns : Ns + Nr])
6. commitment = SimulateCommitment(instance, response, challenge)
7. fail if any element of commitment is the identity element
8. expected_challenge = DeriveChallenge(tag, instance,
     Group.serialize(commitment))
9. return challenge == expected_challenge
~~~

Step 7 maintains consistency with `Group.deserialize`, which rejects the identity element. Since the simulator always outputs accepting transcripts, there is no need to run `Verifier` in this case.

## Batch verification {#batch-verification}

Verification of multiple batchable NARG strings **MAY** be done more efficiently than verifying each NARG string on its own, via batch verification. Batch verification can be more efficient even in the presence of a single instance, provided the instance has at least a few equations. Batch verification is a local verifier-side optimization, which affects neither the prover nor the NARG string.

Batch verification is done by re-computing the verifier challenge of each NARG string individually ({{challenge-derivation}}), and then checking a single random linear combination of the verification equations of the whole batch. See {{Section 8.2 of ?RFC8032}}, {{BDLSY11}}, and {{BellareGR98}}.

The verification equation for `Nt` transcripts `(commitment, challenge, response)` of preimages of linear relations is:

~~~
commitment[i][j] + challenge[i] * image(instances[i])[j]
                 == map(instances[i], response[i])[j]
~~~

for each transcript index `i` and each equation index `j`.
Batch verification consists of sampling uniformly random scalars `batching_randomness[i][j]` (for `i = 0, ..., Nt - 1` and `j = 0, ..., num_equations(instances[i]) - 1`) and checking the single equation:

~~~
sum(
  batching_randomness[i][j] * commitment[i][j]
  + batching_randomness[i][j] * challenge[i] * image(instances[i])[j]
  - batching_randomness[i][j] * map(instances[i], response[i])[j]
  for i in 0, ..., Nt - 1
  for j in 0, ..., num_equations(instances[i]) - 1
) == Group.identity()
~~~

Similarly to batch verification of Ed25519 signatures {{BDLSY11}}, a false NARG string will be accepted with probability at most `2^-128`, which is negligible. In general, for `batching_randomness` elements drawn uniformly from a set of `2^t` scalars, a false NARG string will be accepted with probability at most `2^-t`.

It is **RECOMMENDED** that the batching randomness be generated deterministically, with the duplex sponge of {{fiat-shamir}} as follows; it **MAY** instead be freshly sampled from a cryptographically secure random number generator. Below, `session_ids[i]` is the 32-byte session identifier of the `i`-th NARG string being verified ({{sigma-proofs-tag}}).

~~~
 1. batching_sid = DeriveSessionID(
      "irtf-cfrg-sigma-protocols/batch-verify")
 2. duplex_sponge = DS.Init(batching_sid)
 3. for i in 0, ..., Nt - 1:
 4.   duplex_sponge.Absorb(session_ids[i])
 5.   duplex_sponge.Absorb(SerializeLinearRelation(instances[i]))
 6.   duplex_sponge.Absorb(narg_strings[i])
 7. batching_randomness_bytes = duplex_sponge.Squeeze(
      16 * sum(num_equations(instances[i]) for i in 0, ..., Nt - 1))
~~~

The session identifier has fixed length, and the length of each NARG string is determined by the respective instance.

The squeezed output is read in row-major order (for example, the second batching randomness corresponds to the second equation of the first transcript). Each 16-byte chunk is interpreted as a little-endian integer via `LE2IP` ({{bytes-and-integers}}). The batching randomness elements are uniform in `[0, 2^128)` and are used as scalars without further reduction.

~~~
 8. k = 0
 9. for i in 0, ..., Nt - 1:
10.   for j in 0, ..., num_equations(instances[i]) - 1:
11.     batching_randomness[i][j] =
          LE2IP(batching_randomness_bytes[16*k : 16*(k+1)])
12.     k = k + 1
~~~

The batch verifier **MUST** perform instance validation for each instance, and **MUST** compute each of the verifier challenges with `DeriveChallenge` ({{challenge-derivation}}). Empty batches are accepted as valid; the batch size **MUST** be less than `2^32`. Upon failure, batch verification does not identify the offending NARG string; an application may fall back to verifying the NARG strings individually.

Batch verification is sound only if the prover(s) cannot choose their messages as a function of the batching randomness. When derived deterministically, the batching randomness **MUST** therefore absorb every value in the batched equation before squeezing. In particular, this includes the response message. Omitting prover messages from the derivation will compromise soundness of batch verification {{SOLANA-ZK}} {{SOLANA-PHANTOM}}. When sampled, the batching randomness **MUST** be drawn only after every NARG string in the batch is received, and **MUST NOT** be reused across batches. The batch verification procedure **MUST NOT** reuse the duplex sponge of a NARG verifier.

The batching randomness elements **MAY** be replaced by the successive powers `1, mu, mu^2, ...` of a single uniformly random scalar `mu`, assigned in row-major order (transcripts, then equations) to the pairs `(i, j)` and computed in the scalar field. In this case, step 7 squeezes 16 bytes instead of `16 * K`, where `K = sum(num_equations(instances[i]) for i in 0, ..., Nt - 1)` is the total number of batched equations, and `mu` is the little-endian integer they encode, read via `LE2IP` ({{bytes-and-integers}}), uniformly distributed in `[0, 2^128)`. In this case, an invalid batch is accepted with probability at most `(K - 1)/2^128`, rather than the `2^-128` achieved by independent sampling.

# Efficiency Considerations {#efficiency-considerations}

Constant arithmetic operations **MAY** be preprocessed, provided the security requirements of {{representation}} hold: evaluation-time precomputation, such as fixed-base multiplication tables, is safe; registering a precomputed linear combination as a new instance element is not.

Multi-scalar multiplication (MSM) algorithms can help evaluate `map(instance, scalars)` ({{map-evaluation}}) and the verification equation. For example, the verifier of {{verifier}} is specified as the equality `map(instance, response) == commitment + challenge * image(instance)`, evaluated as two separate vectors for clarity. Implementations **MAY** instead verify each equation `i` by checking that `commitment[i] + challenge * image(instance)[i] - sum(response[j] * M[i][j] for j in 0, ..., num_scalars(instance) - 1)` is `identity()`, accumulating all terms in a single MSM per equation. Prioritizing field operations, by evaluating expressions over terms and scalar coefficients, will be faster than computing and summing each term individually.

The fastest MSM algorithms, such as Pippenger's bucket method or windowed non-adjacent forms, run in time that depends on the scalars. This is safe, for instance, in the verification equation above, for image computation `image(instance)`, and in `SimulateCommitment` ({{simulator}}): there, every scalar is public.

The efficiency considerations of {{fiat-shamir}} apply here too. Implementations that produce or verify many proofs for the same instance can precompute and reuse the duplex sponge state after the instance is absorbed (steps 1-3 of `DeriveChallenge`, {{challenge-derivation}}) across proofs. `ValidateInstance` ({{instance-validation}}) likewise depends only on the instance, and can be checked once per instance rather than once per proof.

# Security Considerations {#security-considerations}

A Sigma Protocol run interactively provides the guarantees of {{interactive-security-properties}}. In practice, however, Sigma Protocols are almost always deployed non-interactively via the Fiat-Shamir transformation ({{non-interactive}}); {{sigma-ni-security}} describes how these guarantees carry over and what additional care the non-interactive setting requires. In either setting, every guarantee is relative to the instance: {{instance-security}} collects the obligations on how prover and verifier construct it and agree on it.

## Interactive security properties {#interactive-security-properties}

The interactive Sigma Protocol of {{sigma-protocol-group}} has special soundness {{Cramer97}} {{Maurer09}}: two accepting transcripts with the same commitment and distinct challenges yield a witness, so a prover that convinces the verifier must know a witness satisfying the proof statement. Knowledge of a witness is meaningful only when the relation is computationally hard: if witnesses are easy to find, the proof conveys nothing.

The interactive Sigma Protocol of {{sigma-protocol-group}} is honest-verifier zero knowledge: the prover messages do not reveal any information beyond what can be directly inferred from the statement itself, so an honest verifier gains no knowledge about the witness {{Cramer97}}.

Because interactive Sigma Protocols do not have transferable message authenticity, a third party (neither the prover nor the verifier) cannot be convinced that the prover made the proof. The interaction is thus not transferable as evidence to a third party {{JakobssonSI96}} {{Pass03}}.

## Fiat-Shamir transformation {#sigma-ni-security}

The security considerations of {{fiat-shamir}} apply here as well.

Soundness holds only if the encoded instance contains the entire statement being proven ({{serialize-linear-relations}}). Omitting any statement element will compromise knowledge soundness of the resulting non-interactive argument {{CVE-2022-29566}}. For example, consider the verifiable-decryption statement `M + E1 = x * E0`. If encoded with the single image element `F = M + E1`, then `M` and `E1` never enter the instance encoding function, and the resulting NARG string is malleable across statements: it verifies (unchanged) for every pair `(M', E1')` with `M' + E1' = F`. An attacker can thus present a NARG string generated for one plaintext-ciphertext pair as valid for a different one. Another example: encoding `Y = x * (E0 + E1)` with the single element `K = E0 + E1` as base instead of the two terms `x * E0 + x * E1` verifies unchanged for every pair `(E0', E1')` with `E0' + E1' = K`. {{representation}} requires the instance to contain, individually, every group element on which the application's acceptance depends; both examples above violate that requirement while remaining structurally valid ({{instance-validation}}).

The challenge is drawn uniformly at random from the scalar field ({{verifier}}), and the non-interactive instantiations of {{non-interactive}} always derive full-field challenges. Writing `C` for the set the challenge is drawn from, `1/|C| < 2^-250` for the ciphersuites of {{ciphersuites}}. Compositions of Sigma Protocols (out of scope for this document) **MAY** restrict the challenge to a smaller *challenge set* `C`.

Knowledge extraction in the random oracle model requires rewinding the adversary: by the Forking Lemma {{PointchevalS00}}, an adversary that outputs an accepting proof with probability `epsilon` after `q` hash queries yields a witness with probability about `epsilon^2/q`, a quadratic loss. In the algebraic group model (with a random oracle), extraction is instead straight-line (when, for each row of `M`, finding a non-trivial linear relation among its elements is computationally hard) with total extraction error on the order of `q/|C|` (Section 9 of {{Orru24}}).

## NARG string validation {#verifier-input-validation}

The security considerations of {{fiat-shamir}} apply here too.

In particular, for group elements, deserialization **MUST** verify that each point is valid, lies on the curve, and in the prime-order (sub-)group suited for cryptographic use. Uncompressed or hybrid forms of {{SEC1}} **MUST** be rejected {{ChalkiasGN20}}. Skipping the on-curve or subgroup check enables invalid-curve attacks {{JagerSS15}}. Accepting non-canonical field elements will compromise soundness {{CVE-2022-23806}}. The identity element **MUST** be rejected in any deserialized prover messages and instance elements ({{group-abstraction}}).

For scalars, deserialization **MUST** reject any value that is not the canonical representative in `[0, p)` {{CVE-2023-33252}} {{CVE-2025-57801}}.

For compact NARG strings, the verifier **MUST** recompute the challenge and compare it before accepting.

## Instance security {#instance-security}

The prover and verifier construct the instance from values they independently hold and trust, such as the group generator. Often, one party will supply elements or scalars to the other ({{relation-notation}}). These are untrusted input, and **MUST** be checked ({{verifier-input-validation}}). For the verifier, those checks are part of verification. The prover **MUST NOT** produce a proof over an instance without validating well-formedness of all group elements and scalars first.

Some equations pin down no specific scalars. For example, the equation `X = x * G + 5 * y * G` collapses to `X = (x + 5 * y) * G`, and has `p` distinct witnesses `[x, y]`, each trivial to derive from any other. Similarly, the pair of terms `x * H - x * H` cancels for every value of `x`, and constrains nothing. It is the responsibility of the caller to provide non-trivial relations. Some effort in this direction is made in {{instance-validation}} (such as rejection of trivial images), however this will not cover all cases. Applications **MUST** handle degenerate equations before calling the prover and verifier.

## Privacy Considerations {#privacy-considerations}

The NARG string discloses nothing beyond the truth of the statement the instance encodes. However, if the instance is chosen by the adversary the privacy guarantee might be vacuous. Untrusted inputs to the instance need to be validated by the caller. Instance validation ({{instance-validation}}) checks only the structure of the result; a well-formed instance may encode an attacker-chosen linear map.

The entropy source of `ProverCommitment` **MUST** provide different scalars for every different input. A re-used nonce reveals the witness {{PS3}}. (This is the extractor: given different challenges `c1 != c2`, the witness is `(s1 - s2) / (c1 - c2)`, where `s1`, `s2` are the corresponding responses).

The `Verifier` procedure **SHOULD NOT** be used interactively with an untrusted verifier: interactive Sigma Protocols only guarantee zero-knowledge against honest verifiers ({{security-considerations}}).

For verification, `VerifyBatchable` and `VerifyCompact` **SHOULD** be used. The non-interactive Fiat-Shamir transformation yields statistically zero-knowledge arguments of knowledge.

Implementations **SHOULD** securely delete prover state as soon as it is no longer needed (witness and instance), and put in place safeguards to prevent re-use of the prover state. Private witness information should not be part of crash dumps and diagnostic logging.

## Constant-Time Requirements {#constant-time}

The secret values of this document are the witness, the nonces, and the prover state that carries them. The instance and the NARG string are public. All group and field operations whose inputs include secret values **SHOULD** be constant-time in those values, and randomness **SHOULD** be derived with straight-line code, avoiding rejection sampling and other methods whose iteration count depends on the entropy drawn ({{rng-definition}}). Implementations **MAY** skip multiplications by coefficient `1`, or test instance coefficients for zero in variable time.

The dominant secret-dependent operation is the multi-scalar multiplication `map(instance, nonces)` in `ProverCommitment`, whose scalars are secret and whose bases are public instance elements: it **SHOULD** be constant-time with respect to the scalars, a guarantee group libraries typically offer as an interface separate from their variable-time MSM. The variable-time algorithms of {{efficiency-considerations}} leak scalar bits through window sizes and iteration counts, and partial knowledge of the nonces will compromise the witness {{HowgraveGrahamS01}} {{JancarSSS20}}.

In some applications, such as keyed-verification credentials, constant-time implementations are required for the verifier too: there, the instance itself depends on the issuer's secret key. The secret then enters the verification equation through the group elements rather than the scalars, and an MSM that is constant-time only with respect to the scalars is not sufficient: the point arithmetic must not branch on exceptional cases, and the comparison of the two sides of the verification equation must be constant-time.

The constant-time requirements of {{fiat-shamir}} apply here, and extend to the encoding of the instance during challenge derivation. Implementations that expose the simulator ({{core-interface}}) for OR composition should note that which clause is simulated is itself determined by the witness. Real and simulated clauses **SHOULD** follow the same code path, with constant-time selection of the desired transcript.

## Post-Quantum Considerations {#post-quantum-security-considerations}

Sigma Protocols are unconditionally sound and honest-verifier zero-knowledge. What breaks in the post-quantum setting are the statements themselves. They are preimages of linear maps in groups where the discrete logarithm problem is assumed hard, and they are meaningful only while computing discrete logarithms remains infeasible. Since the discrete logarithm problem is efficiently solvable by quantum computers using Shor's algorithm, these proofs **MUST NOT** be relied upon for post-quantum soundness guarantees, and relations of {{linear-map}} **MUST NOT** be used in the presence of quantum adversaries. Implementations requiring post-quantum soundness **SHOULD** transition to alternative proof systems.

For instance, in the statement `C = m * G + r * H, R = r * G`, the witness `m` is only computationally hidden. The NARG string does not leak the witness. Yet, a quantum adversary may recover `r` from `R` and then `m` from `C - r * H`, with two discrete logarithm computations.

As another example, the statement `C = m * G + r * H, D = m * G + s * H`, asserting that two commitments open to the same value, is meaningless to a quantum adversary: the commitments bind `m` only computationally, and an adversary that computes the discrete logarithm of `H` to the base `G` can open either of them to any value of its choice.

The quantum random-oracle model (QROM) {{BDFLSZ11}}, where the adversary may query the hash function in superposition, is not considered in this document. An analysis of the Fiat-Shamir transformation in the QROM can be found in {{DFMS19}}.

Other families of Sigma Protocols, e.g. MPC-in-the-Head {{IKOS07}}, lattice-based {{AttemaCK21}}, or code-based {{Stern93}} approaches, can provide post-quantum guarantees, but are not specified in this document. The generic AND composition with a post-quantum-sound Sigma Protocol does not upgrade security. For example, the binding of a Pedersen commitment fails against a quantum adversary regardless of the strength of the conjunct statement, so the combined statement is meaningful only while **both** underlying problems remain hard. See {{BonehS23}}.

# Ciphersuites {#ciphersuites}

A ciphersuite for the non-interactive Sigma Protocol ({{non-interactive}}) is composed of the following parameters:

- an elliptic curve group, over which the Sigma Protocol of {{sigma-protocol-group}} is run,
- a duplex sponge {{fiat-shamir}}.

The ciphersuites defined by this document, and the identifiers used by the test vectors, are:

| Identifier | Group | Ne | Ns | Duplex Sponge | Security |
|---|---|---|---|---|---|
| `sigma-proofs_Shake128_P256` | P-256 (secp256r1) | 33 | 32 | SHAKE128 | 128-bit pre-quantum |
| `sigma-proofs_Shake128_BLS12381` | BLS12-381 (G1) | 48 | 32 | SHAKE128 | about 120-bit pre-quantum |
{: #tab-ni-ciphersuites title="Non-interactive Sigma Protocol ciphersuites"}

Each row uses the Sigma Protocol of {{sigma-protocol-group}} over the named group. `Ne` and `Ns` are the element and scalar byte lengths of that group. The ciphersuite identifier fixes the group, the codecs, and the hash instantiation, and is included verbatim in the `tag` ({{sigma-proofs-tag}}).

For every ciphersuite in this document, the verifier challenge is derived with `DecodeField(buf, p, 1)` exactly as specified in {{fiat-shamir}}: the scalar field is prime, and its serialization length `Ns = 32` equals the smallest integer such that `256^Ns >= p`, so provers and verifiers squeeze exactly `Ns + 16 = 48` bytes per challenge ({{challenge-derivation}}). Note that `DecodeField` interprets the squeezed bytes as a little-endian integer.

The groups are prime-order elliptic curve groups, defined as follows.

## P-256 (secp256r1)

This ciphersuite uses P-256 {{NIST-SP-800-186}} for the Group.

### Elliptic curve group of P-256 (secp256r1) {{NIST-SP-800-186}}

- `order()`: `115792089210356248762697446949407573529996955224135760342422259061068512044369`.
- `generator()`: the base point `G` specified in {{NIST-SP-800-186}}; its compressed serialization is `036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296`. It is the group element at index `0` of every instance ({{representation}}).
- `serialize([A])`: the compressed Elliptic-Curve-Point-to-Octet-String conversion of {{SEC1}} (`Ne = 33`).
- `deserialize(buf)`: inverts the conversion above; only the compressed form is a valid encoding (each `Ne`-byte slice begins with `0x02` or `0x03`). It **MUST** perform partial public-key validation as defined in Section 5.6.2.3.4 of {{!NIST-SP-800-56A=DOI.10.6028/NIST.SP.800-56Ar3}} and **MUST** fail otherwise.

### Scalar Field of P-256

- `serialize(s)`: the big-endian fixed-length integer encoding `I2OSP` ({{bytes-and-integers}}) (`Ns = 32`).
- `deserialize(buf)`: `OS2IP` ({{bytes-and-integers}}); it **MUST** fail unless the result is in `[0, order())`.

## BLS12-381 (G1)

This ciphersuite uses the prime-order subgroup G1 of the BLS12-381 elliptic curve {{!RFC9380}} for the Group.

### Elliptic curve group of BLS12-381 (G1) {{!RFC9380}}

- `order()`: `52435875175126190479447740508185965837690552500527637822603658699938581184513`.
- `generator()`: the generator of G1 specified in Section 4.2.1 of {{!PAIRING=I-D.irtf-cfrg-pairing-friendly-curves}}; its compressed serialization is `97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb`. It is the group element at index `0` of every instance ({{representation}}).
- `serialize([A])`: the compressed G1 serialization of Appendix C of {{PAIRING}} (`Ne = 48`). The point-at-infinity encoding of that format (`I_bit` set) is neither produced ({{group-abstraction}}) nor accepted.
- `deserialize(buf)`: inverts the serialization above. It **MUST** perform full point validation and **MUST** reject the point at infinity.

### Scalar Field of BLS12-381

- `serialize(s)`: the big-endian fixed-length integer encoding `I2OSP` ({{bytes-and-integers}}) (`Ns = 32`).
- `deserialize(buf)`: `OS2IP` ({{bytes-and-integers}}); it **MUST** fail unless the result is in `[0, order())`.

# IANA Considerations

This document has no IANA actions. The ciphersuite identifiers of {{ciphersuites}} are defined by this document and enter the protocol only as components of the `tag` ({{sigma-proofs-tag}}); no registry is established.

# Acknowledgments
{:numbered="false"}

The authors thank Jan Bobolz, Vishruti Ganesh, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang for reviewing a previous edition of this specification.

--- back

# Test Vectors

This appendix contains test vectors for the non-interactive Sigma Protocols specified in this document, one section per ciphersuite ({{tv-p256}}, {{tv-bls12381}}). {{seeded-prng}} pins the randomness used, so that the vectors are reproducible from this document alone.

The vectors follow the format specified in the Test Vectors appendix of {{fiat-shamir}}: a block of `Key = Value` lines, no key repeated, values inline or indented under their key, and sequences written one `- ` item per line. Every vector carries `Id`, its stable name, and `Function`, which is `SigmaProof` throughout this document. Where {{fiat-shamir}} identifies the hash suite with `Hash`, these vectors carry `Ciphersuite`, which fixes the group and the hash together ({{ciphersuites}}). Every vector also carries `Expected`, which is `accept` or `reject`: unlike the functional vectors of {{fiat-shamir}}, each vector here is a verifier decision.

The remaining keys are those of the protocol. `Relation` names the relation of {{relation-notation}} and `Flavor` is `batchable` or `compact`; one vector covers one flavor, so `Tag`, `SessionId` and `NargString` are unambiguous. The `Witness` field, which never appears on the wire, is encoded as the concatenation of `Scalar.serialize` of the witness scalars, in the order given by each relation.

## Seeded PRNG {#seeded-prng}

The randomness for these vectors is drawn from a seeded PRNG, instantiated via a duplex sponge {{fiat-shamir}} initialized with the session identifier `DeriveSessionID(prng_tag)`.

The US-ASCII tag:

~~~
TestDRNG-SIGMA-PROOFS-{Ciphersuite}-{Relation}
~~~

Yields the scalars that build the instance and witness, in the order given by each relation.

The tag:

~~~
TestDRNG-SIGMA-PROOFS-DSFS-{Ciphersuite}-{Relation}
~~~

Provides the randomness for the prover in the batchable NARG string. That is, it is used to sample `num_scalars(instance)` commitment nonces of the batchable proof.

Finally, the tag:

~~~
TestDRNG-SIGMA-PROOFS-CMPT-{Ciphersuite}-{Relation}
~~~

Provides the randomness for the prover in the compact NARG strings.

Applications **MUST NOT** use this deterministic pseudorandom generator. The prover's randomness **MUST** be seeded from operating-system entropy ({{scalar}}).

## sigma-proofs_Shake128_P256 {#tv-p256}

This section contains vectors for the ciphersuite identified as `sigma-proofs_Shake128_P256`.

### Valid proofs {#tv-p256-valid}

{::include ./poc/vectors/sigma-proofs_Shake128_P256.txt}

## sigma-proofs_Shake128_BLS12381 {#tv-bls12381}

This section contains vectors for the ciphersuite identified as `sigma-proofs_Shake128_BLS12381`.

### Valid proofs {#tv-bls12381-valid}

{::include ./poc/vectors/sigma-proofs_Shake128_BLS12381.txt}

