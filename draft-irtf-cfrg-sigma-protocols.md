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

Sigma Protocols are unconditionally sound and honest-verifier zero-knowledge. What breaks in the post-quantum setting are the statements themselves. They are preimages of linear maps in groups where the discrete logarithm problem is assumed hard, and they are meaningful only while computing discrete logarithms remains infeasible. Therefore, relations of {{linear-map}} **SHOULD NOT** be used in the presence of quantum adversaries.

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

The authors thank Jan Bobolz, Vishruti Ganesh, Stephan Krenn, Mary Maller, Ivan Visconti, and Yuwen Zhang for reviewing a previous edition of this specification.

The authors thank Giap Vu and David Wong (zkSecurity) for their help and contributions.

--- back

# Test Vectors

This appendix contains test vectors for the non-interactive Sigma Protocols specified in this document, one section per ciphersuite ({{tv-p256}}, {{tv-bls12381}}). Each ciphersuite section has two subsections: valid proofs, and adversarial vectors. {{seeded-prng}} pins the randomness used, so that the vectors are reproducible from this document alone.

The vectors follow the format specified in the Test Vectors appendix of {{fiat-shamir}}: a block of `Key = Value` lines, no key repeated, values inline or indented under their key, and sequences written one `- ` item per line. Every vector carries `Id`, its stable name, and `Function`, which is `SigmaProof` throughout this document. Where {{fiat-shamir}} identifies the hash suite with `Hash`, these vectors carry `Ciphersuite`, which fixes the group and the hash together ({{ciphersuites}}). Every vector also carries `Expected`, which is `accept` or `reject`: unlike the functional vectors of {{fiat-shamir}}, each vector here is a verifier decision.

The remaining keys are those of the protocol. `Relation` names the relation of {{relation-notation}} and `Flavor` is `batchable` or `compact`; one vector covers one flavor, so `Tag`, `SessionId` and `NargString` are unambiguous. The `Witness` field, which never appears on the wire, is encoded as the concatenation of `Scalar.serialize` of the witness scalars, in the order given by each relation.

Every adversarial vector carries `BaseId`, naming the valid vector it is derived from: it re-verifies that transcript under a different tag, statement, or encoding, and a conformant verifier **MUST** reject it while accepting its baseline. Testing only that the adversarial vectors are rejected is therefore not sufficient; an implementation that rejects every input passes no accept/reject pair. The prose accompanying each vector states which check fails; where the rejection step depends on the implementation's check order, any of the stated rejection points is conformant.

Batch verification ({{batch-verification}}) can be tested on any subset of these vectors: a batch of valid batchable proofs **MUST** verify, and a batch containing any invalid batchable proof **MUST** be rejected.

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

Knowledge of a discrete logarithm, `X = x * G`: the Schnorr relation
given as example in {{linear-map}}.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = discrete_logarithm
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
SessionId =
  72eeaaf4b2af14a6020b59d9b0501f7263bdbb16a403d93d7af1635546dcc503
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
Witness =
  9b7b9af133b35ea96e662c4662956909fe465084fe929506980e025022d750be
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = accept
~~~

Knowledge of a discrete logarithm, `X = x * G`: the Schnorr relation
given as example in {{linear-map}}.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = discrete_logarithm
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
SessionId =
  2934314b80877ce535bf39bb9074bc541c98e171b563b74dff82a63a921c6858
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
Witness =
  9b7b9af133b35ea96e662c4662956909fe465084fe929506980e025022d750be
NargString =
  3f29987a13e3ea094f2f7ee8f1ccc37ef3239bd303535a9959ca3aacca1f216c
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c28
Expected = accept
~~~

Discrete-logarithm equality, `X = x * G` and `Y = x * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/p256/dleq/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = dleq
Flavor = batchable
Tag = dleq-DSFS-with-sigma-proofs_Shake128_P256
SessionId =
  322adf7cff2aca1c08e9c7053b1d1d75016d22f1903f1b109f0267034645478c
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000103a0d262ccb556df026581adf2ea6ea52cf69ca3
  9f0644b89e43471cb40d921b0503dc308f6d1c515121d2334015b95254336a60
  8a78031809b31099aadadcb566350241d6b25cf581b93fb4f769f1d88aa571df
  e9d3f2e451b2f779e8da710ae0015b
Witness =
  b4fbb257ea2f224915a82a630ff348069e2b25bafdcf6255322c9fa0dfb6340a
NargString =
  0203ed31e0d73b821eba236b903f83ddd6e60e59a77249462be32fc43ab4d5dd
  7e038ad4a96b49f6e29ea0afcb6a329632b5e3cdea70137e965515219da19be4
  497655ca705567b987c6f9c5dd5bd866d069dfdcbc415b2036dab9ec63a821d4
  c045
Expected = accept
~~~

Discrete-logarithm equality, `X = x * G` and `Y = x * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/p256/dleq/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = dleq
Flavor = compact
Tag = dleq-CMPT-with-sigma-proofs_Shake128_P256
SessionId =
  6f3abd4c1daaa824fce769441e9f5c724021ee723174190745be999dbfeca92f
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000103a0d262ccb556df026581adf2ea6ea52cf69ca3
  9f0644b89e43471cb40d921b0503dc308f6d1c515121d2334015b95254336a60
  8a78031809b31099aadadcb566350241d6b25cf581b93fb4f769f1d88aa571df
  e9d3f2e451b2f779e8da710ae0015b
Witness =
  b4fbb257ea2f224915a82a630ff348069e2b25bafdcf6255322c9fa0dfb6340a
NargString =
  5351e8969b72d4bdc0f2688ff68c69bb36154dc9074e534d954c8899b6c813b5
  284cb4905860f4b1db7edc4473f5ee2b4ab178c5c2a8cbe57056ac330fc71d37
Expected = accept
~~~

Knowledge of the opening of a Pedersen commitment, `C = x * G + r * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/p256/pedersen_commitment/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = pedersen_commitment
Flavor = batchable
Tag = pedersen_commitment-DSFS-with-sigma-proofs_Shake128_P256
SessionId =
  6d12e90fc2e3d74d9496ff609cd49f1013c6319da01b7aba5383f6b46789985e
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  0206c16fcf4c4017adb8908fb2ec0aba8ea9edd683ae38eac52d59f040956be8
  f803e8372937cb2d0d9d0d48263ecd0a1d4b96207bceb3806739757fcad774f9
  2642
Witness =
  25c9fd63403d0da31081857537ade64b637c80ed2338639148a9938b3562ea06
  afc354c8985ee3cb61b83af2f7a5bb2abeb7d510db5168b6ede21b4910594a2b
NargString =
  03491976f248dcde9ecf9c4536754cb2e81b61be73999efd8e82d061cabf3a49
  439eaa3fd376be7bb7a599b5bd03397d967174f61b27c514e4541a05cfaea37b
  2d05c8c392bcc53462ce9b997cec950c02f6d023537137b3586e2ec277a3c328
  80
Expected = accept
~~~

Knowledge of the opening of a Pedersen commitment, `C = x * G + r * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/p256/pedersen_commitment/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = pedersen_commitment
Flavor = compact
Tag = pedersen_commitment-CMPT-with-sigma-proofs_Shake128_P256
SessionId =
  4d241bd0f43a3a162d0671aa263a8285f51d22d848d08b0f9e2e747f20b19d89
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  0206c16fcf4c4017adb8908fb2ec0aba8ea9edd683ae38eac52d59f040956be8
  f803e8372937cb2d0d9d0d48263ecd0a1d4b96207bceb3806739757fcad774f9
  2642
Witness =
  25c9fd63403d0da31081857537ade64b637c80ed2338639148a9938b3562ea06
  afc354c8985ee3cb61b83af2f7a5bb2abeb7d510db5168b6ede21b4910594a2b
NargString =
  9e11b127fa8984da359687ba95ce5b1bb4e82ea252e0df9562d62e8c60acc013
  ecfcd356f2476e287e3f043f7cf11d1fb3a3dce9a190ce605819d1a05bbd23c5
  5630f834648c294b6f39d23e9f0f507119ecdf8691ee3ac5dcfd4b669bbdf3f7
Expected = accept
~~~

Two Pedersen-form equations sharing both witness scalars, `X = x0 * G0 +
x1 * G1` and `Y = x0 * G2 + x1 * G3` ({{relation-notation}}).

~~~
Id = sigma-protocols/p256/pedersen_commitment_dleq/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = pedersen_commitment_dleq
Flavor = batchable
Tag = pedersen_commitment_dleq-DSFS-with-sigma-proofs_Shake128_P256
SessionId =
  688476139ac68ba996cc86d0331830b18fe2b5c8ab87038d4cf622d7c897c1cf
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000006000000000000000000000000000000000000000000000000000000
  0000000000000001020000000000000004000000000000000000000000000000
  0000000000000000000000000000000000000001010000000500000000000000
  0000000000000000000000000000000000000000000000000000000102120b29
  125003d5d494503fd47fa4057e761c1cb1632e8965233b8f8dfadd9d2503dc92
  fe87397abd7e0beded9099032d680f46280672afeb1682e46b45e046d5b302a2
  8a33dc8792cb198a9d7942eb1a34909373a5f382e8e68983a54f6fba75875502
  76d70754e0a8f249a41695d5db16f8765d27a46a19dfcd8c1fdc7ac5896f46f5
  03ccdb0adda1a852cac38054215e298b8d4b19823e3a66b9a80e44d063935de4
  09028ef1cfa2468871b4b5116a6709c8df1f722180fc4fc1ad6e5db991660be7
  8915
Witness =
  1242ef15dea6fafe29b8d3e9ba859d0489744d46cc8b52563c445dcd0ee62854
  b80c18e412222e458decdfbecd398b8036df12500008fac1a8f16eecb517bf54
NargString =
  03e2aa1a7e5b705690b8fc4859dc9353a8ca262c6f11016306a9a84664e55f48
  fc0268b6aeff56dbd1517e0721f62a59fe09fa2f523972ad06f3a6ccd75d82f8
  6e95febeaa429522ab5e7bc356178a08cf50442e991f4a70db479f650903104a
  92fa26e56545c5957e6e0ec86adbe6ca1675d8a713f39abeef120c72edeae7bf
  a9ad
Expected = accept
~~~

Two Pedersen-form equations sharing both witness scalars, `X = x0 * G0 +
x1 * G1` and `Y = x0 * G2 + x1 * G3` ({{relation-notation}}).

~~~
Id = sigma-protocols/p256/pedersen_commitment_dleq/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = pedersen_commitment_dleq
Flavor = compact
Tag = pedersen_commitment_dleq-CMPT-with-sigma-proofs_Shake128_P256
SessionId =
  ef423a52be5ad7d7d8e499aa870634f5ac3fc424b89fdc96aa72d8c5361e79d1
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000006000000000000000000000000000000000000000000000000000000
  0000000000000001020000000000000004000000000000000000000000000000
  0000000000000000000000000000000000000001010000000500000000000000
  0000000000000000000000000000000000000000000000000000000102120b29
  125003d5d494503fd47fa4057e761c1cb1632e8965233b8f8dfadd9d2503dc92
  fe87397abd7e0beded9099032d680f46280672afeb1682e46b45e046d5b302a2
  8a33dc8792cb198a9d7942eb1a34909373a5f382e8e68983a54f6fba75875502
  76d70754e0a8f249a41695d5db16f8765d27a46a19dfcd8c1fdc7ac5896f46f5
  03ccdb0adda1a852cac38054215e298b8d4b19823e3a66b9a80e44d063935de4
  09028ef1cfa2468871b4b5116a6709c8df1f722180fc4fc1ad6e5db991660be7
  8915
Witness =
  1242ef15dea6fafe29b8d3e9ba859d0489744d46cc8b52563c445dcd0ee62854
  b80c18e412222e458decdfbecd398b8036df12500008fac1a8f16eecb517bf54
NargString =
  6cb7a0e88a0aa524c402339e9891851ed483bbe2f2ac4c2cea87999d33bef283
  3c4bfd5c2a8de1abcd9a7134fd13391680dc7c9321b7e517b7bacf3755a6b177
  48c11272f913bb15744d25f97e1f21885a948c952567463f289d6e382866314b
Expected = accept
~~~

The blind commitment computation of {{BBSBlind}}, `C = blind * Q2 +
msg_1 * J1 + msg_2 * J2 + msg_3 * J3`.

~~~
Id = sigma-protocols/p256/bbs_blind_commitment_computation/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = bbs_blind_commitment_computation
Flavor = batchable
Tag =
  bbs_blind_commitment_computation-DSFS-with-sigma-proofs_Shake128_P256
SessionId =
  72af721d175eb7b0c975ab01d37b8770077ce6bf9e81779188f59cb51a31bcbc
Instance =
  0100000001000000050000000000000000000000000000000000000000000000
  0000000000000000000000010400000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0200000003000000000000000000000000000000000000000000000000000000
  0000000000000001030000000400000000000000000000000000000000000000
  000000000000000000000000000000010202eaa274def05ab048396033e7f2d7
  638851a60131af9759a016e3eff592941c02b4f47e54f51d447c160ecf71c456
  a8e0d513d593c07bfaac23a373a4b51ca868034f75a59df8f7f10f97fcd9bdaf
  24a3b0c5ea403167929f4fcab9d4e3f483747c02f86566f754588d585264dac4
  f3650cf8ff53ec716ed21dfd07213058d8fc78020390ef88459ded35acdbe56d
  986dad595f45a8b6f190bbce3ddb5908308f6115b5
Witness =
  af35a44a86ed7403467f49203e8c79501e70f039b113cd1753993f84977d95ac
  13cadbba0e76ff85edd77b7340ba0396e45671dff7229dc424faa180dba435ba
  334d189229fa64202a6182e85d80497f21f250fa467ded4cf8152154af76c241
  0a3c8706d1a6d4623d89b5b9213c59e1163975d6ef7abc8311682ddfe6d7390b
NargString =
  03206f70cc509ce8660cca8caa1f3b403f143c006705fe72daf4cb083be82495
  8499b37f26362a50c596ec4885b97e8deeae5b3da96329e3e715ceee04b9f32b
  026945804d8d0f3594587be911a9809a61bb200b23b30cc94f246f8250be4882
  df8128a391c9deefda6d96daa4c5977f902d137a0b4130e7e2fe3f14f3e0106c
  3052e00a1c9b9607a5d7a502ac0d419fc87b0636289fdabd05824091e07140e0
  1d
Expected = accept
~~~

The blind commitment computation of {{BBSBlind}}, `C = blind * Q2 +
msg_1 * J1 + msg_2 * J2 + msg_3 * J3`.

~~~
Id = sigma-protocols/p256/bbs_blind_commitment_computation/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = bbs_blind_commitment_computation
Flavor = compact
Tag =
  bbs_blind_commitment_computation-CMPT-with-sigma-proofs_Shake128_P256
SessionId =
  079c5d8e65618f746d72d2881bbb630155565d95375eb27619581b1e937a697d
Instance =
  0100000001000000050000000000000000000000000000000000000000000000
  0000000000000000000000010400000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0200000003000000000000000000000000000000000000000000000000000000
  0000000000000001030000000400000000000000000000000000000000000000
  000000000000000000000000000000010202eaa274def05ab048396033e7f2d7
  638851a60131af9759a016e3eff592941c02b4f47e54f51d447c160ecf71c456
  a8e0d513d593c07bfaac23a373a4b51ca868034f75a59df8f7f10f97fcd9bdaf
  24a3b0c5ea403167929f4fcab9d4e3f483747c02f86566f754588d585264dac4
  f3650cf8ff53ec716ed21dfd07213058d8fc78020390ef88459ded35acdbe56d
  986dad595f45a8b6f190bbce3ddb5908308f6115b5
Witness =
  af35a44a86ed7403467f49203e8c79501e70f039b113cd1753993f84977d95ac
  13cadbba0e76ff85edd77b7340ba0396e45671dff7229dc424faa180dba435ba
  334d189229fa64202a6182e85d80497f21f250fa467ded4cf8152154af76c241
  0a3c8706d1a6d4623d89b5b9213c59e1163975d6ef7abc8311682ddfe6d7390b
NargString =
  431c50915e63bb13e4c89556d736cea30703c6235711c62aa3a3fde58e250526
  93c3b5716f935f1052bb9fb97dd5635a7f14b3254ccdeeffc8fad01f2f4fed36
  db0324e47ffdf5218646411ca9ccbcdde13001686a63997ea358f88c956524db
  a190b324f47d021fc6b4373414e99aa68e673eb517e04fb169923418dec5d44b
  fb208ece8117954283043ab111babce94b9d5716ef75f696f8c4492e2def66e7
Expected = accept
~~~

Correct ElGamal decryption, `X = x * G` and `M = x * E0 - E1`
({{relation-notation}}).

~~~
Id = sigma-protocols/p256/elgamal_decryption/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = elgamal_decryption
Flavor = batchable
Tag = elgamal_decryption-DSFS-with-sigma-proofs_Shake128_P256
SessionId =
  b9125fe73ce90119db10799a9669a1ee47f6bc7b1dc7e0e8ab00296df6159657
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000004000000
  0000000000000000000000000000000000000000000000000000000000000001
  0300000000000000000000000000000000000000000000000000000000000000
  0000000101000000000000000200000000000000000000000000000000000000
  000000000000000000000000000000010372462b86837aaadb6ec2348fc4a602
  9f7ae77e9aea238017bebbbe469dd299be039f3ab1733887055e7f18884bc8d6
  66d2461925888f366009aeefcaaffd94900e02597c2dd8b7bd7c2c9864efa356
  ed285103582e75c001fbd8400aaf618790fa93036d21e24e585051080212d7ee
  b3884dcb28017e91d50967bcd432bbd9a8cf4986
Witness =
  14375a0f9d92dd6fd4b67cb11de6f81b54c101f6e846cd8817dce6db7b30fb4c
NargString =
  02f2de68f98653dc53ef1832f363b62fd68837f7b5d17080e068e4450ef35bc5
  2f036ae8948f8836f4c38bf16298de1179a4641f6a11e2222457160ff4f8963b
  72868c2b3964e4fc66374f635bb8a497d34592420c5b2ebd653ed30f80fe56bb
  3776
Expected = accept
~~~

Correct ElGamal decryption, `X = x * G` and `M = x * E0 - E1`
({{relation-notation}}).

~~~
Id = sigma-protocols/p256/elgamal_decryption/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = elgamal_decryption
Flavor = compact
Tag = elgamal_decryption-CMPT-with-sigma-proofs_Shake128_P256
SessionId =
  cf4b3a76432ab31da160eb35049dde5afea29635eaadc9a79c59a04771b0908f
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000004000000
  0000000000000000000000000000000000000000000000000000000000000001
  0300000000000000000000000000000000000000000000000000000000000000
  0000000101000000000000000200000000000000000000000000000000000000
  000000000000000000000000000000010372462b86837aaadb6ec2348fc4a602
  9f7ae77e9aea238017bebbbe469dd299be039f3ab1733887055e7f18884bc8d6
  66d2461925888f366009aeefcaaffd94900e02597c2dd8b7bd7c2c9864efa356
  ed285103582e75c001fbd8400aaf618790fa93036d21e24e585051080212d7ee
  b3884dcb28017e91d50967bcd432bbd9a8cf4986
Witness =
  14375a0f9d92dd6fd4b67cb11de6f81b54c101f6e846cd8817dce6db7b30fb4c
NargString =
  827f88105d6a14c364c070fcdc5a53f0208b42ec6d8a6e397eea1d24382676bb
  7af67b61c733281b12822892a29da92326df8fd6921802462909ace20d42e632
Expected = accept
~~~

The `ChaumPedersen` relation of {{relation-notation}} again, with `Y = x
* H` derived by the prover from its witness rather than received: the
compiled instance matches `dleq`, and only the tag (hence the proof
bytes) differs.

~~~
Id = sigma-protocols/p256/dleq_derived_element/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = dleq_derived_element
Flavor = batchable
Tag = dleq_derived_element-DSFS-with-sigma-proofs_Shake128_P256
SessionId =
  c14c1f05e26976121b0842e9a64270893d4d7ca1b24e09c7d6b4147e74e9af0d
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000103f56baee56b8f80b4bae59bb48c615a7b34ab47
  c8f0de3fe6bc23706511a90a0d037100a881faf4f73982c7e3113810c6e56a69
  c42c98562a121c15ad1951c8eafa031def6155fd67b1be8e4fd49c7227e576c1
  abe0886e5d6a928a015f5d8f08e436
Witness =
  45d78f1fff7555932001aa84fb525f9caa8a0949bb8406aaacdd9ce9f06dfdea
NargString =
  029e903a7f21e67b403658a8b55c2097d0b5ec918a10b4ac965dbbddca20d216
  d50374b96946905242651598a20721cce60aaa1a1d84f4f4644ad1abb2ea61eb
  435f785e12da6947bdcaa0b49176170df8a65f54f828e03412df5b31744433be
  5e7c
Expected = accept
~~~

The `ChaumPedersen` relation of {{relation-notation}} again, with `Y = x
* H` derived by the prover from its witness rather than received: the
compiled instance matches `dleq`, and only the tag (hence the proof
bytes) differs.

~~~
Id = sigma-protocols/p256/dleq_derived_element/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Relation = dleq_derived_element
Flavor = compact
Tag = dleq_derived_element-CMPT-with-sigma-proofs_Shake128_P256
SessionId =
  5ed1c6effe868eaf259136b7702a342c2bd7aee2028e29dcee0364f8cbe88e2d
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000103f56baee56b8f80b4bae59bb48c615a7b34ab47
  c8f0de3fe6bc23706511a90a0d037100a881faf4f73982c7e3113810c6e56a69
  c42c98562a121c15ad1951c8eafa031def6155fd67b1be8e4fd49c7227e576c1
  abe0886e5d6a928a015f5d8f08e436
Witness =
  45d78f1fff7555932001aa84fb525f9caa8a0949bb8406aaacdd9ce9f06dfdea
NargString =
  e8c65a06a08e5573f7b29c56246dc4efe5bd9d834ed12aa32e62a427875b852c
  ffb5e51026648606a6f78a935c334c86c1a930c515e852db06e010f7418e8871
Expected = accept
~~~


### Adversarial vectors {#tv-p256-invalid}

Deserialization fails on the SEC1 uncompressed prefix 0x04.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/A1
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  047e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Deserialization fails on the SEC1 hybrid prefix 0x06.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/A2
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  067e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Deserialization fails on the SEC1 hybrid prefix 0x07.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/A2b
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  077e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Deserialization fails if the x-coordinate is lifted by the field
characteristic (x = 5, encoded as x + p): the coordinate is
non-canonical.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/A3
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  02ffffffff000000010000000000000000000000010000000000000000000000
  049dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Deserialization fails on 0x00 padded to Ne bytes.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/A4
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  0000000000000000000000000000000000000000000000000000000000000000
  009dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Deserialization fails on x = 1, which has no square root for y.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/A6
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  0200000000000000000000000000000000000000000000000000000000000000
  019dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Deserialization fails if `response[0]` is set to order + 1.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/B1
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  19ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325
  52
Expected = reject
~~~

Deserialization fails if `challenge` is set to order + 1.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/B2
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c28
Expected = reject
~~~

Verification fails if one trailing 0x00 byte is appended to a valid
proof.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/C1
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b00
Expected = reject
~~~

Verification fails if a valid proof is truncated by one byte.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/C2
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
Expected = reject
~~~

Verification fails if one trailing 0x00 byte is appended to a valid
proof.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/C1
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  3f29987a13e3ea094f2f7ee8f1ccc37ef3239bd303535a9959ca3aacca1f216c
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c28
  00
Expected = reject
~~~

Verification fails if a valid proof is truncated by one byte.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/C2
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  3f29987a13e3ea094f2f7ee8f1ccc37ef3239bd303535a9959ca3aacca1f216c
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c
Expected = reject
~~~

Verification fails on the all-zero compact proof: challenge and response
are zero.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/D1
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
Expected = reject
~~~

Instance validation fails if scalar index 1 appears in no equation
(check 6); the proof satisfies the verification equations, so rejection
must come from instance validation.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/E1
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = instance_unconstrained_scalar-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  031ac02e1fd7d885b1e5eb1811abd9c4d03eee8eada37d9c1a860ca3c649b8e2
  a302ccab62b6a53592a5bc088188532faa9eee974c21150d6276da6c6d924b6e
  2dc1
NargString =
  033d85fedbddfd463f0392eeea57107720404fbce572e420fe54fba77bad18b4
  b94358208ea29237036630d19ee48191bf7626c37730249a3951083345b19ed4
  e6c2e07d1d92976e9398c5cc356ce644df48ecb1362ccf31d97166a3e40048c7
  76e4555c95e4b42275076c8523f4ee48be8835478f8b0262fce9279e2bcb8c7a
  94
Expected = reject
~~~

Instance validation fails on the same instance, here with the
unconstrained `response[1]` perturbed.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/E1b
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = instance_unconstrained_scalar-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  031ac02e1fd7d885b1e5eb1811abd9c4d03eee8eada37d9c1a860ca3c649b8e2
  a302ccab62b6a53592a5bc088188532faa9eee974c21150d6276da6c6d924b6e
  2dc1
NargString =
  033d85fedbddfd463f0392eeea57107720404fbce572e420fe54fba77bad18b4
  b94358208ea29237036630d19ee48191bf7626c37730249a3951083345b19ed4
  e6c2e07d1d92976e9398c5cc356ce644df48ecb1362ccf31d97166a3e40048c7
  77e4555c95e4b42275076c8523f4ee48be8835478f8b0262fce9279e2bcb8c7a
  94
Expected = reject
~~~

Instance validation fails if the image terms X + (-X) sum to the
identity (check 9).

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/E2
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = instance_trivial_equation-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000002000000010000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000101000000000000000000000000000000
  00000000000000000000000000000000000000000000000000000001031db20b
  c00c5012329627c85174b00ade13788636ce3ce3842e0fc1dde4179ca5021db2
  0bc00c5012329627c85174b00ade13788636ce3ce3842e0fc1dde4179ca5
NargString =
  022fb88456a6a7f8d974b129ec99f3745ffd9e3dcbae9771815571d4c4087a12
  088aa155e5f5e22708f62eec3e7425026489340ed065e835229f1a5010637696
  d9
Expected = reject
~~~

Instance validation fails if a statement element is the identity (check
8), here at index 1, encoded as stand-in bytes (P-256 has no identity
encoding); parsers may instead reject at group deserialization.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/E3
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = instance_identity_element-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  0000000000000000000000000000000000000000000000000000000000000000
  0003871d14718441e23004e5c432427775bde2e9244f75550e839d210556bde1
  cad0
NargString =
  02b9d1353c5f3bf39418f2ea4bb8f8ba63cef1e8cc7eb14f51242c31ec17765a
  5fa919d7f15f2e14c494b5e199eaf0b70735118e7ae2b7a278edee4b27a0135f
  fb2cb0ed2a76d9c583db0758976f24bc3eb65764691a2a51779f84acca97e161
  bc
Expected = reject
~~~

Instance validation fails if a term references element index 2 while a
single element follows; parsers may instead reject on length.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/E4
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = instance_index_out_of_bounds-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000020000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

A valid NARG string verifies under the tag it was produced for.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/F1
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = accept
~~~

Verification fails under a different tag.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/F1b
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag =
  discrete_logarithm/wrong-session-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

A valid NARG string verifies under the tag it was produced for.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/F1
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  3f29987a13e3ea094f2f7ee8f1ccc37ef3239bd303535a9959ca3aacca1f216c
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c28
Expected = accept
~~~

Verification fails under a different tag.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/F1b
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag =
  discrete_logarithm/wrong-session-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  3f29987a13e3ea094f2f7ee8f1ccc37ef3239bd303535a9959ca3aacca1f216c
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c28
Expected = reject
~~~

A valid NARG string verifies against the statement it was produced for.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/F2
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = dleq-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000103a0d262ccb556df026581adf2ea6ea52cf69ca3
  9f0644b89e43471cb40d921b0503dc308f6d1c515121d2334015b95254336a60
  8a78031809b31099aadadcb566350241d6b25cf581b93fb4f769f1d88aa571df
  e9d3f2e451b2f779e8da710ae0015b
NargString =
  0203ed31e0d73b821eba236b903f83ddd6e60e59a77249462be32fc43ab4d5dd
  7e038ad4a96b49f6e29ea0afcb6a329632b5e3cdea70137e965515219da19be4
  497655ca705567b987c6f9c5dd5bd866d069dfdcbc415b2036dab9ec63a821d4
  c045
Expected = accept
~~~

Verification fails if the statement's two equations are swapped.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/F2b
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = dleq-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000020000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000000000000000000000000000000000000000000000000000
  00000000000000000000000103a0d262ccb556df026581adf2ea6ea52cf69ca3
  9f0644b89e43471cb40d921b0503dc308f6d1c515121d2334015b95254336a60
  8a78031809b31099aadadcb566350241d6b25cf581b93fb4f769f1d88aa571df
  e9d3f2e451b2f779e8da710ae0015b
NargString =
  0203ed31e0d73b821eba236b903f83ddd6e60e59a77249462be32fc43ab4d5dd
  7e038ad4a96b49f6e29ea0afcb6a329632b5e3cdea70137e965515219da19be4
  497655ca705567b987c6f9c5dd5bd866d069dfdcbc415b2036dab9ec63a821d4
  c045
Expected = reject
~~~

A valid NARG string verifies against the statement it was produced for.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/F2
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = dleq-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000103a0d262ccb556df026581adf2ea6ea52cf69ca3
  9f0644b89e43471cb40d921b0503dc308f6d1c515121d2334015b95254336a60
  8a78031809b31099aadadcb566350241d6b25cf581b93fb4f769f1d88aa571df
  e9d3f2e451b2f779e8da710ae0015b
NargString =
  5351e8969b72d4bdc0f2688ff68c69bb36154dc9074e534d954c8899b6c813b5
  284cb4905860f4b1db7edc4473f5ee2b4ab178c5c2a8cbe57056ac330fc71d37
Expected = accept
~~~

Verification fails if the statement's two equations are swapped.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/F2b
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = dleq-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000020000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000000000000000000000000000000000000000000000000000
  00000000000000000000000103a0d262ccb556df026581adf2ea6ea52cf69ca3
  9f0644b89e43471cb40d921b0503dc308f6d1c515121d2334015b95254336a60
  8a78031809b31099aadadcb566350241d6b25cf581b93fb4f769f1d88aa571df
  e9d3f2e451b2f779e8da710ae0015b
NargString =
  5351e8969b72d4bdc0f2688ff68c69bb36154dc9074e534d954c8899b6c813b5
  284cb4905860f4b1db7edc4473f5ee2b4ab178c5c2a8cbe57056ac330fc71d37
Expected = reject
~~~

Verification fails if a statement element is changed after proving.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/F3
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001039db6eb62700691
  c3580fbda8fc7ee33f6cfdd5b43203507c1b0533b15d0d1b7e
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Verification fails if a statement element is changed after proving.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/F3
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001039db6eb62700691
  c3580fbda8fc7ee33f6cfdd5b43203507c1b0533b15d0d1b7e
NargString =
  3f29987a13e3ea094f2f7ee8f1ccc37ef3239bd303535a9959ca3aacca1f216c
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c28
Expected = reject
~~~

Verification fails if the batchable proof's transcript is re-encoded as
a compact NARG string.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/F4
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  e44d6cb80e7b099d06525dbb3567fc05ebfc9b7d3da0624e5cf643163d7a51e3
  9dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e1713b
Expected = reject
~~~

Verification fails if the compact proof's transcript is re-encoded as a
batchable NARG string: the challenge derived under the batchable tag
differs.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/F4b
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  0221f8d84da0727022bf043b23de7c67590535109a3a6c24f4fba9c8732190c6
  eacfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c
  28
Expected = reject
~~~

Verification fails if `response[0]` is increased by 1.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/H1
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  037e00143a98c515388e00397c050c46729f010e30752f00172c2e9444cd323e
  199dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3c
Expected = reject
~~~

Verification fails if `commitment[0]` is replaced by a different valid
group element.

~~~
Id = sigma-protocols/p256/discrete_logarithm/batchable/H2
BaseId = sigma-protocols/p256/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2
  969dda433231690cefaaaceb1bf372b37ca060a6a3a87b40dafea0a8d2f5e171
  3b
Expected = reject
~~~

Verification fails if `challenge` is replaced by a different scalar.

~~~
Id = sigma-protocols/p256/discrete_logarithm/compact/H3
BaseId = sigma-protocols/p256/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_P256
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_P256
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  00000000000000000000000000000000000000000000000103f0f109368d010f
  5adf85ad7ce620a87291f3d4cabcf72fd8d2b91bc50f541fa8
NargString =
  3f29987a13e3ea094f2f7ee8f1ccc37ef3239bd303535a9959ca3aacca1f216d
  cfa4f6e2f3a7a88a485fc90cc1eba4019f4d66756cd8b3df83a6a43044ab1c28
Expected = reject
~~~


## sigma-proofs_Shake128_BLS12381 {#tv-bls12381}

This section contains vectors for the ciphersuite identified as `sigma-proofs_Shake128_BLS12381`.

### Valid proofs {#tv-bls12381-valid}

Knowledge of a discrete logarithm, `X = x * G`: the Schnorr relation
given as example in {{linear-map}}.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = discrete_logarithm
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
SessionId =
  b9a184f47a2038072177099bdfe75e6663e86f0cb6790b7b618102b3f3b2d787
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
Witness =
  641c3cdcc72c9b3a84b85df5808de5f37cf4489ca15f1cffdfd105b780ec0682
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = accept
~~~

Knowledge of a discrete logarithm, `X = x * G`: the Schnorr relation
given as example in {{linear-map}}.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = discrete_logarithm
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
SessionId =
  8651b5e07aef46852f93102b9e9432370b671d4bd84fbfcfd1e224a06e7ae182
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
Witness =
  641c3cdcc72c9b3a84b85df5808de5f37cf4489ca15f1cffdfd105b780ec0682
NargString =
  2b2af194b74fff452d74060e514e36a43f4b7405bff46781a78f42bc7696c7ee
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad94
Expected = accept
~~~

Discrete-logarithm equality, `X = x * G` and `Y = x * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/dleq/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = dleq
Flavor = batchable
Tag = dleq-DSFS-with-sigma-proofs_Shake128_BLS12381
SessionId =
  8a5c790e1a988d7ad14e5eecdfbd2fc1ce87e01e788c38e3c2487f8d8898c9cc
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  000000000000000000000001b8a52d4f929a5fc9a27b16941d102b632bac0b06
  61265ed04ec9e59d35480f93d4ebefc5af6a06090964444a5ed9abfdac2a3348
  158e801ab8f31490543b66ddf04a103dd0bc7f41194f72b575b62d08900aaf6e
  7ba8f3672c1b7064b19ecf968f3af22d60210b724fc400f8b8e8547a3f82ba01
  7d24199087b0bd1941c21f4c6afa8e1d636914790ee4b80e44908926
Witness =
  4a27c7be9fb7612efe553eb66c7120b978433c35625c00c9c530da6e7214db08
NargString =
  b13432cd2a44f3287e1ee64986f77cfd30bc6e27cb5bb245e5e0d5cd74d7ea59
  d64b17f3e612b0a5790bad93d77ea46291f38f62b25f78dae74200765604f560
  b5b0459b45404eb953e498497a94757841739571c4fa83ba5b27fb2cd9c01c20
  53843da83608b616cb57c042f0d21160317095e5ab1706e02299dfd47f67b453
Expected = accept
~~~

Discrete-logarithm equality, `X = x * G` and `Y = x * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/dleq/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = dleq
Flavor = compact
Tag = dleq-CMPT-with-sigma-proofs_Shake128_BLS12381
SessionId =
  244120cf7e64e64f0230270461e2011b7e7a37a4ddd1f10613c5a9ea3d69afb5
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  000000000000000000000001b8a52d4f929a5fc9a27b16941d102b632bac0b06
  61265ed04ec9e59d35480f93d4ebefc5af6a06090964444a5ed9abfdac2a3348
  158e801ab8f31490543b66ddf04a103dd0bc7f41194f72b575b62d08900aaf6e
  7ba8f3672c1b7064b19ecf968f3af22d60210b724fc400f8b8e8547a3f82ba01
  7d24199087b0bd1941c21f4c6afa8e1d636914790ee4b80e44908926
Witness =
  4a27c7be9fb7612efe553eb66c7120b978433c35625c00c9c530da6e7214db08
NargString =
  6756a6afe70dc8b509ece61173992cd9970d6219332d289fecf58e240f1497ca
  1712fb2963a360c4bc783fa9764bb115b7162e014c5f6c8859fbcd71fbc58844
Expected = accept
~~~

Knowledge of the opening of a Pedersen commitment, `C = x * G + r * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/pedersen_commitment/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = pedersen_commitment
Flavor = batchable
Tag = pedersen_commitment-DSFS-with-sigma-proofs_Shake128_BLS12381
SessionId =
  e029c091ebd8fea4edbd7025de04170104768f284ab9693ede56a0a6ffb299fc
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  98a75ce3f191eebaed9f6a49b445f423ac6ba6dd2caad41ff2d5a05db9531f35
  0d9125914ddacd670af9e851d44c05239482122220076c1aa251a964e649aec8
  3af91fb2660b1e1dd1932353a88020c3ef09a805be4d8af09a094eaf2263695f
Witness =
  513794634e24e09f9eb668c0c1f4dfd6857e303b6b8bc5d08bae5a19e3961ed3
  27b79d17769ee1f8c1d774380a3acdb8d70c96f4869fa17fdcaf7a5729804a12
NargString =
  a35cdeff7ecb8c09e2527e98c6da38d23d8f9ac25affe1be3fec9976428f0b83
  7b8b9c62b8726f4ee3522e59a64e6b402e26ba8823477689798c38ba703692f5
  156f5d39febaa33eacf1a0ecbc2973a813e0e02d5c72770b6397cfab9315e5cf
  3c2402516220b2ac1ec139c9bfdc020f
Expected = accept
~~~

Knowledge of the opening of a Pedersen commitment, `C = x * G + r * H`
({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/pedersen_commitment/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = pedersen_commitment
Flavor = compact
Tag = pedersen_commitment-CMPT-with-sigma-proofs_Shake128_BLS12381
SessionId =
  0d54417e1f7bbbb652a9230e7e47701d1654bee35c8ae86235864576c86521a4
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  98a75ce3f191eebaed9f6a49b445f423ac6ba6dd2caad41ff2d5a05db9531f35
  0d9125914ddacd670af9e851d44c05239482122220076c1aa251a964e649aec8
  3af91fb2660b1e1dd1932353a88020c3ef09a805be4d8af09a094eaf2263695f
Witness =
  513794634e24e09f9eb668c0c1f4dfd6857e303b6b8bc5d08bae5a19e3961ed3
  27b79d17769ee1f8c1d774380a3acdb8d70c96f4869fa17fdcaf7a5729804a12
NargString =
  0af9ef56a2968b32d07654a7de630732e9cad9625c51f7b7975cd3056ef71021
  1be5f52ee640769f3fd276008102aa8ee5041f859aa509d2bf8bc35224eb2841
  36a8475ab594387b75de3af7e2ff51464c6b518172604308ede2dac3fc97f9bc
Expected = accept
~~~

Two Pedersen-form equations sharing both witness scalars, `X = x0 * G0 +
x1 * G1` and `Y = x0 * G2 + x1 * G3` ({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/pedersen_commitment_dleq/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = pedersen_commitment_dleq
Flavor = batchable
Tag = pedersen_commitment_dleq-DSFS-with-sigma-proofs_Shake128_BLS12381
SessionId =
  ce017f3f5b3462089c1b374cdd47271a0d0d3bae7381eb3435830eeaf9c48879
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000006000000000000000000000000000000000000000000000000000000
  0000000000000001020000000000000004000000000000000000000000000000
  0000000000000000000000000000000000000001010000000500000000000000
  0000000000000000000000000000000000000000000000000000000192e906e9
  85c25121c422faf4c618bd1a1b9a31a563997e0300fc79a90752ec3423b0b607
  7a8f1efbf89c4feee7e6f55b85fe8aa4926c2c83d53466c50d7e61f51b071708
  e0886e493aec496695ca47ec167c232c892c4dbfb5ab7f62208af10489f0a331
  1573d65bc23cb94ff627e7e5855348e476b5d6a2b7fa4daa31d77c20f7a6f44b
  059d3fe72dde06ec2b3e29f4973cf3101e95d7c046d2984c5bde86e5ca114357
  ef165d2d15018d420aa35a96c109631357d5c2f61997cb3004b5a0d49785c04c
  35f1feccfe251efff48c5dcedfaffbab72620d295c0fce75698a7d07ae46d5f4
  b2f44602f8cb21af77c53e07b3134ce7555cb8088050c52848913e400eb19141
  6af4356dadc545c7e12333ebe29658ab0c3a01d890f9ff0a250bc926
Witness =
  6633fad945a9da933660070571afb1deb184bb2d24f542bdee864493dcb30027
  05f1a4f40164cbbe8b8a33038ad8458afb6b262c0691f7442b1fb2ad253b60c3
NargString =
  93a9baa8ac481ad40ffb0c046c03cc8d05f698c9cce9f24aa004f86d8f2b1756
  304a4c9e213c36b95628c1e606d2f448b5f0c6903de76e160f034500b499cb05
  ea59240e4e616206e444b2f3842a30a78a50ee8551dda8fb532d07b3f9411895
  1e6c7803723853a5a5b655ec96bf793dbac487d93804573544d9b16a43cf9fa1
  4bc77e8961c638fa11f7eb0a9623f1e665272e2b9140a989b3638b896217e015
Expected = accept
~~~

Two Pedersen-form equations sharing both witness scalars, `X = x0 * G0 +
x1 * G1` and `Y = x0 * G2 + x1 * G3` ({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/pedersen_commitment_dleq/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = pedersen_commitment_dleq
Flavor = compact
Tag = pedersen_commitment_dleq-CMPT-with-sigma-proofs_Shake128_BLS12381
SessionId =
  9be697e93cbf8dc535caadba2629113c6c63bb12b6f46a86668e28fb2c9e09ef
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000006000000000000000000000000000000000000000000000000000000
  0000000000000001020000000000000004000000000000000000000000000000
  0000000000000000000000000000000000000001010000000500000000000000
  0000000000000000000000000000000000000000000000000000000192e906e9
  85c25121c422faf4c618bd1a1b9a31a563997e0300fc79a90752ec3423b0b607
  7a8f1efbf89c4feee7e6f55b85fe8aa4926c2c83d53466c50d7e61f51b071708
  e0886e493aec496695ca47ec167c232c892c4dbfb5ab7f62208af10489f0a331
  1573d65bc23cb94ff627e7e5855348e476b5d6a2b7fa4daa31d77c20f7a6f44b
  059d3fe72dde06ec2b3e29f4973cf3101e95d7c046d2984c5bde86e5ca114357
  ef165d2d15018d420aa35a96c109631357d5c2f61997cb3004b5a0d49785c04c
  35f1feccfe251efff48c5dcedfaffbab72620d295c0fce75698a7d07ae46d5f4
  b2f44602f8cb21af77c53e07b3134ce7555cb8088050c52848913e400eb19141
  6af4356dadc545c7e12333ebe29658ab0c3a01d890f9ff0a250bc926
Witness =
  6633fad945a9da933660070571afb1deb184bb2d24f542bdee864493dcb30027
  05f1a4f40164cbbe8b8a33038ad8458afb6b262c0691f7442b1fb2ad253b60c3
NargString =
  543dd59971ee254384ae6fef1d36c0dcdbfc1b3ce47ad97d33599e4b6d27f17e
  607cf3588579214c206fbd389eab0e45fd6b72ae79100468e12ed5e7a866c177
  01c611bb833a1518f0588deb29d04dbc3e43f2adfdaa378fda3c0489fbb1c4cf
Expected = accept
~~~

The blind commitment computation of {{BBSBlind}}, `C = blind * Q2 +
msg_1 * J1 + msg_2 * J2 + msg_3 * J3`.

~~~
Id = sigma-protocols/bls12381/bbs_blind_commitment_computation/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = bbs_blind_commitment_computation
Flavor = batchable
Tag =
  bbs_blind_commitment_computation-DSFS-with-sigma-proofs_Shake128_BLS12
  381
SessionId =
  2a5805ac1b5454c5ee85c1d1dd9edcd417a992a718de963f24b188c962457877
Instance =
  0100000001000000050000000000000000000000000000000000000000000000
  0000000000000000000000010400000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0200000003000000000000000000000000000000000000000000000000000000
  0000000000000001030000000400000000000000000000000000000000000000
  00000000000000000000000000000001a1d2f5b67fab08902ded92336405309c
  6b37f32b3e435ed7b0213555f58fa1f55394ddf070c7b2c1ffeb9a4e72043ce3
  a6c3922e0802086d57687391066cf25827154b05982bc17b585272d98ba7a3be
  222acb845fef67fc29ae0e9aae085c7ab40ee516a7d08c3a178c5ff6818c598b
  ed05176adcd57e5ef03fca4d7f3db3a457b47529cd2af4a47845b38e0de2df1d
  b2c01bd2aa2ff4b0cbe41e8b04de59ce28d60849621b7409a19d51c7ef83ca68
  f1d6b1f78665c9735477bb4f354880a0a81862f2e43f3c01765ce2104b0f1f22
  8bc890da4a3ae973d7a14a7584af797b9526062591b1735f4bd01396beaad8ea
Witness =
  28288611c102591a64e5d092e2ce83cc10f8d15f094f1342e7d74bd13b85da56
  148a573a14e1c0c340ed3b0505ef72f3e308410156ed657b6690662bf22b73c6
  393c117132d5a600b63968dfd4b03480b89cf5aff74ec52749a6086b50878c62
  1e6ea7c86713a9e429396b2be43a403ed1d435367f157b9c8370e9f223ba479a
NargString =
  977956f7bad0c7473dfffc0fc9c83e6a875dc84944c8d7e6d43e37111f26b4ce
  1e34dc254886cf4560b5ca988c8b4a1116fae4c649c9c45aa1d18b91befafa3e
  c3c5d33d696b08668651de18abcb0f2f146d2ddade6629b540783e11e180b8e4
  9bacef2d6ff14d1ec1c10153b0c277321d2df04da792deb0e7be13e9c754a418
  0b8706446d986ee791f8523a1f5125c8027de941da6d6f6f20de5ef10271cb01
  57408dad73376457ed50efa9fb07f996
Expected = accept
~~~

The blind commitment computation of {{BBSBlind}}, `C = blind * Q2 +
msg_1 * J1 + msg_2 * J2 + msg_3 * J3`.

~~~
Id = sigma-protocols/bls12381/bbs_blind_commitment_computation/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = bbs_blind_commitment_computation
Flavor = compact
Tag =
  bbs_blind_commitment_computation-CMPT-with-sigma-proofs_Shake128_BLS12
  381
SessionId =
  d44869a3b7c697750425649f4ff70570a192a6afc76d86f233d1d11c6f88e996
Instance =
  0100000001000000050000000000000000000000000000000000000000000000
  0000000000000000000000010400000000000000010000000000000000000000
  0000000000000000000000000000000000000000000000010100000002000000
  0000000000000000000000000000000000000000000000000000000000000001
  0200000003000000000000000000000000000000000000000000000000000000
  0000000000000001030000000400000000000000000000000000000000000000
  00000000000000000000000000000001a1d2f5b67fab08902ded92336405309c
  6b37f32b3e435ed7b0213555f58fa1f55394ddf070c7b2c1ffeb9a4e72043ce3
  a6c3922e0802086d57687391066cf25827154b05982bc17b585272d98ba7a3be
  222acb845fef67fc29ae0e9aae085c7ab40ee516a7d08c3a178c5ff6818c598b
  ed05176adcd57e5ef03fca4d7f3db3a457b47529cd2af4a47845b38e0de2df1d
  b2c01bd2aa2ff4b0cbe41e8b04de59ce28d60849621b7409a19d51c7ef83ca68
  f1d6b1f78665c9735477bb4f354880a0a81862f2e43f3c01765ce2104b0f1f22
  8bc890da4a3ae973d7a14a7584af797b9526062591b1735f4bd01396beaad8ea
Witness =
  28288611c102591a64e5d092e2ce83cc10f8d15f094f1342e7d74bd13b85da56
  148a573a14e1c0c340ed3b0505ef72f3e308410156ed657b6690662bf22b73c6
  393c117132d5a600b63968dfd4b03480b89cf5aff74ec52749a6086b50878c62
  1e6ea7c86713a9e429396b2be43a403ed1d435367f157b9c8370e9f223ba479a
NargString =
  3b32ef1ba00ed483b5494e33305df9a260dac8ae87e95eed9de83617de093b71
  4955e5e99e066b6bc828c6ab6f282d38e3f11f5edbdf8857d6ddad0c8788bfb5
  68f2d25c344c5f27226941d199e5a25f129544cccfa5c0e751c9622752d19ac9
  3314321c51a7c2853483e7239b3e567f6785f863ef4a8bf558fbf228e2c0bd4d
  4056b35bfa8f6868d298d50d76c640c67a59fa67c35793b4123c49fa03a88198
Expected = accept
~~~

Correct ElGamal decryption, `X = x * G` and `M = x * E0 - E1`
({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/elgamal_decryption/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = elgamal_decryption
Flavor = batchable
Tag = elgamal_decryption-DSFS-with-sigma-proofs_Shake128_BLS12381
SessionId =
  f3606306ba6a9e7497185a0dd337bee9364dd4b4cd889704fc40ce74412dffeb
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000004000000
  0000000000000000000000000000000000000000000000000000000000000001
  0300000000000000000000000000000000000000000000000000000000000000
  0000000101000000000000000200000000000000000000000000000000000000
  00000000000000000000000000000001a73aa2551fd1f24865adb5b9a84f63ef
  b8d2cab44fcf21dfa9e587dcabff2a0ffa36a93a82df2027ec32288160f0ebd3
  835f420c8a573cde22b41e8b427fda9427e9ab5d6bca17cdc4d045c8dd37091a
  a7315f499646c01861faf1a96f863776a002ade8d4092fd89a457856e9b7afd6
  cbe26135981799f75042353f6e9a3eabf205e3788417e21d67741f16b69837c5
  86309903b1709ca1b7aca43326415b5bf7e9eb8f259c631913fc55b3a78021cc
  bdfde509aa8168b3d949ef129247cfd9
Witness =
  6f92d7965b9cb245c7656316af218d42c5625f5234bbbd3eba630c9d6f058a76
NargString =
  abc0eca21b6faea727caf039722661724aa0ffa84df6cff0540292c4b339b2cb
  d8a06d8b64846bd48d9f194be457a14785c969bc6583aea3aa84fb9a1be42b90
  3a9de7be864d9f50f3ab7cf4c1fa4465ac65ee456fb7c652048ba4a0658d3ef8
  03c8f8cba745239dc02dac475278009f48a4c3b4e8c77b698d7403396b684f5d
Expected = accept
~~~

Correct ElGamal decryption, `X = x * G` and `M = x * E0 - E1`
({{relation-notation}}).

~~~
Id = sigma-protocols/bls12381/elgamal_decryption/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = elgamal_decryption
Flavor = compact
Tag = elgamal_decryption-CMPT-with-sigma-proofs_Shake128_BLS12381
SessionId =
  7e4a5e42b1686205633d27701ae29f682fb2c748e21c0a8a87d021486652c899
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000004000000
  0000000000000000000000000000000000000000000000000000000000000001
  0300000000000000000000000000000000000000000000000000000000000000
  0000000101000000000000000200000000000000000000000000000000000000
  00000000000000000000000000000001a73aa2551fd1f24865adb5b9a84f63ef
  b8d2cab44fcf21dfa9e587dcabff2a0ffa36a93a82df2027ec32288160f0ebd3
  835f420c8a573cde22b41e8b427fda9427e9ab5d6bca17cdc4d045c8dd37091a
  a7315f499646c01861faf1a96f863776a002ade8d4092fd89a457856e9b7afd6
  cbe26135981799f75042353f6e9a3eabf205e3788417e21d67741f16b69837c5
  86309903b1709ca1b7aca43326415b5bf7e9eb8f259c631913fc55b3a78021cc
  bdfde509aa8168b3d949ef129247cfd9
Witness =
  6f92d7965b9cb245c7656316af218d42c5625f5234bbbd3eba630c9d6f058a76
NargString =
  69a11eea4a1ee7d995219a7b0f5df7bf18ee156b4b4e66b95147b090c07cb8cb
  26816cc9aac1a2b14e5adbebbf973a42e2826591392787fddca9e13b8443b904
Expected = accept
~~~

The `ChaumPedersen` relation of {{relation-notation}} again, with `Y = x
* H` derived by the prover from its witness rather than received: the
compiled instance matches `dleq`, and only the tag (hence the proof
bytes) differs.

~~~
Id = sigma-protocols/bls12381/dleq_derived_element/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = dleq_derived_element
Flavor = batchable
Tag = dleq_derived_element-DSFS-with-sigma-proofs_Shake128_BLS12381
SessionId =
  54bbba96ccae65df6e806d77e8869cd48afdbc785038d6f90fa905a14f7d53bf
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000199dab5463df27b0f83b0608d830294a57f53d279
  fd3c5b719bd25ca5bb9a25a57787f6c92bb933ccaa421588ee4554ff8673f08e
  10bee9fe8e7eb4f6a1ef0b60571e84c26710a2d4b0bacf0a49033dc814b2c0c9
  3d1e83025f0d9fde75835ac4b1aa95d5868f12734c8183e2222f3c321bd19403
  802e635dd2c12731e366be9e5e37af51c283afb582fa8a153f494b1c
Witness =
  48775faa1051b0df070268dee5c4163b9635ebecb049f9016f3538423a7d227c
NargString =
  abc30c203650564c3318f34ca0a4140728631799358f1004bff7708e2e0e1c80
  e5d3550cf546bd78734f35c50a0ef599b3f2f83ece52e1d93bdaff1f9344b03f
  c5b0f324f0a397f4ba8d10d7bb954e9ae884eaa07dd11d942f925f14ebdd3e29
  1b5757ca9c1cf7f34a3fe51c5803c9996f9ae0092d24059aecaf12352268d1d6
Expected = accept
~~~

The `ChaumPedersen` relation of {{relation-notation}} again, with `Y = x
* H` derived by the prover from its witness rather than received: the
compiled instance matches `dleq`, and only the tag (hence the proof
bytes) differs.

~~~
Id = sigma-protocols/bls12381/dleq_derived_element/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Relation = dleq_derived_element
Flavor = compact
Tag = dleq_derived_element-CMPT-with-sigma-proofs_Shake128_BLS12381
SessionId =
  f284a4d31c70b703930a48a8f420606f8997f3b52ce41458ed8c827257f01a08
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  00000000000000000000000199dab5463df27b0f83b0608d830294a57f53d279
  fd3c5b719bd25ca5bb9a25a57787f6c92bb933ccaa421588ee4554ff8673f08e
  10bee9fe8e7eb4f6a1ef0b60571e84c26710a2d4b0bacf0a49033dc814b2c0c9
  3d1e83025f0d9fde75835ac4b1aa95d5868f12734c8183e2222f3c321bd19403
  802e635dd2c12731e366be9e5e37af51c283afb582fa8a153f494b1c
Witness =
  48775faa1051b0df070268dee5c4163b9635ebecb049f9016f3538423a7d227c
NargString =
  57a809847f916a14f39d848a26d1f17fb0158b2b88aaa3263d44750e10a27583
  5f9a4abeedd6c411defe5803910725b117fd1eee92ea9b38ae576fb83177f457
Expected = accept
~~~


### Adversarial vectors {#tv-bls12381-invalid}

Deserialization fails if the compression bit is cleared.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/A1
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  221df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Deserialization fails if the x-coordinate is lifted by the field
characteristic (x = 4, encoded as x + p).

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/A3
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624
  1eabfffeb153ffffb9feffffffffaaaf56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Deserialization fails on the canonical compressed encoding of the point
at infinity: the identity is invalid in prover messages.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/A4
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  c000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000056b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Deserialization fails on a point (x = 0) on the curve but outside the
prime-order subgroup G1.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/A5
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  8000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000056b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Deserialization fails on x = 1, which is not on the curve (x^3 + 4 is a
non-residue).

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/A6
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  8000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000156b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Deserialization fails if `response[0]` is re-encoded as s + order: same
value mod p, non-canonical bytes. Reducing instead of rejecting yields
malleability.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/B1
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcbcaa396b96915e9ea45449ee848e72694
  09cdf63ba2b25a8150042aeb5bd1b642
Expected = reject
~~~

Deserialization fails if `challenge` is re-encoded as c + order
(non-canonical bytes).

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/B2
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  9f1898e7e0ed7c8d60adde165af00ea993091808bff2c380a78f42bb7696c7ef
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad94
Expected = reject
~~~

Verification fails if one trailing 0x00 byte is appended to a valid
proof.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/C1
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b64100
Expected = reject
~~~

Verification fails if a valid proof is truncated by one byte.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/C2
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b6
Expected = reject
~~~

Verification fails if one trailing 0x00 byte is appended to a valid
proof.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/C1
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  2b2af194b74fff452d74060e514e36a43f4b7405bff46781a78f42bc7696c7ee
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad94
  00
Expected = reject
~~~

Verification fails if a valid proof is truncated by one byte.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/C2
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  2b2af194b74fff452d74060e514e36a43f4b7405bff46781a78f42bc7696c7ee
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad
Expected = reject
~~~

Verification fails on the all-zero compact proof: challenge and response
are zero.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/D1
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
Expected = reject
~~~

Instance validation fails if scalar index 1 appears in no equation
(check 6); the proof satisfies the verification equations, so rejection
must come from instance validation.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/E1
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag =
  instance_unconstrained_scalar-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  a52f63244810b5e28b235f33df487fce15bc509eac539e19275e1a0c1ae36de1
  79fa412292007a1d6df975de5b8ca0a6a62b428f90a014557c5744b69c6303d0
  db7a9c876dd15743738b432a9dd1cfad79790d101eedee3bb441bccd262db1c0
NargString =
  8a31aa9ace6268707d6a0213fdf4bd9a4231fc4fec35338998a38b5334723d84
  f3c46d55c6ff9104aba7bde3e38b46cd3b5d6d79ba363cb1f75f304c0af27b3c
  717d6c2048126fb60147c58ce188a5bc0c18c708366e5b159dc527ef76ac46f5
  fb5f58bd1acdc8a9e425c7f99d7f4b4a45a360ed659e5b5db089c8f07cf725b1
  4d7aaf71cb6a55bc1e41ac4fb4ab03b2
Expected = reject
~~~

Instance validation fails on the same instance, here with the
unconstrained `response[1]` perturbed.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/E1b
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag =
  instance_unconstrained_scalar-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010200000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  a52f63244810b5e28b235f33df487fce15bc509eac539e19275e1a0c1ae36de1
  79fa412292007a1d6df975de5b8ca0a6a62b428f90a014557c5744b69c6303d0
  db7a9c876dd15743738b432a9dd1cfad79790d101eedee3bb441bccd262db1c0
NargString =
  8a31aa9ace6268707d6a0213fdf4bd9a4231fc4fec35338998a38b5334723d84
  f3c46d55c6ff9104aba7bde3e38b46cd3b5d6d79ba363cb1f75f304c0af27b3c
  717d6c2048126fb60147c58ce188a5bc0c18c708366e5b159dc527ef76ac46f5
  fb5f58bd1acdc8a9e425c7f99d7f4b4b45a360ed659e5b5db089c8f07cf725b1
  4d7aaf71cb6a55bc1e41ac4fb4ab03b2
Expected = reject
~~~

Instance validation fails if the image terms X + (-X) sum to the
identity (check 9).

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/E2
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = instance_trivial_equation-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000002000000010000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000101000000000000000000000000000000
  00000000000000000000000000000000000000000000000000000001b8d20484
  960f1741eabb4d0dd0c43e72931d646c09440bf1880a1720daaa3308e7634661
  77aa88c313f8a9ad1e406c0e98d20484960f1741eabb4d0dd0c43e72931d646c
  09440bf1880a1720daaa3308e763466177aa88c313f8a9ad1e406c0e
NargString =
  8bf4a4e7cca2a2f88859d0b012289500a49db0b5e4e5df3d778248435ed8b51d
  0fb3ca489c9f45e8811bb4cc8d0096f96ad6f36b97912382f39758d4e9f591a8
  c1d24c1f3d42a2535161c7b7a9c556a3
Expected = reject
~~~

Instance validation fails if a statement element is the identity (check
8), here at index 1, encoded as the canonical compressed encoding of
infinity; parsers may instead reject at group deserialization.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/E3
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = instance_identity_element-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000020000000000000000000000000000000000000000000000
  0000000000000000000000010200000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  c000000000000000000000000000000000000000000000000000000000000000
  00000000000000000000000000000000b8722b4b2a3cc66976d848739df2bfb6
  6ae371da496a1e239add4646c35c8b8758409ad4b6312b74d4a98bb83284cb87
NargString =
  adc1c8943d8bfa5ab165ff1ed2c0f45f71567a404849da3e0b9fbd37266681c1
  089d6d9b33116aebdab2972d0cb6db1343a4376149f6584e69ef48dac314f448
  ec00ac5b96fa50ce5a369327bb6649775a460213642cf7055af8c4bb0bcbc6b6
  122f563a9163c3d3f74876f8b25b0298
Expected = reject
~~~

Instance validation fails if a term references element index 2 while a
single element follows; parsers may instead reject on length.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/E4
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag =
  instance_index_out_of_bounds-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000020000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

A valid NARG string verifies under the tag it was produced for.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/F1
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = accept
~~~

Verification fails under a different tag.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/F1b
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag =
  discrete_logarithm/wrong-session-DSFS-with-sigma-proofs_Shake128_BLS12
  381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

A valid NARG string verifies under the tag it was produced for.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/F1
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  2b2af194b74fff452d74060e514e36a43f4b7405bff46781a78f42bc7696c7ee
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad94
Expected = accept
~~~

Verification fails under a different tag.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/F1b
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag =
  discrete_logarithm/wrong-session-CMPT-with-sigma-proofs_Shake128_BLS12
  381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  2b2af194b74fff452d74060e514e36a43f4b7405bff46781a78f42bc7696c7ee
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad94
Expected = reject
~~~

A valid NARG string verifies against the statement it was produced for.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/F2
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = dleq-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  000000000000000000000001b8a52d4f929a5fc9a27b16941d102b632bac0b06
  61265ed04ec9e59d35480f93d4ebefc5af6a06090964444a5ed9abfdac2a3348
  158e801ab8f31490543b66ddf04a103dd0bc7f41194f72b575b62d08900aaf6e
  7ba8f3672c1b7064b19ecf968f3af22d60210b724fc400f8b8e8547a3f82ba01
  7d24199087b0bd1941c21f4c6afa8e1d636914790ee4b80e44908926
NargString =
  b13432cd2a44f3287e1ee64986f77cfd30bc6e27cb5bb245e5e0d5cd74d7ea59
  d64b17f3e612b0a5790bad93d77ea46291f38f62b25f78dae74200765604f560
  b5b0459b45404eb953e498497a94757841739571c4fa83ba5b27fb2cd9c01c20
  53843da83608b616cb57c042f0d21160317095e5ab1706e02299dfd47f67b453
Expected = accept
~~~

Verification fails if the statement's two equations are swapped.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/F2b
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = dleq-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000020000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000000000000000000000000000000000000000000000000000
  000000000000000000000001b8a52d4f929a5fc9a27b16941d102b632bac0b06
  61265ed04ec9e59d35480f93d4ebefc5af6a06090964444a5ed9abfdac2a3348
  158e801ab8f31490543b66ddf04a103dd0bc7f41194f72b575b62d08900aaf6e
  7ba8f3672c1b7064b19ecf968f3af22d60210b724fc400f8b8e8547a3f82ba01
  7d24199087b0bd1941c21f4c6afa8e1d636914790ee4b80e44908926
NargString =
  b13432cd2a44f3287e1ee64986f77cfd30bc6e27cb5bb245e5e0d5cd74d7ea59
  d64b17f3e612b0a5790bad93d77ea46291f38f62b25f78dae74200765604f560
  b5b0459b45404eb953e498497a94757841739571c4fa83ba5b27fb2cd9c01c20
  53843da83608b616cb57c042f0d21160317095e5ab1706e02299dfd47f67b453
Expected = reject
~~~

A valid NARG string verifies against the statement it was produced for.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/F2
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = dleq-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0200000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000010100000003000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000020000000000000000000000000000000000000000000000
  000000000000000000000001b8a52d4f929a5fc9a27b16941d102b632bac0b06
  61265ed04ec9e59d35480f93d4ebefc5af6a06090964444a5ed9abfdac2a3348
  158e801ab8f31490543b66ddf04a103dd0bc7f41194f72b575b62d08900aaf6e
  7ba8f3672c1b7064b19ecf968f3af22d60210b724fc400f8b8e8547a3f82ba01
  7d24199087b0bd1941c21f4c6afa8e1d636914790ee4b80e44908926
NargString =
  6756a6afe70dc8b509ece61173992cd9970d6219332d289fecf58e240f1497ca
  1712fb2963a360c4bc783fa9764bb115b7162e014c5f6c8859fbcd71fbc58844
Expected = accept
~~~

Verification fails if the statement's two equations are swapped.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/F2b
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = dleq-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0200000001000000030000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000020000000000000000000000
  0000000000000000000000000000000000000000000000010100000001000000
  0000000000000000000000000000000000000000000000000000000000000001
  0100000000000000000000000000000000000000000000000000000000000000
  000000000000000000000001b8a52d4f929a5fc9a27b16941d102b632bac0b06
  61265ed04ec9e59d35480f93d4ebefc5af6a06090964444a5ed9abfdac2a3348
  158e801ab8f31490543b66ddf04a103dd0bc7f41194f72b575b62d08900aaf6e
  7ba8f3672c1b7064b19ecf968f3af22d60210b724fc400f8b8e8547a3f82ba01
  7d24199087b0bd1941c21f4c6afa8e1d636914790ee4b80e44908926
NargString =
  6756a6afe70dc8b509ece61173992cd9970d6219332d289fecf58e240f1497ca
  1712fb2963a360c4bc783fa9764bb115b7162e014c5f6c8859fbcd71fbc58844
Expected = reject
~~~

Verification fails if a statement element is changed after proving.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/F3
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001b94ba65546846b43
  9edbfc9da84c1c2d2af3d0ede8c88ec50fce2e1c3f782e932205982683f0802a
  4dce313610bbb2db
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Verification fails if a statement element is changed after proving.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/F3
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001b94ba65546846b43
  9edbfc9da84c1c2d2af3d0ede8c88ec50fce2e1c3f782e932205982683f0802a
  4dce313610bbb2db
NargString =
  2b2af194b74fff452d74060e514e36a43f4b7405bff46781a78f42bc7696c7ee
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad94
Expected = reject
~~~

Verification fails if the batchable proof's transcript is re-encoded as
a compact NARG string.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/F4
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  0bfd67330803e2f88ba4d8f54723e95c53a032c2aa976b0f7e54099ec42d461c
  56b5ef663f786ca2120ac6e03f454e8eb6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Verification fails if the compact proof's transcript is re-encoded as a
batchable NARG string: the challenge derived under the batchable tag
differs.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/F4b
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  b87d072b8238866651b08da8276e9ea30125617a5ac1b7fcb6934f43bdfed513
  4624ffe8040caccc46560bd101c648885bc2ffa13e32b693d76be6e548a3d6c3
  9929b9d21f10e5ba1df2b44071f7ad94
Expected = reject
~~~

Verification fails if `response[0]` is increased by 1.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/H1
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  a21df433ede15a7e0bb0d8501e24c6c41ba6c36f387bd9961bcbc1acddda5ece
  0abe8338bef0293d96d924dafd80ddcb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b642
Expected = reject
~~~

Verification fails if `commitment[0]` is replaced by a different valid
group element.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/batchable/H2
BaseId = sigma-protocols/bls12381/discrete_logarithm/batchable
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = batchable
Tag = discrete_logarithm-DSFS-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac58
  6c55e83ff97a1aeffb3af00adb22c6bb56b5ef663f786ca2120ac6e03f454e8e
  b6105238a2b3fe8250042aec5bd1b641
Expected = reject
~~~

Verification fails if `challenge` is replaced by a different scalar.

~~~
Id = sigma-protocols/bls12381/discrete_logarithm/compact/H3
BaseId = sigma-protocols/bls12381/discrete_logarithm/compact
Function = SigmaProof
Ciphersuite = sigma-proofs_Shake128_BLS12381
Flavor = compact
Tag = discrete_logarithm-CMPT-with-sigma-proofs_Shake128_BLS12381
Instance =
  0100000001000000010000000000000000000000000000000000000000000000
  0000000000000000000000010100000000000000000000000000000000000000
  000000000000000000000000000000000000000000000001ac2de2d5ca1310a4
  3b8c5adee4632e69c117edbc6c0e9a259efbefd6e5aedc86a4185f06e74a63bf
  a648c1c4e8b4b444
NargString =
  2b2af194b74fff452d74060e514e36a43f4b7405bff46781a78f42bc7696c7ef
  5bc2ffa13e32b693d76be6e548a3d6c39929b9d21f10e5ba1df2b44071f7ad94
Expected = reject
~~~

