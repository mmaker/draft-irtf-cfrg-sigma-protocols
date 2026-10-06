---
title: "Fiat-Shamir Transformation"
category: info

docname: draft-irtf-cfrg-fiat-shamir-latest
submissiontype: IRTF
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
  SHA3:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)

informative:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
    date: 2024
    seriesinfo:
      "FIPS": "204"
    author:
      - org: "National Institute of Standards and Technology (NIST)"
  CO25:
    title: "A Fiat-Shamir Transformation From Duplex Sponges"
    target: https://eprint.iacr.org/2025/536.pdf
    date: 2025
    author:
      -
        fullname: "Alessandro Chiesa"
      -
        fullname: "Michele Orrù"
  SPONGE:
    title: "Cryptographic Sponge Functions"
    target: https://keccak.team/files/CSF-0.1.pdf
    date: 2011
    author:
      -
        fullname: "Guido Bertoni"
      -
        fullname: "Joan Daemen"
      -
        fullname: "Michaël Peeters"
      -
        fullname: "Gilles Van Assche"
  DUPLEX:
    title: "Duplexing the Sponge: Single-Pass Authenticated Encryption and Other Applications"
    target: https://keccak.team/files/SpongeDuplex.pdf
    date: 2011
    author:
      - fullname: "Guido Bertoni"
      - fullname: "Joan Daemen"
      - fullname: "Michaël Peeters"
      - fullname: "Gilles Van Assche"
  BPW16:
    title: "How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios"
    target: https://eprint.iacr.org/2016/771
    date: 2012
    author:
      - fullname: "David Bernhard"
      - fullname: "Olivier Pereira"
      - fullname: "Bogdan Warinschi"
  DMWG23:
    title: "Weak Fiat-Shamir Attacks on Modern Proof Systems"
    target: https://eprint.iacr.org/2023/691
    date: 2023
    author:
      - fullname: "Quang Dao"
      - fullname: "Jim Miller"
      - fullname: "Opal Wright"
      - fullname: "Paul Grubbs"
  FROZENHEART:
    title: "The Frozen Heart vulnerability in PlonK"
    target: https://blog.trailofbits.com/2022/04/18/the-frozen-heart-vulnerability-in-plonk/
    date: 2022
    author:
      - org: "Trail of Bits"
  SOLANA-ZK:
    title: "Post Mortem: ZK ElGamal Proof Program Bug"
    target: https://solana.com/news/post-mortem-may-2-2025
    date: 2025
    author:
      - org: "Solana Foundation"
  POSEIDON2:
    title: "Poseidon2: A Faster Version of the Poseidon Hash Function"
    target: https://eprint.iacr.org/2023/323
    date: 2023
    author:
      - fullname: "Lorenzo Grassi"
      - fullname: "Dmitry Khovratovich"
      - fullname: "Markus Schofnegger"
  SAFE:
    title: "SAFE: Sponge API for Field Elements"
    target: https://eprint.iacr.org/2023/522
    date: 2023
    author:
      - fullname: "JP Aumasson"
      - fullname: "Dmitry Khovratovich"
      - fullname: "Bart Mennink"
      - fullname: "Porçu Quine"
  GNARK-OOM:
    title: "Out-of-memory during deserialization with crafted inputs"
    target: https://github.com/Consensys/gnark/security/advisories/GHSA-cph5-3pgr-c82g
    date: 2024
    author:
      - org: "Consensys"
  GNARK-KZG:
    title: "Plonk verifier KZG multi point verification"
    target: https://github.com/Consensys-Incorporated/gnark/security/advisories/GHSA-7p92-x423-vwj6
    date: 2023
    author:
      - org: "Consensys"
  CVE-2022-29566:
    title: "CVE-2022-29566: Fiat-Shamir hashing omits public values from the statement and the proof in Bulletproofs (Frozen Heart)"
    target: https://nvd.nist.gov/vuln/detail/CVE-2022-29566
    date: 2022
  CVE-2024-45039:
    title: "CVE-2024-45039: gnark Groth16 commitment extension unsound for more than one commitment"
    target: https://nvd.nist.gov/vuln/detail/CVE-2024-45039
    date: 2024
  CVE-2026-46654:
    title: "CVE-2026-46654: Plonky3 Fiat-Shamir challenge collision from a non-binding transcript"
    target: https://nvd.nist.gov/vuln/detail/CVE-2026-46654
    date: 2026

--- abstract

This document describes the Fiat-Shamir transformation, which allows making a public-coin protocol non-interactive by means of a cryptographic hash function.

It specifies how the hash function is employed, how prover messages are encoded as hash-function input, and how verifier messages are decoded from the hash function's output, as well as the serialization and deserialization of the non-interactive argument string.

--- middle

# Introduction

The Fiat-Shamir transformation turns a *public-coin* interactive argument into a non-interactive argument by replacing the verifier's random messages with the output of a cryptographic hash function. The protocol transcript is serialized into a *non-interactive argument* (NARG) string that can be verified without interacting with the prover. The resulting argument is secure in the random oracle model, where the hash function is treated as an ideal random function (see {{sec-transformation}}).

It is notoriously easy to get the Fiat-Shamir transformation wrong, introducing critical security bugs {{BPW16}}, {{DMWG23}}, {{FROZENHEART}}, {{SOLANA-ZK}}. This specification provides guidelines and security requirements for each component of the Fiat-Shamir transformation, avoiding duplicate security analysis across multiple proof systems. It provides:

- a non-interactive argument prover (NARG prover), and
- a non-interactive argument verifier (NARG verifier)

The prover is a randomized procedure and generally relies on a cryptographically-secure entropy source; the verifier **SHOULD** be deterministic.

Both the non-interactive prover and verifier rely on:

- a duplex sponge, prescribing how to interact with the cryptographic hash function ({{hash-instantiations}});
- a set of codecs, describing how each prover and verifier message talks to the duplex sponge ({{codecs}});
- a serialization and deserialization procedure for the NARG string produced by the prover ({{narg-string}}).

This transformation is also well-suited for recursive proving, since the in-circuit cost of recomputing the Fiat-Shamir challenges is low. It is compatible with arithmetization-friendly hash functions (e.g. Poseidon2 {{POSEIDON2}}) that operate natively on field elements. See {{CO25}} for the general construction.

Other types of non-interactive transformations (with and without random oracles) are possible, but outside the scope of this specification.

~~~ aasvg
+--------------------------------------------------------------------+
| NARG Prover (session_id, instance, witness)                        |
|                                                                    |
|                                                        +------+    |
| session_id ------------------------------------------->| Init |    |
|                                                        +------+    |
|                                                            |       |
|                                                            v       |
|                                       +------------+   +--------+  |
| instance ---------------------------->| encode[0]  |-->| Absorb |  |
| +-------------------+                 +------------+   +--------+  |
| | Interactive Prover|                                      |       |
| |(instance, witness)|                                      |       |
| |                   | prover_msg[1]                        v       |
| |                   |                 +------------+   +--------+  |
| |                   +---------------->| encode[1]  |-->| Absorb |  |
| |                   |                 +------------+   +--------+  |
| |                   |                                      |       |
| |                   | verifier_msg[1]                      v       |
| |                   |                 +------------+   +---------+ |
| |                   |<----------------| decode[1]  |<--| Squeeze | |
| |                   |                 +------------+   +---------+ |
| |                   |                                      |       |
| |                   | prover_msg[2]                        v       |
| |                   |                 +------------+   +--------+  |
| |                   +---------------->| encode[2]  |-->| Absorb |  |
| |                   |                 +------------+   +--------+  |
| |                   |                                      |       |
| |                   | verifier_msg[2]                      v       |
| |                   |                 +------------+   +---------+ |
| |                   |<----------------| decode[2]  |<--| Squeeze | |
| |                   |                 +------------+   +---------+ |
| |                   |        .                             .       |
| |                   |        .                             .       |
| |                   |        .                             .       |
| |                   |                                      |       |
| |                   | prover_msg[k-1]                      v       |
| |                   |                 +------------+   +--------+  |
| |                   +---------------->| encode[k-1]|-->| Absorb |  |
| |                   |                 +------------+   +--------+  |
| |                   |                                      |       |
| |                   | verifier_msg[k-1]                    v       |
| |                   |                 +------------+   +---------+ |
| |                   |<----------------| decode[k-1]|<--| Squeeze | |
| |                   |                 +------------+   +---------+ |
| |                   | prover_msg[k]                                |
| |                   +---------------->                             |
| +-------------------+                                              |
|                                                                    |
|    narg_string := serialize(prover_msg[..])                        |
+--------------------------------------------------------------------+
~~~
{: #fig-fiat-shamir-prover title="Non-interactive prover for the Fiat-Shamir transformation"}

~~~ aasvg
+-------------------------------------------------------------------+
| NARG Verifier V(session_id, instance, narg_string)                |
|                                                                   |
| 1. prover_msg[..] := deserialize(narg_string)                     |
| 2. derive verifier messages:                                      |
|                                                                   |
|                                     +------+                      |
| session_id ------------------------>| Init |                      |
|                                     +------+                      |
|                                         |                         |
|                                         v                         |
|              +-----------+          +--------+                    |
| instance --->| encode[0] |--------->| Absorb |                    |
|              +-----------+          +--------+                    |
|                                         |                         |
|                                         v                         |
|prover_msg[1] +-----------+          +--------+                    |
|------------->| encode[1] |--------->| Absorb |                    |
|              +-----------+          +--------+                    |
|                                         |                         |
|                                         v                         |
| verifier_msg[1] +-----------+       +---------+                   |
| <---------------| decode[1] |<------| Squeeze |                   |
|                 +-----------+       +---------+                   |
|                                         |                         |
|                                         v                         |
|prover_msg[2] +-----------+          +--------+                    |
|------------->| encode[2] |--------->| Absorb |                    |
|              +-----------+          +--------+                    |
|                                         |                         |
|                                         v                         |
| verifier_msg[2] +-----------+       +---------+                   |
| <---------------| decode[2] |<------| Squeeze |                   |
|                 +-----------+       +---------+                   |
|       .                                 .                         |
|       .                                 .                         |
|       .                                 .                         |
|prover_msg[k]  +-----------+       +--------+                      |
|-------------->| encode[k] |------>| Absorb |                      |
|               +-----------+       +--------+                      |
|                                         |                         |
|                                         v                         |
| verifier_msg[k]   +-----------+   +---------+                     |
| <-----------------| decode[k] |<--| Squeeze |                     |
|                   +-----------+   +---------+                     |
|                                                                   |
| 3. Run the interactive verifier                                   |
|                                                                   |
| +------------------------------------------------+                |
| | Interactive Verifier                           |                |
| |  (instance, prover_msg[..], verifier_msg[..])  |                |
| +------------------------------------------------+                |
+-------------------------------------------------------------------+
~~~
{: #fig-fiat-shamir-verifier title="Non-interactive verifier for the Fiat-Shamir transformation"}

Note that the prover does not need to compute the last verifier message `verifier_msg[k]`. The security guarantees provided by this transformation are described in {{security-considerations}}.

# Terminology and conventions in this document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

The algorithms and procedures in this document are specified using Python-like pseudocode. Functions may depend on external parameters, such as the suite ({{suites}}); once selected, these parameters are treated as constants.

The following notation is used throughout this document.

## Bytes and integers

A byte is an 8-bit unsigned integer (an octet), and a **byte string** is a finite sequence of bytes. An `N`-byte string is a byte string of length `N`. The empty byte string is written `""`; `x || y` is the concatenation of the byte strings `x` and `y`. `len(x)` denotes the length in bytes of the byte string `x`. `zeros(N)` denotes the `N`-byte string of zero bytes.

Byte strings are indexed from zero. For integers `0 <= i <= j <= len(x)`, `x[i : j]` denotes the `(j - i)`-byte substring of `x` consisting of the bytes at positions `i, i+1, ..., j-1`. In particular, `x[0 : N]` is the first `N` bytes of `x`, `x[i : i]` is the empty byte string `""`, and `x[0 : len(x)]` is `x` itself.

A byte string `x` is a **prefix** of a byte string `y` if `y == x || z` for some byte string `z` (even empty). An encoding is **prefix-free** if, for any two distinct values, the encoding of one is never a prefix of the encoding of the other. A simple prefix-free encoding of a byte string `b` is `LE(len(b), 4) || b` as described in {{serialize-byte-strings}}.

`LE(n, w)` and `LE2IP(x)` are the integer/byte-string conversion primitives used throughout this document. `LE(n, w)` converts a non-negative integer `n` into a `w`-byte, little-endian byte string, and fails if `n >= 256^w`. `LE2IP(x)` converts a byte string `x` into a non-negative integer using the little-endian byte order.

The set of integers between `0` and `N-1` is denoted `[0, N)`. For a modulus `M`, `Ns` denotes the smallest integer such that `256^Ns >= M`.

## Duplex sponge interface

The Fiat-Shamir transformation relies on a cryptographic hash function, modeled as a random oracle. This is implemented as a stateful interface called a **duplex sponge** (defined in {{hash-instantiations}}), which `Absorb`s prover messages into an evolving internal state and `Squeeze`s from that state the bytes from which verifier messages are derived.

The interface generalizes the **sponge** {{SPONGE}}, which maps a variable-length input to a variable-length output by absorbing all of its input and then squeezing all of its output, to the **duplex** setting {{DUPLEX}}, in which absorbing and squeezing may be arbitrarily interleaved while retaining the same state. The state is split into a **rate**, the portion through which bytes are absorbed and squeezed, and a **capacity**, which is never read or written directly. Security relies on the size of the capacity. The properties a concrete instantiation must satisfy for this to hold, and the resulting security loss, are given in {{security-considerations}} and analyzed in {{CO25}}.

## Proof systems terminology

The **session identifier** is a 32-byte string identifying the non-interactive argument system and the application context. It is held by both the prover and the verifier (see {{session-id}}).

A **prover message** is a message sent by the interactive prover, and a **verifier message** is a message sent by the interactive verifier (a uniformly random value, sometimes called _challenge_). The **transcript** is the ordered sequence of prover and verifier messages. In particular, the transcript does _not_ include the instance and session identifier.

The **instance** specifies the statement being proven and is held by both the prover and the verifier.

The **witness** is the prover's private input. It is known only to the prover and is never revealed. It appears neither in the transcript nor in the NARG string.

For an NP language, the instance is a word, the witness is a proof of its membership in the language, and the resulting non-interactive argument proves that the instance is indeed in the language. This claim is also referred to as the **statement**. Proof systems might support different statements or express the same language in different ways.

The **NARG string** (non-interactive argument string) is the serialized output of the non-interactive prover.

The notation in this document is for an interactive argument with `k` rounds in which the prover moves first (that is, sends the first message) and the verifier moves last. Other types of interactions can be expressed in the same notation: set the first prover message or final verifier message to `""` when the protocol omits that message. All messages in rounds `2`, ..., `k-1` **MUST** be non-empty.

## Codec and serialization

A prover message is processed in two independent ways: it is absorbed into the hash function to derive the verifier messages, and it is written into the NARG string sent to the verifier. This document keeps the two separate.

A **codec** ({{codecs}}) is the pair of maps between messages and the hash function's alphabet (bytes, in this document):

- **Encoding** converts the instance and each prover message into the bytes absorbed by the duplex sponge ({{encoding-bytes}}).
- **Decoding** converts the bytes squeezed from the duplex sponge into a uniformly-distributed verifier message ({{decoding}}).

**Serialization** ({{narg-string}}) is concerned with mapping prover messages to and from the NARG string:

- **Serialization** writes the prover messages into the NARG string produced by the non-interactive prover.
- **Deserialization** reads the prover messages back from the NARG string, and returns an error if the message is invalid.

For a prover message, the encoded bytes coincide with the serialized bytes: the encoding maps are the serialization functions of {{serialization}}. However, codecs and serialization serve different purposes. Codecs must maintain the soundness of the transformation, whereas deserialization keeps the NARG string unambiguous and rejects malformed proofs (see {{decoding}} and {{deserialization}}).

# Duplex sponge {#hash-instantiations}

## Interface

Prover and verifier messages are handled via three operations:

- `Init(session_id) -> state`: create a new duplex sponge state, seeded by the 32-byte string `session_id`.
- `state.Absorb(x)`: absorb `x` into the state.
- `state.Squeeze(n) -> buf`: produce `n` elements (bytes, in this document) from the state.

In the duplex sponge interface, messages can be absorbed incrementally, and `Absorb` inserts no separators: `state.Absorb(x)` followed by `state.Absorb(y)` (with no `state.Squeeze` in between) is equivalent to `state.Absorb(x || y)`.

Each `state.Squeeze(n)` is uniformly distributed, and consecutive `state.Squeeze` calls continue one output stream.

The security requirements for the 32-byte string `session_id` are given in {{session-id}}; its role in composability and reuse is discussed in {{sec-session-identifiers}}.

## XOF duplex sponge {#xof-duplex-sponge}

This section implements the duplex sponge from an eXtendable-Output Function (XOF). `XOF(M, L)` maps a byte string `M` to an `L`-byte string. The suite ({{suites}}) fixes the XOF, its rate `R` (the block size in bytes at which the XOF absorbs input, which **MUST** satisfy `R >= 32`), and its security properties ({{sec-transformation}}).

The state is a pair `(M, offset)`: `M` is the byte string absorbed so far, and `offset` is the number of output bytes already squeezed since `M` last changed.

Every verifier message is the XOF evaluation over the session identifier, the encoded instance, and the encoded prover messages up to and including the current round. That is, the `i`-th verifier message (for `1 <= i <= k`) of byte length `len_i` is computed as:

~~~
verifier_msg[i] := decode[i](XOF(
                       session_id || zeros(R - 32)
                       || encode[0](instance)
                       || encode[1](prover_msg[1])
                       || ...
                       || encode[i](prover_msg[i]),
                   len_i))
~~~

The session identifier is padded with `R - 32` zero bytes so that the instance and prover messages begin on a fresh rate-block boundary (see {{xof-init}}), for efficiency ({{efficiency}}).

### Init {#xof-init}

Seed the state by absorbing the session identifier, padded with zeros to fill the rate (the remaining `R - 32` bytes).

~~~
Init(session_id)

Input: session_id, a 32-byte string

Output: a duplex sponge state

1. assert len(session_id) == 32
2. return state := (M = session_id || zeros(R - 32), offset = 0)
~~~

### Absorb {#xof-absorb}

Feed a byte string `x` into the state. Absorbing the empty string leaves the state unchanged.

~~~
state.Absorb(x)

Input: x, a byte string

1. if x != "":
2.    state.M = state.M || x
3.    state.offset = 0
~~~

### Squeeze {#xof-squeeze}

Returns the next `n` bytes of the XOF output stream computed over the absorbed input. Consecutive `Squeeze` calls **continue** the same output stream.

~~~
state.Squeeze(n)

Input: n, the number of bytes to be squeezed

Output: a uniformly-distributed random n-byte string

1. out = XOF(state.M, state.offset + n)[state.offset : state.offset + n]
2. state.offset = state.offset + n
3. return out
~~~

Evaluated literally, `Squeeze` re-hashes `M` on every call, at a cost quadratic in the number of rounds. Implementations **SHOULD** instead keep an incremental XOF context that absorbs `M` as it grows, and squeeze from a reader over a copy of that context, continuing from `offset`; this yields identical bytes.

# Codecs {#codecs}

The only security requirement on encoding maps is that they be prefix-free. Decoding maps are infallible, and **MUST** be distribution-preserving ({{decoding}}).

## Encoding into byte strings {#encoding-bytes}

The encoding of the instance and of each prover message is its serialization, as described in {{serialization}}.


## Decoding from byte strings {#decoding}

Each verifier message type fixes the number of bytes to squeeze.

Decoding is not deserialization, and need not invert encoding nor even be injective; its only requirement is to be _distribution-preserving_: if its input is a uniformly random byte string, then its output is (statistically close to) uniformly distributed over the verifier message type.

### Byte strings

The decoding function for fixed-length byte strings is the identity.

~~~
DecodeBytes(buf, N)

Inputs:

- buf, a byte string
- N, the expected byte length

Output: out, a byte string of length N

1. assert len(buf) == N
2. return buf
~~~

### Unsigned integers {#decoding-uint}

To sample a uniformly random element modulo `M`, squeeze `Ns + 16` bytes, interpret them as a little-endian non-negative integer via `LE2IP`, and reduce modulo `M`.

~~~
DecodeUint(buf, M)

Inputs:

- buf, a byte string of length Ns + 16
- M, the modulus

Output: out, an integer in the range [0, M)

1. assert len(buf) == Ns + 16
2. return LE2IP(buf) mod M
~~~

Decoding always interprets bytes in little-endian order via `LE2IP`.

The 16 extra bytes bound the statistical distance between the reduced value and the uniform distribution over `[0, M)` to `2^-128`. More generally, sampling `n` extra bytes bounds the bias to `2^-8n`. An instantiation targeting a security level of `lambda` bits **SHOULD** squeeze `lambda/8` extra bytes.

In three cases this approach is inefficient:

- if `M` is a power of two, since the decoding bias is always 0;
- if `M` is only slightly below a power of `256` (for example, the secp256k1 scalar field order) where squeezing just `Ns` bytes and reducing with a single conditional subtraction already has bias of approximately `2^-128`;
- if the soundness error of the interactive argument is much smaller than the bias introduced, for example a protocol with 30-bit challenges does not require such a big modular reduction.

In such cases, applications **MAY** use an alternative decoding function, provided it meets the following security requirements:

- The function **MUST** have bias at most the soundness error of the interactive argument. The bias adds to the soundness error of the resulting non-interactive argument, and this requirement asks that the resulting non-interactive soundness error stays within a small multiple of the interactive soundness error.
- The function **SHOULD** be amenable to straight-line implementations. In particular, rejection sampling **SHOULD NOT** be used (see {{constant-time}}).

A similar observation in the context of hashing to a finite field is available in {{Section 5 of ?RFC9380}}.

### Field elements {#decoding-field}

A field element of a field of order `p^m` is decoded coordinate by coordinate, via `DecodeUint` ({{decoding-uint}}), starting from the least-significant. This consumes `m * (Ns + 16)` bytes. A prime field is the case `m = 1`.

~~~
DecodeField(buf, p, m)

Inputs:

- buf, a byte string of length m * (Ns + 16)
- p, the prime characteristic of the field
- m, the extension degree

Output: out, an element of the field of order p^m, given by its
        coordinates (a[0], ..., a[m-1]) over the prime field

1. assert len(buf) == m * (Ns + 16)
2. for i in 0, ..., m-1:
3.    chunk = buf[i * (Ns + 16) : (i + 1) * (Ns + 16)]
4.    a[i] = DecodeUint(chunk, p)
5. return (a[0], ..., a[m-1])
~~~

For `m = 1`, `DecodeField` is `DecodeUint`, and {{decoding-uint}} applies, including its alternatives.

For `m > 1`, decoding relies on `16 * m` additional randomness bytes. Applications with big-integer arithmetic available **MAY** use a more randomness-efficient decoding algorithm, by instead sampling `Nm + 16` bytes, where `Nm` is the smallest integer with `256^Nm >= p^m`, interpreting them as an integer via `LE2IP`, reducing modulo `p^m`, and recovering the coordinates `(a[0], ..., a[m-1])` as the base-`p` digits of the result (least-significant digit first), with the same `2^-128` bias bound.

# Initialization

Before any prover message is processed, both parties start the duplex sponge with the session identifier ({{session-id}}), and then the instance ({{instance}}). Session identifier and instance are not part of the NARG string.

## Session identifiers {#session-id}

The procedure `DeriveSessionID` below is the **RECOMMENDED** way to obtain a session identifier from a human-meaningful variable-length `tag`.

The `tag` is a byte string whose encoding as a sequence of bytes **MUST** be specified unambiguously, so that every implementation reproduces identical bytes. It is **RECOMMENDED** that the `tag` be a US-ASCII string, without byte-order mark at the beginning, nor `0x00` byte termination.

When the `tag` is composed of several fields, those fields **MUST** be combined unambiguously, so that no two distinct tuples of field values yield the same byte string. For example, concatenating `("SV1", "22")` and `("SV12", "2")` both yield `SV122` and so would share the same session identifier. Using fixed-width fields or an unambiguous delimiter is sufficient.

The tag has the following security requirements:

1. the tag **MUST** uniquely identify the **non-interactive argument** used, including the interactive argument system, the types of prover and verifier messages, the hash suite, and the language associated with the interactive argument.
2. the tag **MUST** uniquely identify the **codecs** used: the order and types of encodings and decodings at each round. For example, implementations that sample verifier messages differently must have different session identifiers.
3. the tag **MUST** identify the application context in which the non-interactive argument is used, so that a NARG string produced for one application cannot be accepted in another. A namespace string under the application's control is sufficient, such as the URL `https://example.com/login/v2`. Freshness information, such as an epoch number or timestamp, **MAY** additionally be included when the application requires proofs not to be replayed within its own context (see {{sec-session-identifiers}}).
4. the tag **SHOULD** begin with a fixed identification string that is unique to the application.
5. the tag **SHOULD** include a version number.

An application **MAY** set the 32-byte `session_id` by its own means; it **MUST** then satisfy the same requirements.

~~~
DeriveSessionID(tag)

Input: tag, an application-chosen byte string (see above)

Output: session_id, a 32-byte string

1. duplex_sponge := DS.Init("irtf-cfrg-fiat-shamir/session-id")
2. duplex_sponge.Absorb(tag)
3. return duplex_sponge.Squeeze(32)
~~~

Above, `DS` denotes the duplex sponge in use ({{hash-instantiations}}), instantiated with one of the suites of {{suites}}. The 32-byte string `"irtf-cfrg-fiat-shamir/session-id"` is a domain separator for this derivation.

As an example, consider a fictional application named Foo that implements sigma protocols over elliptic curves for encrypted messages shared during a time epoch `tttt`. A reasonable choice of tag is:

~~~
FOO-SV{xx}-{tttt}-DSFS-{hashID}-SIGMA-PROOFS-{yy}
~~~

where `xx` is the two-digit number indicating the version, `yy` is the two-digit number indicating the elliptic-curve ciphersuite, `hashID` is the hash identifier, and `tttt` is the epoch number written in decimal US-ASCII digits.

As another example, consider a fictional application named Bar that implements an ad-hoc zero-knowledge virtual machine for correct execution of circuits. A reasonable choice of tag is:

~~~
BAR-COM{cc}
~~~

where `{cc}` is the commit hash of the associated version of the cryptographic specification of the protocol.

Yet another reasonable choice for the tag is to append a description of the interactive argument system together with the length of each prover and verifier message, after the version string. For instance:

~~~
BAZ-SV{xx}-DSFS-{hashID}-sumcheck-{ff}-A2round-messageS1challenge
~~~

where `xx` is the two-digit version number, `hashID` is the hash identifier, and `ff` is the two-digit identifier of the finite field over which the proof is computed. The suffix `A2round-messageS1challenge` describes one sumcheck round where the prover absorbs (`A`) two field elements `round-message`, and the verifier squeezes (`S`) one field element `challenge`. This is similar to the SAFE API {{SAFE}} *IO pattern*.

## Instance

The prover and verifier **MUST** absorb `encode[0](instance)`, where `encode[0]` is the first encoding map. The encoded instance **MUST** be non-empty. While the session identifier of the previous section {{session-id}} fixes the language, the instance selects one of its members.

As for every encoding map, `encode[0]` **MUST** be prefix-free, else a malicious prover may be able to produce valid NARG strings on statements it cannot prove (see {{codecs}}). The encoding map `encode[0]` **SHOULD** reuse the serialization functions of {{serialization}}.

As an example, consider the sumcheck relation for multilinear polynomials in `N` variables over the field of size `p^m`. For a polynomial committed using the polynomial commitment scheme `COM`, the relation consists of:

- instance `(S, C)`: `C` the commitment, and `S` the target sum;
- witness `(F, r)`: `F` is the multilinear polynomial in `N` variables, and `r` is the commitment opening information.

such that:

~~~
COM.Open(C, F, r)  = 1,
sum(F(b1, ..., bN) for (b1, ..., bN) in {0, 1}^N) = S
~~~

A valid instance encoding function is:

~~~
SerializeField(S, p, m) || SerializeUint(N, 2^32) || COM.Serialize(C)
~~~

where `COM.Serialize` is the commitment-serialization function of the scheme `COM` (the opening check `COM.Open` is used above).

As another example, consider, in the discrete logarithm setting, the Chaum-Pedersen relation over an additive elliptic curve group with generators `G`, `H` (for which the relative discrete logarithm is not known). The relation consists of:

- the instance `(C, D)`, a pair of Pedersen commitments;
- the witness `(x, r, s)`, scalar field elements with `x` the commitment message and `r`, `s` independent random commitment openings

such that

~~~
C = xG + rH, D = xG + sH.
~~~

A valid instance encoding function is:

~~~
enc(G) || enc(H) || enc(C) || enc(D)
~~~

where `enc` is the group element-serialization function described in {{serialize-ec-point}}.

Omitting public statement data from the transformation, such as `N` in the first example or the group generators `G`, `H` in the second, can compromise soundness of the proof system. See {{instance-encoding}}.

# Non-interactive argument string {#narg-string}

Serialization and deserialization **MUST** satisfy the following security requirements:

1. Deserialization inverts serialization and fails on any byte string that is not the serialization of a valid value.
2. Each value has a unique serialization. Accepting more than one serialization of a value makes proofs malleable.
3. Deserialization enforces every validity condition of the value's type: for example, an elliptic-curve point lies in the prime-order subgroup, and an integer or field element is in its canonical range.
4. Deserialization fails gracefully on inputs. Lengths and counts read from the NARG string are untrusted and checked before being used for indexing, allocation, or arithmetic.
5. If any trailing bytes remain in the input after deserializing the last prover message, verification fails; otherwise, proofs are malleable.

## Serialization {#serialization}

The NARG string is the concatenation of the serialization of each prover message, as defined below.

### Byte strings {#serialize-byte-strings}

Serialization of an `N`-byte string is the identity function.

~~~
SerializeBytes(s)

Input: s, an N-byte string

Output: out, an N-byte string

1. return s
~~~

`SerializeBytes` carries no length information of its own. It **MUST NOT** be used unless `N` is fixed by the message's type and the instance, so that prover and verifier agree on `N` before the NARG string is parsed (see {{deserialize-byte-strings}}). On such a fixed-length domain the identity is prefix-free, as required of encodings by {{codecs}}.

Otherwise, when the length is below 2^32 bytes, a prefix-free serialization is given by

~~~
SerializeVarLenString(s)

Input: s, an N-byte string

Output: out, an (N+4)-byte string

1. return LE(len(s), 4) || s
~~~

### Sequences and tuples

A fixed-length array or a tuple is serialized as the concatenation of the serializations of its elements, with no separators.

### Unsigned integers {#serialize-uint}

An integer modulo `M` is represented by its unique integer representative in the range `[0, M)` and serialized via `LE`.

~~~
SerializeUint(x, M)

Inputs:

- x, an integer modulo M
- M, the modulus

Output: out, an Ns-byte string

1. assert 0 <= x < M
2. return LE(x, Ns)
~~~

### Field elements {#serialize-field}

This section specifies the _default_ serialization of a finite field of order `p^m`, where `p` is the prime characteristic and `m >= 1` is the extension degree.

The choice of field serialization **MUST** be reflected in the session tag (see {{session-id}}). The field serialization function **MUST** be prefix-free. The default is the serialization specified below, which encodes each prime-field coordinate as a fixed-width little-endian integer via `SerializeUint` ({{serialize-uint}}); if the standard the application builds on already fixes a canonical serialization for the field, that serialization **SHOULD** be pinned in place of the default.

For example, Curve25519 {{?RFC7748}}, Ed25519 {{?RFC8032}}, ristretto255 {{Section 4.4 of ?RFC9496}} serialize field elements as a fixed-width little-endian integer, matching the default. Similarly, in Section 7.1 of {{FIPS204}}, the integer coordinates of lattice vectors are serialized least-significant-byte first. Other standards instead fix a big-endian serialization, such as P-256 {{SEC1}} and BLS12-381 {{?I-D.irtf-cfrg-pairing-friendly-curves}} via `I2OSP` ({{Section 4.1 of ?RFC8017}}).

With respect to a fixed basis, a field element is represented by its `m` coordinates in the prime field, each an integer in `[0, p)`, and serializes to `m * Ns` bytes, with `Ns` taken for the modulus `p`.

~~~
SerializeField(a, p, m)

Inputs:

- a, an element of the field of order p^m, given by its
     coordinates (a[0], ..., a[m-1]) over the prime field
- p, the prime characteristic of the field
- m, the extension degree

Output: out, an (m * Ns)-byte string

1. out := ""
2. for i in 0, ..., m-1:
3.    out := out || SerializeUint(a[i], p)
4. return out
~~~

Note that a prime field is the case `m = 1`, in which case `SerializeField` is equivalent to `SerializeUint`.

### Elliptic curve group elements {#serialize-ec-point}

A group element is serialized using the group's element-serialization function, into an `Ne`-byte string, where `Ne` is fixed by the group.

For many prime-order elliptic-curve groups, this is the compressed Elliptic-Curve-Point-to-Octet-String conversion of {{SEC1}}. This document alters {{SEC1}} serialization: uncompressed and hybrid encodings are forbidden, so the only accepted initial octets are `0x00`, `0x02`, and `0x03`; the identity is encoded as `Ne` zero octets instead of {{SEC1}}'s single `0x00` octet. Restricting the accepted initial octets guarantees unique serialization. Padding the identity element removes branching from the parsing of the NARG string.

The ristretto255 and decaf448 {{?RFC9496}} encodings of the identity are already fixed-length `Ne`-byte strings.

## Deserialization

Deserialization of the NARG string consists of reading the prover messages: each message is read by consuming, from the front of the input, a byte string whose length is determined by its type and the instance. Each deserialization function below returns the decoded value together with the unread remainder of its input; the remainder is the input to the next read.

Verification **MUST** fail if any of the prover messages cannot be deserialized successfully.

### Byte strings {#deserialize-byte-strings}

For an `N`-byte string whose length is known from the message's type and the instance, deserialization reads `N` bytes.

~~~
DeserializeBytes(input, N)

Inputs:

- input, the unread remainder of the NARG string
- N, the expected byte length

Output: an N-byte string, and the unread remainder of input

1. fail if len(input) < N
2. return (input[0 : N], input[N : len(input)])
~~~

`DeserializeBytes` is the inverse of `SerializeBytes` ({{serialize-byte-strings}}), and consumes `N` bytes of the NARG string, and fails if fewer bytes remain.

A byte string whose length is not known in advance is deserialized by reading a 4-byte length `N` via `LE2IP`, then reading the next `N` bytes; this is the inverse of `SerializeVarLenString` ({{serialize-byte-strings}}).

~~~
DeserializeVarLenString(input)

Input: input, the unread remainder of the NARG string

Output: an N-byte string, and the unread remainder of input

1. fail if len(input) < 4
2. N := LE2IP(input[0 : 4])
3. fail if len(input) - 4 < N
4. return (input[4 : 4 + N], input[4 + N : len(input)])
~~~

This consumes `4 + N` bytes of the NARG string, and fails if fewer bytes remain. The value decoded is the resulting byte string.

### Sequences and tuples

Deserialize each element in order. Fail if any element fails to deserialize. The number and types of the elements are fixed by the protocol.

### Unsigned integers

Read the next `Ns` bytes and interpret them as a little-endian integer `x = LE2IP(.)`. If `x >= M`, fail: non-canonical integer encodings **MUST** be rejected. The value returned is `x`. This is the inverse of `SerializeUint` ({{serialize-uint}}).

~~~
DeserializeUint(input, M)

Inputs:

- input, the unread remainder of the NARG string
- M, the modulus

Output: x, an integer in the range [0, M), and the unread
        remainder of input

1. fail if len(input) < Ns
2. x := LE2IP(input[0 : Ns])
3. fail if x >= M
4. return (x, input[Ns : len(input)])
~~~

This consumes `Ns` bytes of the NARG string. It fails if fewer bytes remain, or if the integer read is not in the range `[0, M)`.

### Field elements

A field element of a field of order `p^m` is deserialized coordinate by coordinate: read `m * Ns` bytes and deserialize each `Ns`-byte coordinate as an integer modulo `p` using the unsigned-integer deserialization above. A prime field is the case `m = 1`. This is the inverse of `SerializeField` ({{serialize-field}}).

~~~
DeserializeField(input, p, m)

Inputs:

- input, the unread remainder of the NARG string
- p, the prime characteristic of the field
- m, the extension degree

Output: a, an element of the field of order p^m, given by its
        coordinates (a[0], ..., a[m-1]) over the prime field, and
        the unread remainder of input

1. for i in 0, ..., m-1:
2.    (a[i], input) := DeserializeUint(input, p)
3. return ((a[0], ..., a[m-1]), input)
~~~

This consumes `m * Ns` bytes of the NARG string, and fails if fewer bytes remain or if any coordinate is non-canonical.

The deserialization **MUST** match the pinned serialization ({{serialize-field}}): where the application pins a standard's own serialization, that standard's deserialization governs.

### Elliptic-curve group elements

Read the next `Ne` bytes and convert them to a group element using the group's element-deserialization function.

# Efficiency considerations {#efficiency}

`Init(session_id)` (see {{interface}}) can be precomputed. Implementations can therefore start each prover and verifier execution from a copy of the duplex sponge state, instead of initializing it every time. In the XOF duplex sponge ({{xof-duplex-sponge}}), the padded session identifier fills exactly one rate block ({{xof-init}}), saving one invocation of the permutation function per execution. Similarly, `DeriveSessionID` can be precomputed when the session identifier is derived from a tag. The same observation extends to longer shared prefixes: proofs for the same instance can additionally start from a stored copy of the state obtained after absorbing `encode[0](instance)`.

Prefer batch algorithms for codecs and serialization when available. For example, Montgomery’s trick lets point compression share one modular inversion across a batch.

# Security considerations

## Codecs {#sec-codecs}

Encoding maps are inverted only in the security analysis, never by the prover or verifier: the knowledge-soundness extractor relies on an efficiently computable left inverse to recover prover messages from the absorbed bytes {{CO25}}.

Decoding preserves the uniform distribution only when its input is uniform. Verifier messages **SHOULD** therefore be derived from `Squeeze` output and never from prover-controlled, or non-uniform bytes: decoding a non-uniform input yields a verifier message that is distinguishable from uniform, which would break the public-coin property the transformation depends on.

## Constant-time requirements {#constant-time}

Constant-time implementation of all functions in this document is **RECOMMENDED** to prevent side-channel leakage. Public-coin protocols can still process private instances, including private verification keys or messages shared only between prover and verifier. For example, in keyed-verification anonymous credentials, the verifier computes an instance that depends on the issuer's secret key.

## Session identifiers {#sec-session-identifiers}

The purpose of session identifiers is to ensure composability and mitigate protocol confusion.

A session identifier **MAY** be reused, and reuse is expected whenever several proofs share the same application context: the identifier names that context, and identical contexts are meant to share one.

## Security of the transformation {#sec-transformation}

The Fiat-Shamir transformation carries over the soundness and zero-knowledge properties of the interactive proof. The random oracle instantiation **MUST** be extraction-friendly and simulation-friendly indifferentiable to preserve soundness and zero-knowledge of the transformation. Both properties are stronger than indifferentiability alone {{CO25}}.

Completeness of the non-interactive argument is preserved: if the statement being proven is true, then the resulting non-interactive argument string is valid.

### Knowledge soundness

If the interactive proof is state-restoration knowledge sound, then so is the non-interactive proof, with a loss quadratic in the number of queries the adversary makes to the random oracle {{CO25}}. In particular, valid proofs cannot be generated without the corresponding statement being true (in the random oracle model).

### Zero-Knowledge

If the interactive proof is honest-verifier zero-knowledge, then so is the non-interactive proof. In particular, the resulting argument string does not reveal any information beyond what can be directly inferred from the statement being valid.

The additive zero-knowledge loss introduced by the transformation is linear in the number of queries the adversary makes to the random oracle {{CO25}}.

Zero-knowledge holds only when the prover's random number generator is indistinguishable from fresh uniform randomness to any party that does not know the witness. Reusing the same randomness (or correlated randomness) across two distinct proofs will compromise zero-knowledge: for example, two Schnorr proofs sharing the same commitment nonce reveal the witness. This can be obtained by relying on a cryptographically secure random number generator meeting the requirements of {{?RFC4086}} (for example, the operating system's `getrandom(2)` interface), or by deriving it with a pseudorandom function.

### Quantum adversaries

If the interactive proof is state-restoration sound against quantum adversaries, then the non-interactive proof after the Fiat-Shamir transformation in the random oracle model is also secure against quantum adversaries.

The loss introduced by a quantum adversary is polynomial (larger than quadratic) in the number of quantum random-oracle queries.

## Instance encoding

Incorrect encoding of the instance has historically led to a number of critical security vulnerabilities, often grouped under the term *weak Fiat-Shamir transformation*. In each of them, the cryptographic hash function was not provided the full statement being proven. A malicious prover can then compute the verifier message first, and choose the omitted part of the instance afterwards so that the verification equation is satisfied on a statement whose witness it does not hold.

As an example {{BPW16}}, a Chaum-Pedersen proof of equality for an instance `(G, H, X, Y)` proves knowledge of a witness `x` such that `X = x * G` and `Y = x * H`. The prover sends commitments `(A, B)`, obtains a challenge `c`, and replies with a scalar `f`. The verifier accepts if the verification equations hold: `f * G == A + c * X` and `f * H == B + c * Y`. Suppose the challenge `c` is derived only by absorbing `(A, B)` and omitting the instance `(G, H, X, Y)`. A malicious prover can pick `A`, `B`, `H`, and `f` at random, derive `c`, and then set `X` and `Y` to satisfy the verification equations. Verification passes, yet no single `x` satisfies both `X = x * G` and `Y = x * H`. A false statement has been proven. Other examples are available in {{DMWG23}} {{CVE-2022-29566}}.

The transformation does not itself validate the instance. The verifier **MUST** therefore validate the syntax of the instance before use, exactly as it validates prover messages during deserialization ({{deserialization}}): for example, checking that each claimed group element lies in the prime-order group, and that integers are in canonical range.

Completeness and zero-knowledge are guaranteed only for valid instances: if the prover is invoked on an instance-witness pair outside the relation, no guarantee is provided on its output.

## Implementation guidance {#implementation-guidance}

Absorb each prover message in the same function call that writes it to, or reads it from, the NARG string. This keeps hashing and serialization synchronized and helps prevent omitted or reordered messages, which have caused implementation vulnerabilities {{GNARK-KZG}} {{CVE-2024-45039}} {{CVE-2026-46654}}. Prefer the byte-level interface described in this document over proof data structures whose fields are randomly addressable.

Test vectors can help confirm that honestly-generated proofs verify, but such tests exercise only completeness. Negative testing will help exercise the rejection paths too. Some such examples are: tampering with a valid NARG string to cause verification to fail, by flipping, appending, or prepending bytes, and by replacing each prover message in turn with a different value.

The NARG string is untrusted input ({{narg-string}}). For example, in {{deserialize-byte-strings}} the 4-byte length prefix read by `LE2IP` in `DeserializeVarLenString` is attacker-controlled, and can be as large as `2^32 - 1`, so computing `4 + N` can overflow 32-bit integers. As another example, a crafted length indicator can make verification checks trivial, or exhaust memory on deserialization before any cryptographic check runs {{GNARK-OOM}}.

# Suites {#suites}

The suites defined by this document, and the identifiers used by the test vectors, are:

| Identifier | XOF(M, L) | R | Alphabet |
|---|---|---|---|
| `SHAKE128` | SHAKE128(M, 8 * L) {{SHA3}} | 168 | bytes |
| `TurboSHAKE128` | TurboSHAKE128(M, 0x1F, L) {{!RFC9861}} | 168 | bytes |
{: #tab-suites title="Duplex sponge suites"}

The suite identifier is a natural component of the `tag` ({{session-id}}), since it fixes the hash instantiation.

## SHAKE128 {#suite-shake128}

In the SHA-3 family, two XOFs, SHAKE128 and SHAKE256, are defined over the Keccak-f permutation; SHAKE(M, n) outputs an n-bit string. The corresponding collision and second-preimage-resistance for SHAKE128 are min(n/2,128) and min(n,128) bits, respectively (see Appendix A.1 of {{SHA3}}). This instantiation targets 128-bit security. The SHAKE128 state is a 200-byte (1600-bit) string, with a capacity of 32 bytes (256 bits).

## TurboSHAKE128 {#suite-turboshake128}

TurboSHAKE128 {{!RFC9861}} is an XOF built on Keccak-p\[1600, 12\], the Keccak-f\[1600\] permutation reduced to its last 12 rounds. Its state is a 200-byte (1600-bit) string, with a capacity of 32 bytes (256 bits). The corresponding collision and second-preimage-resistance are min(n/2,128) and min(n,128) bits for an n-bit output string, respectively. This instantiation targets 128-bit security. The domain-separation byte is fixed to its default value `D = 0x1F`.

# IANA Considerations

This document has no IANA actions.

# Acknowledgments
{:numbered="false"}

The authors thank Thomas Pornin, Vishruti Ganesh, Brent Zundel, Hart Montgomery, Opal Wright, Giap Vu, David Wong, Théophile Wallez, and Thomas Coratger for their reviews and contributions to this specification.

--- back

# Example protocol: sumcheck {#example-sumcheck}

This appendix describes the Fiat-Shamir transformation for the sumcheck protocol. This protocol is not meant for standalone use; it is a toy example where the verifier's final check would still require the evaluation `y = f(r[1], ..., r[v])`, which is normally obtained via a polynomial commitment scheme opening.

The protocol is parameterized by a prime `p` and a number of variables `v`. The witness is the table `w` of the `2^v` evaluations of a multilinear polynomial `f` on the hypercube: entry `w[j]` is `f(j_0, ..., j_{v-1})`, where `j_0` is the least-significant bit of `j`. The instance is `(v, S)`: the number of variables and the claimed sum `S` of all table entries. The application context is bound through the session identifier ({{session-id}}). All field arithmetic below is modulo `p`.

In each round the prover message is the coefficient pair `(a0, a1)` of the round polynomial `g(X) = a0 + a1 * X` of the lowest unbound variable: `g(0)` and `g(1)` are the even- and odd-indexed half-sums of the table. Each verifier message is one field element, decoded from `Ns` squeezed bytes as `LE2IP(Squeeze(Ns)) mod p`. (For the Mersenne31 instantiation below, the bias of the reduction is approximately `2^-31`, less than the soundness error of the interactive argument.)

~~~
SumcheckProve(session_id, v, w)

Inputs:

- session_id, a 32-byte string
- v, the number of variables
- w, a table of 2^v field elements

Outputs: narg_string; y, the final folded evaluation
f(r[1], ..., r[v])

 1. S := w[0] + w[1] + ... + w[2^v - 1]
 2. state := Init(session_id)
 3. state.Absorb(SerializeUint(v, 2^32) || SerializeField(S, p, 1))
 4. narg_string := ""
 5. for i in 1, ..., v:
 6.    a0 := w[0] + w[2] + ... + w[len(w) - 2]
 7.    a1 := (w[1] + w[3] + ... + w[len(w) - 1]) - a0
 8.    msg := SerializeField((a0, a1), p, 2)
 9.    state.Absorb(msg)
10.    narg_string := narg_string || msg
11.    r := LE2IP(state.Squeeze(Ns)) mod p
12.    w := (w[0] + r * (w[1] - w[0]), w[2] + r * (w[3] - w[2]), ...)
13. return (narg_string, w[0])
~~~

After `v` rounds the single remaining entry `w[0]` is `f(r[1], ..., r[v])`, where `r[i]` is the verifier message of round `i`. The NARG string is the concatenation of the round messages.

~~~
SumcheckVerify(session_id, v, S, narg_string, y)

Inputs:

- session_id, v, as in SumcheckProve
- S, the claimed sum
- narg_string, the NARG string
- y, the evaluation f(r[1], ..., r[v]), supplied by the caller

Output: accept or reject

 1. state := Init(session_id)
 2. state.Absorb(SerializeUint(v, 2^32) || SerializeField(S, p, 1))
 3. for i in 1, ..., v:
 4.    ((a0, a1), narg_string) := DeserializeField(narg_string, p, 2)
 5.    fail if 2 * a0 + a1 != S
 6.    state.Absorb(SerializeField((a0, a1), p, 2))
 7.    r := LE2IP(state.Squeeze(Ns)) mod p
 8.    S := a0 + a1 * r
 9. fail if narg_string != ""
10. fail if S != y
11. return accept
~~~

The test vectors ({{tv-narg}}) instantiate `p = 2^31 - 1`, `v = 4`, and the witness `w = (1, 2, 4, ..., 2^15)`, giving `S = 65535`. They report the NARG string as `NargString` and `f(r[1], ..., r[v])` as `FinalEvaluation`.

# Test Vectors {#test-vectors}

Each test vector in this section is a block of lines of the form `Key = Value`, with no repeated keys. A value is written inline or on indented lines below its key; wrapped lines are concatenated without a separator. A sequence has one item per line, introduced by `- `, and an item's continuation lines carry a further two spaces of indentation. Every vector carries `Id`, a stable name of the form `fiat-shamir/<section>/<vector>` by which this document and a test harness refer to it, and `Function`, the operation the remaining keys describe. The suite ({{suites}}) is identified with the key `Suite`. A vector without `Suite` has the same outcome under every suite. The key `ByteOrder` marks the vectors exercising a non-default serialization ({{serialize-field}}). A vector carrying `Expected` is a verifier decision, `accept` or `reject`. The prose accompanying each rejected vector states which check fails. Each key has a value of one of the following kinds:

- an integer, written in decimal or in hexadecimal with the prefix `0x`;
- a byte string, written in lowercase hexadecimal. The empty byte string is denoted `""`;
- a name (for `Id`, `Function`, `Suite`, or `Expected`);
- a sequence of values (one item per line, each introduced by `- `), including the duplex sponge operations described in {{tv-duplex-sponge}}.

A copy of the test vectors below is provided in JSON format as part of this specification's repo.

## Duplex sponge {#tv-duplex-sponge}

Each `Operations` item is either `absorb` followed by a byte string, or `squeeze` followed by a number of bytes. Each vector runs the operations in order after initializing the state with `SessionId`. `Output` is the concatenation of all squeezed bytes, written as two hexadecimal characters per byte.

### SHAKE128 {#tv-duplex-shake128}

Squeeze 32 bytes right after initialization.

~~~
Id = fiat-shamir/duplex-sponge/shake128/init_squeeze
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - squeeze 32
Output =
  63e1b3543377fab6fb8cf0f7698a9980ca0211d5bc4aba213dd7a6ef7dd63cfa
~~~

Absorb the byte string `hello world`, then squeeze 64 bytes.

~~~
Id = fiat-shamir/duplex-sponge/shake128/absorb_squeeze
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 68656c6c6f20776f726c64
  - squeeze 64
Output =
  f627ff348dfee50d2aa5918a2621a0c1daf74c7ef930d49b5ea6eae73455e8c7
  56d433cbde0ade711bdd55d7ed5de38bb9adea8b2eec4402a0df090c16371413
~~~

Absorb `ab`, then `c`, then squeeze 32 bytes. Absorbs insert no separator, so the output is that of absorbing `abc` in one call.

~~~
Id = fiat-shamir/duplex-sponge/shake128/absorb_split
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 6162
  - absorb 63
  - squeeze 32
Output =
  a629c32a309dda7605798fd07ce20ab14c76635446868eb46e20b6dfd1dd9e41
~~~

Absorb `abc`, squeeze 32 bytes, absorb the empty string, and squeeze 32 more bytes. Absorbing the empty string leaves the state unchanged, so the second squeeze continues the output stream of the first. The 64-byte output begins with the 32-byte output of the previous vector.

~~~
Id = fiat-shamir/duplex-sponge/shake128/empty_absorb
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 616263
  - squeeze 32
  - absorb ""
  - squeeze 32
Output =
  a629c32a309dda7605798fd07ce20ab14c76635446868eb46e20b6dfd1dd9e41
  d88e36c20e053248b90967a90051ba319688a10783c2ce174602eccc02e8d1a6
~~~

Interleave non-empty absorbs and squeezes. A non-empty absorb after a squeeze restarts the output stream over all the input absorbed so far.

~~~
Id = fiat-shamir/duplex-sponge/shake128/interleave
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 00010203040506070809
  - squeeze 16
  - absorb 6d6f72652064617461
  - squeeze 16
Output =
  2da3c7e3a65c6e92901e8b668c43917eb9f02e9988e66d5ce2fbd833a0ecb93e
~~~

Absorb a 600-byte string, longer than the rate `R = 168`, then squeeze 600 bytes:

~~~
Id = fiat-shamir/duplex-sponge/shake128/multiblock
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb ababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    bababababababababababababababababababababababababab
  - squeeze 600
Output =
  d0dc63443a117b76b09845af3347a6dbc29d0ff381ad093e3cfea3a326abbd0d
  a81bfc7dd6220f785900a6d04d508439cc65107c8eb75909f277a6f2740ae55f
  c684b851b66662c22252b6bb8028b5f7402b0beafb391835613a6c3d8116323d
  bdcb4494a198ae886821fca3d2af345227ea06c5c2cdb131c90d3fe58eedf090
  a55bb5a8edc614ab99da6c4ed8fe95a6c289c18dc61918a9abaa4f3ed2358711
  7ced29b33bfb87351d4ffc562add96d384fffbcb7cfb4d4d2125bf809cb85b33
  a3f9b7541c5d3d3f435f7d0a837f92f6878276ca3c833ecc1691f923602e9b8c
  8adb9528d8857d7189384eabbab50f0706b82b53db1c92857c2aa84a3527ce4b
  fcfbdbe02ad953b8517c4b91d36b45f81df67e10e4e9a7c7c064aa9e7f593710
  10eab4fd71c7aebcf00a793e469a78c658dd9f2c1d5ed2e3110939c11e916c1f
  51c47553b1bbceeea92649c9bcc7e5538dab18ca95c298b540b6798c065cd2b4
  13fe3915534a5dc6e7100e012b8c53fccc1018cc24570ca09c8e1c8f6e4e523d
  db7b6dcf313b6e98bb4abc94b8063eac8fdbbce945c35dd021a91e8227aeb165
  02a5a6e9e1d85fbd13b6e1e523e8a24040bbb9ddab5e29315780a57d9ef0d758
  b66e0076704f456dec1fc11577fe3644e53ff70a99a912758c289f225ad64e24
  6af9d895d91e6972b18421ccaa2aed6f843870b9dda07d1e975e51c04d58e7ba
  d60c0b8934fec80d4468816793879bc34d831e2689b77525439837fd15f797ed
  3b78ccdfdec6a5574111de3e243464c77c1d7fa76fb170e3722315e70fbf855a
  33281e8b6c15029202d0bb34749b962cc314515c748b74f4
~~~

Test across the rate boundary: absorb exactly one rate block (`R = 168` bytes), then squeeze 167 bytes and 2 bytes.

~~~
Id = fiat-shamir/duplex-sponge/shake128/rate_block
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1
    e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4
    04142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616
    2636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838
    485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a
    6a7
  - squeeze 167
  - squeeze 2
Output =
  edae25852c909e4acea18d96ddd407e475eeaa7070ff591b49450c7a3ed21b7d
  0bd0ee62ab0c242e636c435b37c38ae6804a179ff434bed773c8d596cd66b928
  b0429247b19cbfc246bb1abd3b741841b21ad0234ba7738abe64ab93914bf5ad
  58a362d86f64d72b8f8603a888421a29769bb77579185409013a271ac258cd71
  a71aedf2801ba6eb4784636e9bfacca229a78aa8dc72af770380a1a981120b37
  16595564c520292578
~~~

A zero-length squeeze is a no-op. Absorb `abc`, squeeze 0 bytes, absorb `def`, and squeeze 32 bytes. The output is that of absorbing `abcdef` and squeezing 32 bytes.

~~~
Id = fiat-shamir/duplex-sponge/shake128/squeeze_zero
Function = DuplexSponge
Suite = SHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 616263
  - squeeze 0
  - absorb 646566
  - squeeze 32
Output =
  fc876a5ffbdc960106af16ca50e3b17b14a172f985f3a6f5df09c9a649ebf588
~~~

### TurboSHAKE128 {#tv-duplex-turboshake128}

Squeeze 32 bytes right after initialization.

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/init_squeeze
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - squeeze 32
Output =
  7ad8a3af35a3083c055e4a953ff001cdd9eeb1198f4be7a3a9ec5a209434619b
~~~

Absorb the byte string `hello world`, then squeeze 64 bytes.

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/absorb_squeeze
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 68656c6c6f20776f726c64
  - squeeze 64
Output =
  8b804d7a8c524c242a94e86f7ddfec329d90e29c1f584a98812e63029a0bdb07
  5b12c545bf9e2aa17c88673b6d9df4b08e728dc47f7d7094cee59a0d7d989634
~~~

Absorb `ab`, then `c`, then squeeze 32 bytes. Absorbs insert no separator, so the output is that of absorbing `abc` in one call.

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/absorb_split
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 6162
  - absorb 63
  - squeeze 32
Output =
  51acee1ee6f0c6a0c5a33b625ac9eaea54bc6b9b1cb85f9b2ef843e73631792e
~~~

Absorb `abc`, squeeze 32 bytes, absorb the empty string, and squeeze 32 more bytes. Absorbing the empty string leaves the state unchanged, so the second squeeze continues the output stream of the first. The 64-byte output begins with the 32-byte output of the previous vector.

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/empty_absorb
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 616263
  - squeeze 32
  - absorb ""
  - squeeze 32
Output =
  51acee1ee6f0c6a0c5a33b625ac9eaea54bc6b9b1cb85f9b2ef843e73631792e
  599e1dfb1bf60638046f82f5bfa28bcfcabf1404b200647d184ead03e51fbf01
~~~

Interleave non-empty absorbs and squeezes. A non-empty absorb after a squeeze restarts the output stream over all the input absorbed so far.

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/interleave
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 00010203040506070809
  - squeeze 16
  - absorb 6d6f72652064617461
  - squeeze 16
Output =
  f2745534347564bed146c95655122f14636bcc58f768296be8494208db29b6be
~~~

Absorb a 600-byte string, longer than the rate `R = 168`, then squeeze 600 bytes:

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/multiblock
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb ababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    babababababababababababababababababababababababababababababababababa
    bababababababababababababababababababababababababab
  - squeeze 600
Output =
  0ef6787d725638e19364c25a2ba879af55a4e1c97bff52919e64cd37a218db44
  a475f9d7ef0e88d87b443fe6590f12fc90c41c546c92cbeb3480e679d6e1ea37
  fc1e10e3e41b15e80aea4745ad9ad31c22857ae360fb66848daab7df8f6135ef
  cc940c4cc6431617cca6c05aa9b8bdf041538206ef912c0861dc07e219875509
  24c848cb788532637cf6e7fb1a3ea233fc335077e4910e8d7da15fe89250f284
  58ec17ecf448e05cf660ca4ffd1fdcb4379570d3a871aa759bb4d763d60d3e1b
  36ab8efcd8cd6fcca8fa67a5071ab21a1d31e4610f7ca8825b5e81f22433c495
  862b642c009823c312fd60fcdcd888af9c6c554da3a370946fa7bfa66ac54480
  b9a36d73fa6ee73ccb78b425de22814667742864608a06fa7534b053a68905ff
  532089b6fc0d597671ae4da685b96b1ac5d2513c0fc944d11155ed43461559a1
  2b984fb0cb45b105d9f2391a137d104f7da6c82fcfe375143bf512824685913f
  2bf61613b1a2a8f55f86d1282aa36c02384381335927259361c9e5875dbe1314
  af82aa65264ff009f525d4f0aedcf80cb908e308132113311d0e9a6783f27a13
  93ae28c10914018e263020dc97f219ebdae4118a79c318bef2d3766452075e35
  79f4b1cddbb80a5bca83a2f1fbec44e9d487925ba23cbfce111ba865e0fdb164
  589c66cbb757865d1bfb4540c01dece5b4180eef4262efc24c4ae3f76c4497a5
  3fb7f38a0de18a7053ab59b59b180ad53e3d2318661783682298d54b9f9ee6e3
  3b2be660295ccdd7d6cc976e21827c66880a0fbcc202743cd1ea0b7351755ee4
  b8a0b140bbc4f6a45eb6b05798721094cebe00e08f4f7bde
~~~

Test across the rate boundary: absorb exactly one rate block (`R = 168` bytes), then squeeze 167 bytes and 2 bytes.

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/rate_block
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1
    e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4
    04142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616
    2636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838
    485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a
    6a7
  - squeeze 167
  - squeeze 2
Output =
  dc4b6f89697ec7e56ad210e6244a3ff25dab91ebd60981761db8f83db3a3a781
  ab43ffd7f325c98b912746b65d233fb5b99fd923cbff5e327b75436afd035c42
  ac9953ca4d686e30e5729aa460b813adf96c16917471679a4de36b19c452aef4
  47f93f4574ddcf09bdf6410774b426ffe415ff8eb2be44c8301ae071b534895b
  0ab66aa0136ffe9656c607bb6e1acaea4069454e297ec0ad4eab437c25455c88
  aeb77d6f33f7b578e9
~~~

A zero-length squeeze is a no-op. Absorb `abc`, squeeze 0 bytes, absorb `def`, and squeeze 32 bytes. The output is that of absorbing `abcdef` and squeezing 32 bytes.

~~~
Id = fiat-shamir/duplex-sponge/turboshake128/squeeze_zero
Function = DuplexSponge
Suite = TurboSHAKE128
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 616263
  - squeeze 0
  - absorb 646566
  - squeeze 32
Output =
  61d3fecc576c3faafb92db1cb22b60794075a024df9626436394c7b852ade899
~~~

## Session identifier derivation {#tv-session-id}

Derive the session identifier of the application tag `interop-test-v00` ({{session-id}}).

~~~
Id = fiat-shamir/session-id/shake128/derive_sid
Function = DeriveSessionID
Suite = SHAKE128
Tag = 696e7465726f702d746573742d763030
SessionId =
  b508aca89eecac56cd33e4a28f817f43f849d035922f354173ae8466628308cf
~~~

Derive the session identifier of the application tag `interop-test-v00` ({{session-id}}).

~~~
Id = fiat-shamir/session-id/turboshake128/derive_sid
Function = DeriveSessionID
Suite = TurboSHAKE128
Tag = 696e7465726f702d746573742d763030
SessionId =
  4326208c9e56ae847be9356ca7c4447c752a9d7326a44a6cbee0c0dfc69505ac
~~~

## Codecs {#tv-codec}

This section contains vectors for decoding verifier messages ({{decoding}}).
The encoding of a prover message is its serialization ({{encoding-bytes}}), covered in {{tv-serialization}}.

Decoding is infallible and reduces modulo `M` ({{decoding-uint}}): the `Ns + 16 = 48`-byte little-endian encoding of `M` itself, the order of the P-256 group, decodes to 0. Deserialization instead rejects non-canonical integers ({{tv-serialization-invalid}}).

~~~
Id = fiat-shamir/codec/decode_uint_wraparound
Function = DecodeUint
Modulus =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325
  51
Input =
  512563fcc2cab9f3849e17a7adfae6bcffffffffffffffff00000000ffffffff
  00000000000000000000000000000000
VerifierMessage = 0x00
~~~

Absorb the instance `instance`, serialized as a variable-length byte string, then squeeze `Ns + 16 = 48` bytes and decode them into a scalar of P-256 ({{decoding-uint}}).

~~~
Id = fiat-shamir/codec/shake128/decode_uint
Function = DecodeUint
Suite = SHAKE128
Modulus =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325
  51
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 08000000696e7374616e6365
  - squeeze 48
Output =
  7124d02b7cdfec99c4033dfd05624cfe2ff3af2c0e71656f770e676bd36de622
  8f85fcb39f34f7bfc24c9f54ab35ddba
VerifierMessage =
  0xf860997c65f8dabecbcc3459a7b89bf69301b19fa1a0e036eb0d132724436d
  4f
~~~

Absorb the instance `instance`, serialized as a variable-length byte string, then squeeze `Ns + 16 = 48` bytes and decode them into a scalar of P-256 ({{decoding-uint}}).

~~~
Id = fiat-shamir/codec/turboshake128/decode_uint
Function = DecodeUint
Suite = TurboSHAKE128
Modulus =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325
  51
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Operations =
  - absorb 08000000696e7374616e6365
  - squeeze 48
Output =
  82a031e31b103ac01253ba3aae215f650a06a4bb24963a05ee1f8c0b82eae90d
  7bd36ea8cb560a91604ae8a97eb0d564
VerifierMessage =
  0xc2088b455016d0126fcdd76335a79566e7fd8379db1de019871d459bfee955
  8b
~~~

## Serialization and deserialization {#tv-serialization}

This section contains vectors for the serialization and deserialization of prover messages ({{narg-string}}). They do not depend on the suite. A conformant deserializer **MUST** reject the invalid inputs.

### Valid inputs {#tv-serialization-valid}

Serialize the byte string `proof` as a variable-length string: its length in 4 little-endian bytes, then its bytes ({{serialize-byte-strings}}).

~~~
Id = fiat-shamir/serialization/serialize_varlen
Function = SerializeVarLenString
Input = 70726f6f66
Output = 0500000070726f6f66
~~~

The serialization of the empty byte string as a variable-length string contains only the length prefix.

~~~
Id = fiat-shamir/serialization/serialize_varlen_empty
Function = SerializeVarLenString
Input = ""
Output = 00000000
~~~

Serialize the integer `0xdeadbeef` modulo `p = 2^256 - 189` in `Ns = 32` little-endian bytes ({{serialize-uint}}).

~~~
Id = fiat-shamir/serialization/serialize_uint
Function = SerializeUint
Modulus =
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  43
Value = 0xdeadbeef
Output =
  efbeadde00000000000000000000000000000000000000000000000000000000
~~~

Serialize `0xdeadbeef` as an element of the scalar field of P-256, whose standard fixes a big-endian serialization (`I2OSP`, {{serialize-field}}).

~~~
Id = fiat-shamir/serialization/serialize_field_be
Function = SerializeField
ByteOrder = big-endian
Modulus =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325
  51
Value = 0xdeadbeef
Output =
  00000000000000000000000000000000000000000000000000000000deadbeef
~~~

### Invalid inputs {#tv-serialization-invalid}

A payload shorter than the length specified by its prefix is rejected ({{deserialize-byte-strings}}).

~~~
Id = fiat-shamir/serialization/deserialize_varlen_reject_truncated
Function = DeserializeVarLenString
Input = 0500000070726f6f
Expected = reject
~~~

The maximal length prefix `2^32 - 1` exceeds the available payload length. The length check must not overflow.

~~~
Id = fiat-shamir/serialization/deserialize_varlen_reject_overflow
Function = DeserializeVarLenString
Input = ffffffffdeadbeef
Expected = reject
~~~

An integer modulo `p` is serialized by its representative in `[0, p)`. The modulus itself is rejected.

~~~
Id = fiat-shamir/serialization/deserialize_uint_reject_modulus
Function = DeserializeUint
Modulus =
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  43
Input =
  43ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Expected = reject
~~~

An integer modulo `p = 2^256 - 189` is serialized in exactly `Ns = 32` bytes. Deserialization rejects inputs with fewer bytes.

~~~
Id = fiat-shamir/serialization/deserialize_uint_reject_short
Function = DeserializeUint
Modulus =
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  43
Input =
  efbeadde000000000000000000000000000000000000000000000000000000
Expected = reject
~~~

Every coordinate of an extension-field element is validated. This degree-2 element is rejected because its second coordinate (`2^256 - 1`) is non-canonical, even though its first coordinate (`p - 1`) is canonical.

~~~
Id = fiat-shamir/serialization/deserialize_field_reject_coordinate
Function = DeserializeField
Modulus =
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  43
ExtensionDegree = 2
Input =
  42ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
Expected = reject
~~~

## NARG strings {#tv-narg}

This section contains NARG strings of the sumcheck protocol of {{example-sumcheck}}, over Mersenne31 (`p = 2^31 - 1`) with `v = 4` variables. Each vector carries the session identifier, the instance (`NumVariables` and `ClaimedSum`), and the NARG string. The valid vectors also carry the witness and the evaluation `y` as `FinalEvaluation`; the adversarial vectors are rejected before the final check (step 10 of `SumcheckVerify`), whatever `y`.

### Valid NARG strings {#tv-narg-valid}

The sumcheck protocol of {{example-sumcheck}} for the witness `w = (1, 2, 4, ..., 2^15)`, with the session identifier derived from the application tag `sumcheck`.

~~~
Id = fiat-shamir/narg/shake128/sumcheck
Function = Sumcheck
Suite = SHAKE128
Modulus = 0x7fffffff
Tag = 73756d636865636b
SessionId =
  0568cefdf774622a3854d82934915fb3e38bc89dc44b6d673fc91b972c886fc2
NumVariables = 4
ClaimedSum = 0xffff
Witness =
  - 1
  - 2
  - 4
  - 8
  - 16
  - 32
  - 64
  - 128
  - 256
  - 512
  - 1024
  - 2048
  - 4096
  - 8192
  - 16384
  - 32768
NargString =
  555500005555000023e362696ba9283c90a3362a74953379afc3b041d3eb126f
FinalEvaluation = 0x3ebfb3b3
Expected = accept
~~~

The sumcheck protocol of {{example-sumcheck}} for the witness `w = (1, 2, 4, ..., 2^15)`, with the session identifier derived from the application tag `sumcheck`.

~~~
Id = fiat-shamir/narg/turboshake128/sumcheck
Function = Sumcheck
Suite = TurboSHAKE128
Modulus = 0x7fffffff
Tag = 73756d636865636b
SessionId =
  abcbcae1f2f90d02b7e6417dbb2ffe162ab00477453eac3ce83d4e7e61000280
NumVariables = 4
ClaimedSum = 0xffff
Witness =
  - 1
  - 2
  - 4
  - 8
  - 16
  - 32
  - 64
  - 128
  - 256
  - 512
  - 1024
  - 2048
  - 4096
  - 8192
  - 16384
  - 32768
NargString =
  55550000555500006ff9a71d4decf758430dfb69f9c6b5359d8ab2744b13d83d
FinalEvaluation = 0x654028db
Expected = accept
~~~

### Adversarial vectors {#tv-narg-invalid}

The coefficient `a0` of the first prover message is serialized as `p + a0`, a non-canonical representative. Deserialization rejects it (step 4 of `SumcheckVerify`), before the first squeeze.

~~~
Id = fiat-shamir/narg/sumcheck/noncanonical_coefficient
Function = Sumcheck
Modulus = 0x7fffffff
SessionId =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
NumVariables = 4
ClaimedSum = 0xffff
NargString =
  5455008055550000b8eefc2728ccf677b7aabd44c1001d074205d5576c3d307d
Expected = reject
~~~

The NARG string carries one trailing zero byte (step 9).

~~~
Id = fiat-shamir/narg/shake128/sumcheck/trailing_bytes
BaseId = fiat-shamir/narg/shake128/sumcheck
Function = Sumcheck
Suite = SHAKE128
Modulus = 0x7fffffff
Tag = 73756d636865636b
SessionId =
  0568cefdf774622a3854d82934915fb3e38bc89dc44b6d673fc91b972c886fc2
NumVariables = 4
ClaimedSum = 0xffff
NargString =
  555500005555000023e362696ba9283c90a3362a74953379afc3b041d3eb126f
  00
Expected = reject
~~~

The NARG string carries one trailing zero byte (step 9).

~~~
Id = fiat-shamir/narg/turboshake128/sumcheck/trailing_bytes
BaseId = fiat-shamir/narg/turboshake128/sumcheck
Function = Sumcheck
Suite = TurboSHAKE128
Modulus = 0x7fffffff
Tag = 73756d636865636b
SessionId =
  abcbcae1f2f90d02b7e6417dbb2ffe162ab00477453eac3ce83d4e7e61000280
NumVariables = 4
ClaimedSum = 0xffff
NargString =
  55550000555500006ff9a71d4decf758430dfb69f9c6b5359d8ab2744b13d83d
  00
Expected = reject
~~~
