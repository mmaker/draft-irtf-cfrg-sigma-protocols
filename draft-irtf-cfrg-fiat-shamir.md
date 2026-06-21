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
    date: 2016
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
  SAFE:
    title: "SAFE: Sponge API for Field Elements"
    target: https://eprint.iacr.org/2023/522
    date: 2023
    author:
      - fullname: "JP Aumasson"
      - fullname: "Dmitry Khovratovich"
      - fullname: "Bart Mennink"
      - fullname: "Porçu Quine"

--- abstract

This document describes the Fiat-Shamir transformation, which allows making a public-coin protocol non-interactive by means of a cryptographic hash function.

It specifies how the hash function is employed, how prover messages are encoded as hash-function input, and how verifier messages are decoded from the hash function's output, as well as the serialization and deserialization of the non-interactive argument string.

--- middle

# Introduction

A public-coin interactive protocol is an exchange of messages between a prover and a verifier in which every verifier message is a uniformly random value sampled independently of the protocol state.

The Fiat-Shamir transformation removes interaction from a public-coin interactive argument by relying on a cryptographic hash function. The non-interactive prover derives each verifier message on its own via a hash function, and serializes the protocol transcript into a *non-interactive argument* (NARG) string. The verifier recomputes the same verifier messages from the NARG string and checks the interactive verifier's decision. The resulting argument is secure in the random oracle model, where the hash function is treated as an ideal random function (see {{indifferentiability-of-the-hash-function}}).

This document describes the duplex sponge Fiat-Shamir transformation, and in particular:

- a non-interactive argument prover (NARG prover), and
- a non-interactive argument verifier (NARG verifier)

The prover is a randomized procedure and generally relies on a cryptographically-secure entropy source; the verifier **SHOULD** be deterministic.

Both the non-interactive prover and verifier rely on:

- a duplex sponge, prescribing how to interact with the cryptographic hash function ({{hash-instantiations}});
- a set of codecs, describing how each prover and verifier message talk to the duplex sponge ({{codecs}});
- a serialization and deserialization procedure for the NARG string produced by the prover ({{narg-string}}).

This document specifies only byte-oriented hash functions, but this transformation generalizes to alphabets other than bytes (for example, prime-field elements); see {{CO25}} for the general construction.

Other types of non-interactive transformations (with and without random oracles) are possible, but outside the scope of this specification.

~~~ aasvg
+--------------------------------------------------------------------------+
| NARG Prover (session_id, instance, witness)                              |
|                                                                          |
|                                                              +------+    |
|  session_id ------------------------------------------------>| Init |    |
|                                                              +------+    |
|                                                                   |      |
|                                                                   v      |
|                                          +------------+      +--------+  |
|  instance ------------------------------>| encode[0]  |----->| Absorb |  |
|  +---------------------+                 +------------+      +--------+  |
|  | Interactive Prover  |                                          |      |
|  |  (instance, witness)|                                          v      |
|  |                     | prover_msg[1]   +------------+      +--------+  |
|  |                     +---------------->| encode[1]  |----->| Absorb |  |
|  |                     |                 +------------+      +--------+  |
|  |                     |                                          |      |
|  |                     |                                          v      |
|  |                     | verifier_msg[1] +------------+      +---------+ |
|  |                     |<----------------| decode[1]  |<-----| Squeeze | |
|  |                     |                 +------------+      +---------+ |
|  |                     |                                          |      |
|  |                     |                                          v      |
|  |                     | prover_msg[2]   +------------+      +--------+  |
|  |                     +---------------->| encode[2]  |----->| Absorb |  |
|  |                     |                 +------------+      +--------+  |
|  |                     |                                          |      |
|  |                     |                                          v      |
|  |                     | verifier_msg[2] +------------+      +---------+ |
|  |                     |<----------------| decode[2]  |<-----| Squeeze | |
|  |                     |                 +------------+      +---------+ |
|  |                     |        .                                 .      |
|  |                     |        .                                 .      |
|  |                     |        .                                 .      |
|  |                     | prover_msg[k-1] +-------------+     +--------+  |
|  |                     +---------------->| encode[k-1] |---->| Absorb |  |
|  |                     |                 +-------------+     +--------+  |
|  |                     |                                          |      |
|  |                     |                                          v      |
|  |                     | verifier_msg[k-1] +-------------+   +---------+ |
|  |                     |<------------------| decode[k-1] |<--| Squeeze | |
|  |                     |                   +-------------+   +---------+ |
|  |                     | prover_msg[k]                                   |
|  |                     +------------------>                              |
|  +---------------------+                                                 |
|                                                                          |
|       narg_string := serialize(prover_msg[..])                           |
+--------------------------------------------------------------------------+
~~~
{: #fig-fiat-shamir-prover title="Non-interactive prover for the Fiat-Shamir transformation"}

~~~ aasvg
+-----------------------------------------------------------------------+
| NARG Verifier V(session_id, instance, narg_string)                    |
|                                                                       |
| 1. prover_msg[..] := deserialize(narg_string)                         |
| 2. derive verifier messages:                                          |
|                                                                       |
|                                     +------+                          |
| session_id ------------------------>| Init |                          |
|                                     +------+                          |
|                                         |                             |
|                                         v                             |
|              +-----------+          +--------+                        |
| instance --->| encode[0] |--------->| Absorb |                        |
|              +-----------+          +--------+                        |
|                                         |                             |
|                                         v                             |
|prover_msg[1] +-----------+          +--------+                        |
|------------->| encode[1] |--------->| Absorb |                        |
|              +-----------+          +--------+                        |
|                                         |                             |
|                                         v                             |
| verifier_msg[1] +-----------+       +---------+                       |
| <---------------| decode[1] |<------| Squeeze |                       |
|                 +-----------+       +---------+                       |
|                                         |                             |
|                                         v                             |
|prover_msg[2] +-----------+          +--------+                        |
|------------->| encode[2] |--------->| Absorb |                        |
|              +-----------+          +--------+                        |
|                                         |                             |
|                                         v                             |
| verifier_msg[2] +-----------+       +---------+                       |
| <---------------| decode[2] |<------| Squeeze |                       |
|                 +-----------+       +---------+                       |
|       .                                 .                             |
|       .                                 .                             |
|       .                                 .                             |
|prover_msg[k]  +-----------+       +--------+                          |
|-------------->| encode[k] |------>| Absorb |                          |
|               +-----------+       +--------+                          |
|                                         |                             |
|                                         v                             |
| verifier_msg[k]   +-----------+   +---------+                         |
| <-----------------| decode[k] |<--| Squeeze |                         |
|                   +-----------+   +---------+                         |
|                                                                       |
| 3. check IP decision:                                                 |
|                                                                       |
| +-------------------------------------------------------------------+ |
| | Interactive Verifier (instance, prover_msg[..], verifier_msg[..]) | |
| +-------------------------------------------------------------------+ |
+-----------------------------------------------------------------------+
~~~
{: #fig-fiat-shamir-verifier title="Non-interactive verifier for the Fiat-Shamir transformation"}

The security guarantees provided by this transformation are described in {{security-considerations}}.

# Terminology and conventions in this document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

The following notation is used throughout this document.

## Bytes and integers

A byte is an 8-bit unsigned integer (an octet), and a **byte string** is a finite sequence of bytes. An `N`-byte string is a byte string of length `N`. The empty byte string is written `""`; `x || y` is the concatenation of the byte strings `x` and `y`. `len(x)` denotes the length in bytes of the byte string `x`. `zeros(N)` denotes the `N`-byte string of zero bytes.

Byte strings are indexed from zero. For integers `0 <= i <= j <= len(x)`, `x[i : j]` denotes the `(j - i)`-byte substring of `x` consisting of the bytes at positions `i, i+1, ..., j-1`. In particular, `x[0 : N]` is the first `N` bytes of `x`, `x[i : i]` is the empty byte string `""`, and `x[0 : len(x)]` is `x` itself.

A byte string `x` is a **prefix** of a byte string `y` if `y == x || z` for some byte string `z` (even empty). An encoding is **prefix-free** if, for any two distinct values, the encoding of one is never a prefix of the encoding of the other. A simple prefix-free encoding of a byte string `b` is `I2OSP(len(b), 4) || b` as described in {{encoding-varlen-string}}.

`I2OSP(n, w)` and `OS2IP(x)` are the primitives defined in Section 4 of {{!RFC8017}}. `I2OSP(n, w)` converts a non-negative integer `n` less than `256^w` into a `w`-byte, big-endian byte string. `OS2IP(x)` converts a byte string `x` into a non-negative integer using the big-endian byte order.

The set of integers between `0` and `N-1` is denoted `[0, N)`.

## Duplex sponge interface

The Fiat-Shamir transformation is built on a cryptographic hash function, modeled as a random oracle. Rather than computing a single fixed-length digest, this document uses the hash function through a stateful interface called a **duplex sponge** (defined in {{hash-instantiations}}), which `Absorb`s prover messages into an evolving internal state and `Squeeze`s from that state the bytes from which verifier challenges are derived.

The interface generalizes the **sponge** {{SPONGE}}, which maps a variable-length input to a variable-length output by absorbing all of its input and then squeezing all of its output, to the **duplex** setting {{DUPLEX}}, in which absorbing and squeezing may be arbitrarily interleaved over a single retained state. The state is split into a **rate**, the portion through which bytes are absorbed and squeezed, and a **capacity**, which is never read or written directly and whose size sets the security level. Security relies on the capacity. The properties a concrete instantiation must satisfy for this to hold, and the resulting security loss, are given in {{security-considerations}} and analyzed in {{CO25}}.

## Proof systems terminology

The **session identifier** is a 32-byte string that identifies the application context and the specific non-interactive argument in use; it is held by both the prover and the verifier (see {{session-id}}).

A **prover message** is a message sent by the interactive prover, and a **verifier message** is a message sent by the interactive verifier (a uniformly random value, since the protocol is public-coin). A message can be a value of any type for which a codec ({{codecs}}) is defined, such as a byte string, an unsigned integer, or a group element. The **transcript** is the ordered sequence of prover and verifier messages. In particular, the transcript does _not_ include the session identifier.

The **instance** specifies the statement being proven and is held by both the prover and the verifier. The (encoded) instance **MUST** be non-empty.

The **witness** is the prover's private input. It is known only to the prover and is never revealed. It appears neither in the transcript nor in the NARG string.

For an NP language, the instance is a word, the witness is proof of its membership in the language, and the resulting non-interactive argument proves that the instance is indeed in the language. This claim is also referred to as the **statement**. Proof systems might support different statements or express the same language in different ways.

The **NARG string** (non-interactive argument string) is the serialized output of the non-interactive prover.

The notation in this document is for an interactive argument with `k` rounds in which the prover moves first and the verifier moves last. Other types of interactions can be expressed in the same notation by setting the unused messages to the empty string: a protocol whose verifier moves first (such as a batch argument) sets its first prover message to `""`, and one whose prover moves last (such as a sigma protocol) sets its final verifier message to `""`. Prover and verifier round messages `2`, ..., `k-1` **MUST** be non-empty.

## Codec and serialization

A prover message is processed in two independent ways: it is absorbed into the hash function to derive the verifier's challenges, and it is written into the NARG string sent to the verifier. This document keeps the two separate.

A **codec** ({{codecs}}) is the pair of maps between messages and the hash function's alphabet (bytes, in this document):

- **Encoding** converts the instance and each prover message into the bytes absorbed by the sponge ({{encoding-bytes}}).
- **Decoding** converts the bytes squeezed from the sponge into a uniformly-distributed verifier message ({{decoding}}).

**Serialization** ({{narg-string}}) is concerned with mapping prover messages to and from the NARG string:

- **Serialization** writes the prover messages into the NARG string produced by the non-interactive prover.
- **Deserialization** reads the prover messages back from the NARG string, and returns an error if the message is invalid.

For a prover message, the serialized bytes coincide with the encoded bytes ({{serialization}}). However, codecs and serialization serve different purposes. Codecs must maintain the soundness of the transformation, whereas deserialization keeps the NARG string unambiguous and rejects malformed proofs (see {{decoding}} and {{deserialization}}).

# Duplex sponge {#hash-instantiations}

This section lists the duplex sponge instantiations provided in this document.

## Interface

Prover and verifier messages are handled via three operations:

- `Init(session_id) -> state`: create a new duplex sponge state, seeded by the 32-byte string `session_id`.
- `Absorb(x)`: absorb the byte string `x` into the state.
- `Squeeze(n) -> buf`: produce `n` bytes from the state.

The sponge interface does not encode message boundaries, as messages can be absorbed incrementally: `Absorb(x)` followed by `Absorb(y)` (with no `Squeeze` in between) is equivalent to `Absorb(x || y)`. The output of `Squeeze(n)` is uniformly distributed over `n`-byte strings and depends on the session identifier, and on every byte absorbed before the call. Consecutive `Squeeze` calls continue one output stream, while any intervening `Absorb` starts a fresh one.

For all duplex sponges, `Squeeze(n)`, `Absorb("")`, `Squeeze(n)` can return the same `n` bytes twice. An empty absorb therefore **MUST NOT** be relied on to produce two different random n-byte strings. See {{proof-systems-terminology}} for the length requirements of round messages.

Guidance on how to produce a 32-byte `session_id` is given in {{session-id}}; its security requirements in {{indifferentiability-of-the-hash-function}}.

## SHAKE128 duplex sponge {#shake128}

In the SHA-3 family, two extendable-output functions (SHAKEs) are defined over the `Keccak-f` permutation: SHAKE128 and SHAKE256. Four other fixed-length hash-function instances (SHA3-224, SHA3-256, SHA3-384, and SHA3-512) are also defined but are out of scope for this document. A SHAKE is an eXtendable-Output Function (XOF) defined as SHAKE(M, n) where the output is an n-bit string. The corresponding collision and second-preimage-resistance strengths for SHAKE128 are min(n/2,128) and min(n,128) bits, respectively (see Appendix A.1 of {{SHA3}}). This instantiation targets 128-bit security.

Viewed as a duplex sponge, the SHAKE128 state is a 200-byte (1600-bit) string, split into a rate of `R = 168` bytes and a capacity of 32 bytes (256 bits). This instantiation is equivalent to invoking the SHAKE128 XOF on the concatenation of the session identifier, the encoded instance, and the encoded prover messages. That is, the `i`-th verifier message (for `1 <= i <= k`) of byte length `len_i` is computed as:

~~~
verifier_msg[i] := decode[i](SHAKE128(
                       session_id || zeros(R - 32)
                       || encode[0](instance)
                       || encode[1](prover_msg[1])
                       || ...
                       || encode[i](prover_msg[i]),
                   len_i * 8))
~~~

The session identifier is padded with `R - 32 = 136` zero bytes so that the instance and prover messages begin on a fresh rate-block boundary (see {{init}}).

### Init {#init}

Seed the state by absorbing the session identifier, padded with zeros to fill the rate (the remaining `R - 32 = 136` bytes).
The zeros are ordinary input absorbed before the standard SHAKE128 padding.

~~~
Init(session_id)

Input: session_id, a byte array

Output: a duplex sponge state

1. assert len(session_id) == 32
2. ctx = SHAKE128.New()
3. ctx.Update(session_id || zeros(R - 32))
4. return state := (ctx, reader = None)
~~~

### Absorb {#shake128-absorb}

Feed a byte string `x` into the state.

~~~
Absorb(state, x)

Inputs:

- state, a duplex sponge state
- x, a byte array

1. state.reader = None
2. state.ctx.Update(x)
~~~

### Squeeze

Returns the next `n` bytes of the SHAKE128 output stream computed over the absorbed input. If the sponge is in the absorbing phase, it finalizes a copy of the absorbing context as a SHAKE128 XOF reader. Consecutive `Squeeze` calls **continue** the same SHAKE128 output stream.

~~~
Squeeze(state, n)

Inputs:

- state, the duplex sponge state
- n, the number of bytes to be squeezed

Output: a uniformly-distributed random n-byte string

1. if state.reader == None:
2.    state.reader = state.ctx.Copy().Finalize()
3. return state.reader.Read(n)
~~~

Consecutive `Squeeze` calls with no intervening `Absorb` continue the same output stream, and any `Absorb` restarts the stream at offset zero (see {{shake128-absorb}}). The `Copy().Finalize()` in `Squeeze` realizes this without consuming the absorbing state: squeezed bytes are never fed back into the state.

# Codecs

A codec is a set of functions that map prover and verifier messages to the hash function's alphabet:

- Encoding converts prover messages into the bytes absorbed by the sponge. Encoding functions **MUST** be prefix-free.
- Decoding converts squeezed bytes into verifier messages. Decoding **MUST** preserve the uniform distribution (up to a small codec error).

## Encoding into byte strings {#encoding-bytes}

All encoding functions **MUST** be prefix-free.

### Byte strings {#encoding-varlen-string}

Encoding of a byte string is the identity function.

~~~
EncodeBytes(s)

Input: s, an N-byte string

Output: out, an N-byte string

1. return s
~~~

If the byte string has length less than 2^32 bytes, but its length is not known during initialization, it can be encoded as a prefix-free string by prefixing its length via `I2OSP`.

~~~
EncodeVarLenString(s)

Input: s, an N-byte string

Output: out, an (N+4)-byte string

1. return I2OSP(len(s), 4) || s
~~~

### Sequences and tuples

A fixed-length array or a tuple is encoded as the concatenation of the encodings of its elements, with no separators.

### Unsigned integers {#encoding-uint}

An integer modulo `M` is represented by its unique integer representative in the range `[0, M)` and encoded via `I2OSP`.

~~~
EncodeUint(x, M)

Inputs:
- x, an integer modulo M
- M, the order of the integer ring

Output: out, an Ns-byte string

1. assert 0 <= x < M
2. return I2OSP(x, Ns)
~~~

where `Ns` is the smallest integer with `256^Ns >= M`.

### Field elements {#encoding-field}

This section specifies the _default_ encoding of a finite field of order `q = p^m`, where `p` is the prime characteristic and `m >= 1` is the extension degree.

If the finite field already has specified serialization and deserialization functions, the specified serialization and deserialization primitives **SHOULD** be used instead, and they **MUST** themselves be prefix-free. The encoding below is chosen to coincide with the serializations of most standards; where it does not, the type's own serialization should be preferred. For instance, a prime-order scalar field element of an elliptic curve is serialized to a canonical `Ns`-byte string using the group's scalar field serialization function. For most prime-order elliptic-curve groups, this serialization is `EncodeUint` as described below.

With respect to a fixed basis, a field element is represented by its `m` coordinates in the prime field, each an integer in `[0, p)`. It is encoded as the concatenation of the per-coordinate encodings produced by `EncodeUint` ({{encoding-uint}}) with modulus `p`. Let `Ns` be the smallest integer with `256^Ns >= p`; a field element encodes to `m * Ns` bytes.

~~~
EncodeField(a, p, m)

Inputs:
- a, an element of the field of order p^m, given by its
     coordinates (a[0], ..., a[m-1]) over the prime field
- p, the prime characteristic of the field
- m, the extension degree

Output: out, an (m * Ns)-byte string

1. out = ""
2. for i in 0, ..., m-1:
3.    out = out || EncodeUint(a[i], p)
4. return out
~~~

Note that a prime field is the case `m = 1`, in which case `EncodeField` is equivalent to `EncodeUint`.

### Elliptic curve group elements {#encoding-ec-point}

A group element is serialized to a canonical `Ne`-byte string using the group's element-serialization function.

For most prime-order elliptic-curve groups, this is the compressed Elliptic-Curve-Point-to-Octet-String conversion of {{SEC1}}. Each group element has exactly one `Ne`-byte representation. The value of `Ne` and the concrete conversion are fixed by the ciphersuite.

## Decoding from byte strings {#decoding}

Decoding converts a uniformly-distributed `Squeeze` output into a verifier message. Each verifier message type fixes the number of bytes to squeeze.

Decoding is not deserialization, and need not invert encoding nor even be injective; its only requirement is to be _distribution-preserving_: if its input is a uniformly random byte string, then its output is (statistically close to) uniformly distributed over the verifier message type.

### Byte arrays

The decoding function for fixed-length byte arrays is the identity.

~~~
DecodeBytes(buf, N)

Inputs:
- buf, a byte string
- N, the expected byte length

Output: out, a byte string of length N

1. fail if len(buf) != N
2. return buf
~~~

### Unsigned integers {#decoding-uint}

To sample a uniformly random element modulo `M` of `Ns` bytes (that is, the smallest integer `Ns` with `256^Ns >= M`), squeeze `Ns + 32` bytes by interpreting them as a big-endian non-negative integer via `OS2IP`, and reduce modulo `M`.

~~~
DecodeUint(buf, M)

Inputs:
- buf, a byte string of length Ns + 32
- M, the modulus

Output: out, an integer in the range [0, M)

1. fail if len(buf) != Ns + 32
2. return OS2IP(buf) mod M
~~~

The 32 extra bytes (256 bits) ensure that the statistical distance between the reduced value and the uniform distribution over `[0, M)` is at most `2^-256`, which is cryptographically negligible. More generally, sampling `Ns + n` bytes bounds the bias to `2^-8n`.

In two cases this approach is inefficient: if `log2(M)` is significantly smaller than 256, and if `M` is a 2-power.
In such cases, applications **MAY** use an alternative decoding function, provided it meets the following security requirements:

-  The function **MUST** have bias less than the soundness error of the interactive argument.
-  The function **SHOULD NOT** use rejection sampling (see {{constant-time}}).
-  The function **SHOULD** be amenable to straight-line implementations.

Similar requirements and a longer discussion are available in {{?RFC9380}}, Section 5.

### Field elements {#decoding-field}

A field element of a field of order `p^m` is decoded coordinate by coordinate: each of its `m` prime-field coordinates is decoded via `DecodeUint` ({{decoding-uint}}) with modulus `p`, starting from the least-signigicant. With `Ns` as in {{encoding-field}}, this consumes `m * (Ns + 32)` bytes. A prime field is the case `m = 1`.

~~~
DecodeField(buf, p, m)

Inputs:
- buf, a byte string of length m * (Ns + 32)
- p, the prime characteristic of the field
- m, the extension degree

Output: out, an element of the field of order p^m, given by its
        coordinates (a[0], ..., a[m-1]) over the prime field

1. fail if len(buf) != m * (Ns + 32)
2. for i in 0, ..., m-1:
3.    chunk = buf[i * (Ns + 32) : (i + 1) * (Ns + 32)]
4.    a[i] = DecodeUint(chunk, p)
5. return (a[0], ..., a[m-1])
~~~

For `m = 1`, `DecodeField` is `DecodeUint`, and the same efficiency remarks apply: when `log2(p)` is significantly smaller than 256 or `p` is a power of two, applications **MAY** substitute a more efficient alternative, subject to the same security requirements described in {{decoding-uint}}.

For `m > 1`, decoding relies on `32 * m` additional randomness bytes. Applications with big-integer arithmetic available **MAY** use a more randomness-efficient decoding algorithm, by instead sampling `Nm + 32` bytes, where `Nm` is the smallest integer with `256^Nm >= p^m`, interpreting them as an integer via `OS2IP`, reducing modulo `p^m`, and recovering the coordinates `(a[0], ..., a[m-1])` as the base-`p` digits of the result. This consumes `Nm + 32` bytes, with the same `2^-256` bias bound.

# Initialization

Before any prover message is processed, both parties start the duplex sponge with the session identifier ({{session-id}}), and then the instance ({{instance}}). Neither of the two is part of the NARG string: the verifier holds both as its own inputs.

## Session identifiers {#session-id}

The session identifier is a 32-byte string that identifies the context in which the non-interactive argument is used.

For a duplex sponge operating over bytes, the session identifier is derived from a `tag` (a variable-length byte string) via the procedure `DeriveSessionID`. The tag has the following security requirements:

1. the tag **MUST** uniquely identify the **non-interactive argument** used, including the interactive argument system, the types of prover and verifier messages, the hash suite, and the language associated with the interactive argument.
2. the tag **MUST** uniquely identify the **codecs** used: the order and types of encodings and decodings at each round.
3. the tag **MUST** contain contextual information about where the proof is made (e.g. a URL to identify the application namespace, a timestamp to prevent replay attacks).
4. the tag **SHOULD** begin with a fixed identification string that is unique to the application.
5. the tag **SHOULD** include a version number.

~~~
DeriveSessionID(tag)

Inputs:
- tag, an application-chosen byte string

Output: session_id, a 32-byte string

1. duplex_sponge = DS.Init("irtf-cfrg-fiat-shamir/session-id")
2. duplex_sponge.Absorb(tag)
3. return duplex_sponge.Squeeze(32)
~~~

Above, `DS` denotes the duplex sponge instantiation in use ({{hash-instantiations}}, for example the SHAKE128 duplex sponge of {{shake128}}), and `DS.Init`, `DS.Absorb`, and `DS.Squeeze` are its operations. The 32-byte string `"irtf-cfrg-fiat-shamir/session-id"` is a domain separator for this derivation.

As an example, consider a fictional application named Foo that implements sigma protocols over elliptic curves for encrypted messages shared during a time epoch `tttt`. A reasonable choice of tag is:

~~~
FOO-SV{xx}-{tttt}-DSFS-{hashID}-SIGMA-PROOFS-{yy}
~~~

where `xx` is the two-digit number indicating the version, `yy` is the two-digit number indicating the elliptic-curve ciphersuite, `hashID` is the hash identifier, and `tttt` is a 32-bit integer identifying the epoch.

As another example, consider a fictional application named Bar that implements an ad-hoc zero-knowledge virtual machine for correct execution of circuits. A reasonable choice of tag is

~~~
BAR-COM{cc}
~~~

where `{cc}` is the commit hash of the associated version of the cryptographic specification of the protocol.

Yet another reasonable choice for the session identifier is to append a description of the interactive argument system together with the length of each prover and verifier message, after the version string. For instance:

~~~
BAZ-SV{xx}-DSFS-{hashID}-sumcheck-{ff}-A2round-message-S1challenge
~~~

where `xx` is the two-digit version number, `hashID` is the hash identifier, and `ff` is the two-digit identifier of the finite field over which the proof is computed. The suffix `A2round-message-S1challenge` describes one sumcheck round (the pattern repeats each round): the prover absorbs (`A`) two field elements `round-message`, and the verifier squeezes (`S`) one field element `challenge`. This is similar to the SAFE API {{SAFE}} *IO pattern*, which is checked by the prover and verifier during execution.

## Instance

The instance is input to the non-interactive prover and the non-interactive verifier; it fixes the specific statement being proven.

The instance is the first value absorbed into the sponge after `Init(session_id)` and before any prover message. The prover and verifier **MUST** absorb `encode[0](instance)`, where `encode[0]` is the first encoding map.
The encoded instance **MUST** be non-empty. While the session identifier of the previous section {{session-id}} fixes the language, the instance selects one of its members.

As for every encoding map, `encode[0]` **MUST** be prefix-free, else a malicious prover may be able to satisfy the verification equations on a statement it cannot prove (see {{instance-encoding}}). The encoding map `encode[0]` **SHOULD** reuse the encodings of {{encoding-bytes}}.

As an example, the sumcheck relation for multilinear polynomials in `N` variables over `p^m` committed with the polynomial commitment scheme `COM` is the pair:

- instance `(N, C, S)`: `N` is the number of variables, `C` the commitment, and `S` the target sum;
- witness `(F, r)`, the multilinear polynomial in `N` variables and `r` the commitment opening information.

such that:

~~~
COM.Open(C, F, r)  = 1,
sum(F(b1, ..., bN) for b1, ..., bN in {0, 1}) = S
~~~

A valid instance encoding function is:

~~~
EncodeField(S, p, m) || EncodeUint(N, 2^32) || COM.Serialize(C)
~~~

where `COM.Serialize` is the commitment-serialization function of the scheme `COM` (the opening check `COM.Open` is used above).

As an example, in the discrete logarithm setting, the Chaum-Pedersen relation over an additive elliptic curve group with generators `G`, `H` (for which the relative discrete logarithm is not known) is the pair:

- instance `(C, D)` are Pedersen commitments
- witness `(x, r, s)` scalar field elements with `x` the commitment message and `r`, `s` independent random commitment openings

such that

~~~
C = xG + rH, D = xG + sH.
~~~

A valid instance encoding function is:

~~~
enc(G) || enc(H) || enc(C) || enc(D)
~~~

where `enc` is the group element-serialization function described in {{encoding-ec-point}}.

Omitting public statement data (for instance, `N` in the first example or the group generators `G`, `H` in the second) from the sponge can compromise soundness of the proof system. See {{instance-encoding}}.

# Non-interactive argument string {#narg-string}

## Serialization

Serialization is the concatenation of the byte encoding of each prover message, as defined in {{encoding-bytes}}.

## Deserialization

Deserialization of the NARG string consists in reading the prover messages and computing the inverse of the serialization procedure: each message is read by consuming a fixed number of bytes, determined by its type and the instance, and advancing past them.

Verification **MUST** fail if any of the prover messages cannot be deserialized successfully. After the last expected prover message has been read, the verifier **MUST** verify that no bytes remain. Bytes that are never read or that are decoded despite being invalid will cause the proof to be malleable: an adversary will be able to malleate a valid proof to obtain a second, distinct accepting proof for the same statement.

### Byte strings {#deserialize-byte-strings}

An `N`-byte string whose length is known from its type and the instance is deserialized by reading that many bytes. This is the inverse of `EncodeBytes` ({{encoding-varlen-string}}).

~~~
DeserializeBytes(input, N)

Inputs:
- input, the unread remainder of the NARG string
- N, the expected byte length

Output: b, an N-byte string

1. fail if len(input) < N
2. b = input[0 : N]
3. return b
~~~

This consumes `N` bytes of the NARG string, and fails if fewer bytes remain.

A byte string whose length is not known in advance is deserialized by reading a 4-byte length `N` via `OS2IP`, then reading the next `N` bytes; this is the inverse of `EncodeVarLenString` ({{encoding-varlen-string}}).

~~~
DeserializeVarLenString(input)

Input: input, the unread remainder of the NARG string

Output: b, an N-byte string

1. fail if len(input) < 4
2. N = OS2IP(input[0 : 4])
3. fail if len(input) - 4 < N
4. b = input[4 : 4 + N]
5. return b
~~~

This consumes `4 + N` bytes of the NARG string, and fails if fewer bytes remain. The value decoded is the resulting byte string.

### Sequences and tuples

Deserialize each element in order. Fail if any element fails to deserialize. The number and types of the elements are fixed by the protocol.

### Unsigned integers

Read the next `Ns` bytes, with `Ns` as in {{encoding-uint}}, and interpret them as a big-endian integer `x = OS2IP(.)`. If `x >= M`, fail: non-canonical integer encodings **MUST** be rejected. The value returned is `x`. This is the inverse of `EncodeUint` ({{encoding-uint}}).

~~~
DeserializeUint(input, M)

Inputs:
- input, the unread remainder of the NARG string
- M, the modulus

Output: x, an integer in the range [0, M)

1. fail if len(input) < Ns
2. x = OS2IP(input[0 : Ns])
3. fail if x >= M
4. return x
~~~

This consumes `Ns` bytes of the NARG string. It fails if fewer bytes remain, or if the integer read is not in the range `[0, M)`.

### Field elements

A field element of a field of order `p^m` is deserialized coordinate by coordinate: read `m * Ns` bytes, with `Ns` as in {{encoding-field}}, and deserialize each `Ns`-byte coordinate as an integer modulo `p` using the unsigned-integer deserialization above. A prime field is the case `m = 1`. This is the inverse of `EncodeField` ({{encoding-field}}).

~~~
DeserializeField(input, p, m)

Inputs:
- input, the unread remainder of the NARG string
- p, the prime characteristic of the field
- m, the extension degree

Output: a, an element of the field of order p^m, given by its
        coordinates (a[0], ..., a[m-1]) over the prime field

1. fail if len(input) < m * Ns
2. for i in 0, ..., m-1:
3.    chunk = input[i * Ns : (i + 1) * Ns]
4.    a[i] = DeserializeUint(chunk, p)
5. return (a[0], ..., a[m-1])
~~~

This consumes `m * Ns` bytes of the NARG string, and fails if fewer bytes remain or if any coordinate is non-canonical.

If the field type already has specified serialization and deserialization functions, those **MUST** be used instead (see {{encoding-field}}). As with encoding, the default is chosen to coincide with the deserializations of most standards; where it does not, the type's own deserialization governs.

### Elliptic-curve group elements

Read the next `Ne` bytes and convert them to a group element using the group's element-deserialization function.
Deserialization **MUST** perform the ciphersuite's input-validation steps and fail unless the input is the canonical encoding of a valid group element.

For example, for elliptic curves defined in {{SEC1}}, decoding is the Octet-String-to-Elliptic-Curve-Point conversion, which checks that the encoding is well-formed and that the point lies on the curve, and returns "invalid" otherwise. Membership in the subgroup used for cryptographic operations is not checked by this conversion: it is implied for curves of prime order, but requires an explicit check when the cofactor is greater than one.

# Efficiency considerations

For both codecs and serialization, batch algorithms should be preferred when available, because they amortize per-element cost over a whole sequence. For example, serializing or deserializing a batch of compressed elliptic-curve points requires only one modular inversion for the entire batch (via Montgomery's trick) rather than one per point, which is the dominant cost in point (de)compression.

`Init(session_id)` (see {{session-id}}) can be precomputed. Implementations can therefore start each prover and verifier execution from a copy of the duplex sponge state, instead of initializing it every time. In the SHAKE128 instantiation, where the padded session identifier fills exactly one rate block ({{init}}), this saves one invocation of the permutation function per execution, and amortizes the cost of `DeriveSessionID` when the session identifier is derived from a tag. The same observation extends to longer shared prefixes: proofs for the same instance can additionally start from a stored copy of the state obtained after absorbing `encode[0](instance)`.

# Security considerations

This section contains additional security considerations about the Fiat-Shamir transformation as described in this document.

## Codecs

While encoding maps are never inverted during the protocol, the security proof relies on a left inverse existing and being efficiently computable: the knowledge-soundness extractor uses it to recover prover messages from the absorbed bytes {{CO25}}.

Decoding preserves the uniform distribution only when its input is uniform. Verifier messages **MUST** therefore be derived from `Squeeze` output and never from prover-controlled or otherwise non-uniform bytes: decoding a non-uniform input yields a verifier message that is distinguishable from uniform, which would break the public-coin property the transformation depends on.

## Constant-time requirements {#constant-time}

While the protocol operates on "public coins", the instance can contain private information, such as verification keys not meant to be shared, or messages meant to be private between prover and verifier. Therefore, constant-time implementation of all the functions in this document is **RECOMMENDED**, to avoid leaking information via side channels.

For example, in the case of keyed-verification anonymous credentials, the zero-knowledge verifier will compute an instance that depends on the issuer's secret key and therefore the instance is not meant to be public.

## Session identifiers

The purpose of session identifiers is to ensure composability and mitigate protocol confusion.

A session identifier uniquely identifies one session of a protocol, so that messages and state belonging to concurrent applications or proof systems are not confused. It **MAY** be reused, and reuse is expected whenever several proofs share the same application context: the identifier names that context, and identical contexts are meant to share one. Applications requiring proofs to be unique, non-replayable, or fresh can achieve this by adding, for example, a counter or timestamp to the session identifier.

## Security of the transformation

The Fiat-Shamir transformation carries over the soundness and zero-knowledge properties of the interactive proof.

Completeness of the non-interactive argument is preserved: if the statement being proven is true, then the resulting non-interactive argument string is valid.

### Soundness

If the interactive proof is state-restoration sound, then so is the non-interactive proof. In particular, valid proofs cannot be generated without the corresponding statement being true (in the random oracle model).

Soundness and knowledge soundness carry over to the non-interactive argument, with an additive soundness loss quadratic in the number of queries the adversary makes to the random oracle {{CO25}}.

### Zero-Knowledge

If the interactive proof is honest-verifier zero-knowledge, then so is the non-interactive proof. In particular, the resulting argument string does not reveal any information beyond what can be directly inferred from the statement being valid.

The additive zero-knowledge loss introduced by the transformation is linear in the number of queries the adversary makes to the random oracle {{CO25}}.

Zero-knowledge holds only when the prover draws fresh randomness for each proof from a cryptographically secure entropy source, as noted in {{introduction}}. Reusing the same randomness (or correlated randomness) across two proofs will compromise zero-knowledge. Implementations **SHOULD** sample different random coins for each proof using the operating system's secure entropy source.

### Quantum adversaries

If the interactive proof is state-restoration sound against quantum adversaries, then the non-interactive proof after the Fiat-Shamir transformation in the random oracle model is also secure against quantum adversaries.

The loss introduced by a quantum adversary is polynomial (larger than quadratic) in the number of quantum random-oracle queries.

### Indifferentiability of the hash function

The random oracle instantiation **MUST** be extraction-friendly and simulation-friendly indifferentiable to preserve soundness and zero-knowledge of the transformation.

To provide soundness and zero-knowledge, stronger capabilities than indifferentiability are needed {{CO25}}. Implementers do not need these notions to use the transformation, but they are the reason a different hash construction **SHOULD NOT** be substituted on the strength of indifferentiability alone.

## Instance encoding

Incorrect encoding of the instance has historically led to a number of critical security vulnerabilities, often grouped under the term *weak Fiat-Shamir transformation* {{BPW16}}. In each of them, the cryptographic hash function was not provided the full statement being proven. A malicious prover then can compute the verifier message first, and choose the omitted part of the instance afterwards so that the verification equation is satisfied on a statement whose witness it does not hold.

One such example is in {{BPW16}}. A Chaum-Pedersen proof of equality for an instance `(G, H, X, Y)` proves knowledge of a witness `x` such that `X = x * G` and `Y = x * H`. The prover sends commitments `(A, B)`, obtains a challenge `c`, and replies with a scalar `f`. The verifier accepts if the verification equations hold: `f * G == A + c * X` and `f * H == B + c * Y`. Suppose the challenge `c` is derived only by absorbing `(A, B)` and omitting the instance `(G, H, X, Y)`. A malicious prover can pick `A`, `B`, `H`, and `f` at random, derive `c`, and then set `X` and `Y` to satisfy the verification equations. Verification passes, yet no single `x` satisfies both `X = x * G` and `Y = x * H`. Thus, a false statement has been proven. Other examples are available in {{DMWG23}}, for a range of different applications.

All security guarantees are conditioned on the instance being part of the relation being proven. The Fiat-Shamir transformation does not verify that the statement being proven is well-formed, or valid. If the instance or the witness provided as input are not in the relation (e.g. they are malformed), the output is undefined and no security guarantee is provided.

## Implementation guidance {#implementation-guidance}

The Fiat-Shamir transformation has historically led to a number of critical security vulnerabilities, especially due to incorrect implementations involving out-of-order (or missing) prover messages.

Test vectors can help confirm that honestly-generated proofs verify, but such tests exercise only completeness. Negative testing will help exercise the rejection paths too. Some such examples are: tampering with a valid NARG string to cause verification to fail, by flipping, appending, or prepending bytes, and by replacing each prover message in turn with a different value.

Absorbing a prover message and serializing it to (or reading it from) the NARG string **SHOULD** be coupled, to prevent prover messages from being hashed without being serialized, or from being skipped or reordered.

A sequential transcript interface is **RECOMMENDED**: implementations are encouraged to expose two directed state machines

* (instance, witness) -> prove -> proof, and
* (instance, proof) -> verify -> accept/reject

where the proof object is a byte string.

Particular care must be taken when building a proof object that is only later serialized into a NARG string: its fields are randomly addressable, making them prone to out-of-order or partial access to prover messages, which can in turn compromise soundness of the resulting non-interactive argument. A sequential interface, by contrast, enforces in-order processing. An end-of-input check is necessary to prevent malleability.

The NARG string must be treated as untrusted input. Therefore, non-interactive verifiers **MUST NOT** assume that length indicators are honest, that integers fall within their expected range, or that the proof length is correct. For example, in {{deserialize-byte-strings}} the length prefix of a byte string is attacker-controlled, and can be as large as `2^32 - 1`, so computing `4 + N` can overflow 32-bit integers.

# IANA Considerations

This document has no IANA actions.

--- back

# Test Vectors

{::include ./poc/vectors/duplexSpongeVectors.txt}
