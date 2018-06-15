Threshold and Multisignatures with the MuSig Module
===========================

This module implements Schnorr signatures, a batch verifier for Schnorr
signatures that can also batch-verify Taproot commitments, and threshold
signatures/multisignatures. This document focuses on threshold signatures.

Multisignatures are described in the MuSig paper [1]. Threshold signatures
are a generalization of these in which all participants distribute "shards"
of their keys to all other participants, enabling signature creation
without all signers present.

### Terminology

A _Schnorr signatures_ with public key `P` on message m is a pairs `(s, R)`,
where `s` is a scalar, `R` is a curvepoint, which satisfies the equation

    sG = R + eP

where `e` is some hash of `P`, `R`, and the message. We will not worry about
the specific curve or hash used, but see [2] for a full specification.

A _multisignature_ is such a signature produced by `n` signers, labelled
1 through `n`, who each contribute a pair `(s_i, R_i)` such that

    sum_i R_i = R
    sum_i s_i = s

we refer to each `R_i` as a _partial nonce_ and each `s_i` as a _partial
signature_.

A _threshold signature_ is such a signature that may be produced by any
`k` signers out of a fixed set of `n`. Production of such a signature
requires an additional step in which each participant splits his secret
key into `n - 1` _key shards_, one for each participant excluding himself.

### Key Generation Procedure

Let `n` signers each have a keypair `(x_i, P_i)` for `i` ranging from 0 to
`n-1`. We define their _combined public key_ as

    P = sum_i µ_i*P_i

were `µ_i = H(L || i)`, where `H` is a collision-resistant hash function
and `L` is a hash of all public keys in some canonical order. We refer to
the coefficient `µ_i` as the _MuSig coefficient_ of the key. Internal to
the source code, `P` is referred to as `combined_pk` and `L` as `ell`;
the MuSig coefficient is computed by `secp256k1_musig_coefficient`.

Observe that this is the public key for a `k-of-n` signature; it does not
depend on the threshold value `k`.

However, if `k` is less than `n`, there is an additional step that each
signer must take: splitting their key. They do this using the function
`secp256k1_musig_keysplit`. The output of this function is `n` _keyshards_,
one for each signer, including the original participant. The function
also outputs `n` _public keyshards_, which are public keys corresponding
to the individual shards.

Each keyshard should be distributed to its respective signer; the "self
keyshard" is never used and can be discarded. The set of public keyshards
should be published to all signers, who should verify somehow that they
all received the same set. They can verify the set itself, and that their
secret shard is represented in it, with `secp256k1_musig_verify_shard`.

### Signing Procedure

To produce a signature, each signer `i` acts as follows.

    1. Produces a nonce pair `(k_i, R_i)` and a commitment (hash) `C_i` to `R_i`.
       This is done with `secp256k1_musig_multisig_generate_nonce`. Sends the
       commitment `C_i` to every other signer.

    2. Once at least `k` nonce commitments have been received from other signers,
       signer `i` creates `n` `secp256k1_musig_signer_data` structures, one for
       each signer including herself.

       She initializes each with `secp256k1_musig_signer_data_initialize`,
       providing nonce commitments from present signers and keyshards from
       missing signers. (For multisignatures, `k = n`, there are no keyshards,
       and every signer must provide a nonce commitment.)

       She sends her actual public nonce `R_i` to every other signer.

    3. Using `secp256k1_musig_set_nonce`, she updates each signer's data structure
       with their public nonces as they come in. If a signer sends a nonce which
       does not match his precommitment, this function will fail. If the data
       structure was initialized with a keyshard present, the signer will simply
       be treated as "missing" in this case; otherwise signing will fail.

       Once `k` valid public nonces have been received, she can produce a partial
       signature using `secp256k1_musig_partial_sign`. She sends this partial
       signature to someone (or everyone) for aggregation.

    4. Some participant receives all the partial signatures and combines them using
       `secp256k1_musig_combine_partial_sigs`. The output of this function is a
       complete signature.

### Underlying Algebra

#### Multisigantures

In the case of multisignatures, i.e. `n`-of-`n` threshold signatures, the algebra
is very simple. In `secp256k1_musig_partial_sign`, all participants' public nonces
are added to get a total public nonce. Each participant computes a messagehash
using this total public nonce and signs with their secret key multiplied by their
MuSig coefficient. That is, each participant modifies their secret key as follows:

    x_i' = µ_i * x_i

We see that the total signature will have public key

    sum_i x_i' * G = sum_i µ_i * x_i * G = sum_i µ_i * P_i = P

#### Threshold Signatures

In the case of threshold signatures, construction is a bit more involved.

First, when splitting her secret key `x_i`, signer `i` creates a shard `x_i^j`
for each signer `j` which satisfies the following equation

    x_i = sum_j L_i^j * x_i^j

Here `L_i^j` is called the _Lagrange coefficient_ of `j`s shard of `i`s secret key.
This equation will hold when the sum is taken over any subset of `k`-many signers,
though for each specific subset, the coefficients will be different. In the code,
these coefficients are computed by `secp256k1_musig_lagrange_coefficient` which
follows the formula given in [1].

Then, when signing, suppose that at least `k` signers are present. Each signer `i`
who is present modifies their signing key as follows

    x_i' = µ_i * x_i + sum_j µ_j * L_j^i * x_j^i

Where the sum is over all missing signers. (Notice that the indices `i` and `j`
have switched places relative to where they were in the description of the
key-splitting procedure. This reflects the fact that the splitting procedure
produces shards of the same key belonging to different owners; while during
signing we use shards of different keys but with the same owner.)

With these modified secret keys, the total signature's public key is

    sum_i x_i' * G
        = sum_i [µ_i * x_i + sum_j µ_j * L_j^i * x_j^i] * G
        = sum_i [µ_i * x_i] * G + sum_i sum_j [µ_j * L_j^i * x_j^i] * G
        = sum_i [µ_i * x_i] * G + sum_j sum_i [µ_j * L_j^i * x_j^i] * G
        = sum_i [µ_i * x_i] * G + sum_j µ_j * sum_i [L_j^i * x_j^i] * G
        = sum_i [µ_i * x_i] * G + sum_j [µ_j * x_j] * G
        = sum_i µ_i * P_i + sum_j µ_j * P_j
        = P

where `i` sums over the present signers and `j` sums over the missing signers.

#### Lagrange Coefficients

As mentioned, the Lagrange coefficients follow the formula given in [1]. Some
further explanation of how this works is in order.

First, signer `i` computes her shards by choosing a uniformly random `k-1`-degree
polynomial `L` whose constant term is her secret key `x_i`. Then each shard is

    x_i^j = L(j + 1)

It is then clear that `x_i = L(0)` and that after keyshard construction, we
never actually need the polynomial `L`, only its evaluation at 0. The Lagrange
interpolation formula, which constructs `L` as a sum of smaller polynomials,
can therefore be simplified by first evaluating all the sub-polynomials at 0.

With this in mind, we see

    L(0) = sum_i x_i^j * l_i(0)
         = sum_i x_i^j * prod_{m ≠ i} (m + 1)/(m - i)
         = sum_i x_i^j * L_i^j
         = x_i

where the first sum is verbatim the equation from [1] with variables renamed, the
second sum gives an explicit form, and the third renames the product `L_i^j` to
emphasize that it is what we refer to be the "Langrange coefficient". The final
equality is simply a restatement of the equation at the top of the Threshold
Signatures section.

In this expression, the outer index `j` ranges over all present signers and the
inner index `m` ranges over all present signers except `j`.


[1] `https://eprint.iacr.org/2018/068`

[2] `https://github.com/sipa/bip-metas/blob/master/schnorr.mediawiki`

[3] `https://en.wikipedia.org/wiki/Lagrange_polynomial`

