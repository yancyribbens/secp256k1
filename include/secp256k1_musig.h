#ifndef SECP256K1_MUSIC_H
#define SECP256K1_MUSIC_H

/** Opaque data structured that holds a parsed MuSig signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the secp256k1_musig_signature_serialize_* and
 *  secp256k1_taprOot_signature_parse_* functions.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_musig_signature;

/** Data structure containing data on other signers to be used during signing
 *
 * This structure is single-use. It is initialized with a missing signer's key
 * shard, which should be stored securely and may be used for multiple signatures;
 * or a present signer's nonce commitment, which will be single-use.
 *
 * Before signing, for each present signer, the structure is completed with
 * that signer's actual public nonce.
 *
 * Use `secp256k1_musig_signer_data_initialize` to initialize
 *
 *   present: flag indicating whether the signer is present for this signature
 *    pubnon: public nonce, must be a valid curvepoint if the signer is `present`
 *  keyshard: shard of the signer's secret key, must be present if not `present`
 * noncommit: pre-commitment to the nonce, used when adhering to the MuSig protocol
 */
typedef struct {
    int present;
    secp256k1_pubkey pubnon;
    unsigned char keyshard[32];
    unsigned char noncommit[32];
} secp256k1_musig_signer_data;

/** Serialize a MuSig signature
 *
 *  Returns: 1
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out64: pointer to a 64-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 *
 *  See secp256k1_musig_signature_parse for details about the encoding.
 */
SECP256K1_API int secp256k1_musig_signature_serialize(
    const secp256k1_context* ctx,
    unsigned char *out64,
    const secp256k1_musig_signature* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a MuSig signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in64: pointer to the 64-byte signature to be parsed
 *
 * The signature is serialized in the form R||s, where R is a 32-byte public
 * key (x-coordinate only; the y-coordinate is considered to be the unique
 * y-coordinate satisfying the curve equation that is a quadratic residue)
 * and s is a 32-byte big-endian scalar.
 *
 * After the call, sig will always be initialized. If parsing failed or the
 * encoded numbers are out of range, signature validation with it is
 * guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_musig_signature_parse(
    const secp256k1_context* ctx,
    secp256k1_musig_signature* sig,
    const unsigned char *in64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);


/** A pointer to a function to generate a Taproot tweak
 *
 * Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
 * Out:  tweak32: pointer to a 32-byte array to be filled by the function.
 * In:        pk: public key to start from
 *        commit: pointer to a 32-byte message to hash into the tweak
 *          data: Arbitrary data pointer that is passed through.
 *
 * Except for test cases, this function should hash the public key, message,
 * and auxilliary data.
 */
typedef int (*secp256k1_taproot_hash_function)(
    unsigned char *tweak32,
    const secp256k1_pubkey *pk,
    const unsigned char *commit,
    void *data
);

/** An implementation of a Taproot hash function that simply hashes
 *  the pubkey followed by the script to commit to. May be called
 *  directly for use with single_sign. */
SECP256K1_API extern const secp256k1_taproot_hash_function secp256k1_taproot_hash_default;

/** Creates a MuSig pubkey from a set of public keys and optionally a Taproot tweak
 *
 * Returns 1 on success, 0 on failure.
 *
 *  Args:    ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *       scratch: scratch space used for the multiexponentiation
 *  Out:       combined_pk: tweaked MuSig pubkey, including Taproot commitment if present (cannot be NULL)
 *   combined_pk_untweaked: if non-NULL, filled with the combined MuSig pubkey without Taproot
 *           ell: if non-NULL, is filled with the 32-byte hash of all pubkeys
 *  In:       pk: input public keys (cannot be NULL)
 *            np: number of keys in the above array
 *      taproot_commit: a 32-byte message to Taproot-tweak the final key with, or NULL for no tweak
 *        hashfp: pointer to a hashing function. If NULL, secp256k1_taproot_hash_default is used
 *         hdata: pointer to arbitrary data used by the hash function (can be NULL)
 */
SECP256K1_API int secp256k1_musig_pubkey_combine(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_pubkey *combined_pk,
    secp256k1_pubkey *combined_pk_untweaked,
    unsigned char *ell,
    const secp256k1_pubkey *pk,
    size_t np,
    const unsigned char *taproot_commit,
    secp256k1_taproot_hash_function hashfp,
    void *hdata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(6);

/** Create a single-signer MuSig signature with a pre-tweaked (or untweaked) secret key
 *
 * Returns 1 on success, 0 on failure.
 *
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte tweaked secret key (cannot be NULL)
 *       noncefp: pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *         ndata: pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
SECP256K1_API int secp256k1_musig_single_sign(
    const secp256k1_context* ctx,
    secp256k1_musig_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Generate a uniformly nonce for a MuSig multisignature or threshold signature
 *
 *  Returns 1 always.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:  secnon: pointer to the returned secret nonce (cannot be NULL)
 *        pubnon: returned public nonce (cannot be NULL)
 *     noncommit: returned nonce commitment, if non-NULL
 *  In:   seckey: secret signing key (cannot be NULL)
 *         msg32: message to be signed (cannot be NULL)
 *       rngseed: unique seed. Does not need to be random but MUST BE UNIQUE (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_multisig_generate_nonce(
    const secp256k1_context* ctx,
    unsigned char *secnon,
    secp256k1_pubkey *pubnon,
    unsigned char *noncommit,
    const unsigned char *seckey,
    const unsigned char *msg32,
    const unsigned char *rngseed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Initializes a signer data structure as "missing"
 *
 *  At most one of `keyshard` or `noncommit` must be NULL, depending if the signer
 *  in question is present or missing. For multisignatures all signers are always
 *  present. If `keyshard` is provided for a signer who turns out to be present,
 *  it will be erased by `secp256k1_musig_set_nonce` after a valid public nonce
 *  is received.
 *
 *  Always returns 1.
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  In/Out: data: pointer to the signer data to initialize (cannot be NULL)
 *  In: keyshard: shard of signer's secret key, if available, otherwise NULL
 *      noncommit signer's nonce commitment, if available, otherwise NULL
 */
SECP256K1_API int secp256k1_musig_signer_data_initialize(
    const secp256k1_context* ctx,
    secp256k1_musig_signer_data *data,
    const unsigned char *keyshard,
    const unsigned char *noncommit
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Checks a signer's public nonce against a precommitment to said nonce, and update data structure if they match
 *
 *  Returns: 1: commitment was valid, data structure updated
 *           0: commitment was valid, nothing happened
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  In/Out: data: pointer to the signer data to update (cannot be NULL)
 *  In:   pubnon: signer's alleged public nonce (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_set_nonce(
    const secp256k1_context* ctx,
    secp256k1_musig_signer_data *data,
    const secp256k1_pubkey *pubnon
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Split a key into shards suitable for distribution for a k-of-n signature
 *
 *  Returns: 1: key successfully split
 *           0: invalid secret key
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:  shards: array of returned shards, which are each 32-byte unsigned char arrays (cannot be NULL)
 *      pubshard: array of public shards, which are curvepoints (cannot be NULL)
 *  In:   seckey: secret signing key to be split (cannot be NULL)
 *             k: number of shards to be required when signing
 *             n: number of signers; also the length of the `shards` array
 *       rngseed: unique seed. Does not need to be random but MUST BE UNIQUE.
                  May be the same as the one used in `secp256k1_musig_multisig_generate_nonce`. (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_keysplit(
    const secp256k1_context* ctx,
    unsigned char *const *shards,
    secp256k1_pubkey *pubshard,
    const unsigned char *seckey,
    const size_t k,
    const size_t n,
    const unsigned char *rngseed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7);

/** Verifies that a set of public shards is valid, and that a secret shard, if provided, is represented in the set
 *
 *  Returns: 1: public shard sum to the expected key, and the secret shard maps to the right public shard
 *           0: one of the above wasn't true, or the secret shard was invalid
 *  Args:    ctx: a secp256k1 context object, initialized for both signing and verification.
 *       scratch: scratch space used for the multiexponentiation
 *  In:   pubkey: public key of the signer who generated the public shards (cannot be NULL)
 *         shard: secret shard provided by the signer to the verifier; will be checked if non-NULL
 *        my_idx: index of verifier's shard in the following list of public shards
 *      pubshard: list of public shards (cannot be NULL)
 *   n_pubshards: number of shards in the above list
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_verify_shard(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_pubkey *pubkey,
    const unsigned char *shard,
    size_t my_idx,
    const secp256k1_pubkey *pubshard,
    size_t n_pubshards
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(6);

/** Produces a partial signature
 *
 *  Returns: 1: partial signature constructed
 *           0: invalid secret key, invalid keyshards, not enough signers and/or keyshards, calling signer not present
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  Out:     sig: partial signature (cannot be NULL)
 *  In:   seckey: secret signing key to use (cannot be NULL)
 *   combined_pk: combined public key of all signers (cannot be NULL)
 *           ell: hash of indiidual public keys (cannot be NULL)
 *         msg32: message to be signed (cannot be NULL)
 *        secnon: secret half of signer's nonce (cannot be NULL)
 *          data: array of public nonces and/or keyshards of all signers (cannot be NULL)
 *     n_signers: number of entries in the above array
 *      my_index: index of the caller in the array of signer data
 */
SECP256K1_API int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_musig_signature *sig,
    const unsigned char *seckey,
    const secp256k1_pubkey *combined_pk,
    const unsigned char *ell,
    const unsigned char *msg32,
    const unsigned char *secnon,
    const secp256k1_musig_signer_data *data,
    size_t n_signers,
    size_t my_index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/** Combines partial signatures
 *
 *  Returns: 1: all partial signatures had valid data. Does NOT mean the resulting signature is valid.
 *           0: some partial signature had s/r out of range
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:          sig: complete signature (cannot be NULL)
 *  In:   partial_sig: array of partial signatures to combine (cannot be NULL)
 *             n_sigs: number of signatures in the above array
 *              msg32: message that was signed, or NULL if Taproot is unused
 *     pubkey_tweaked: the tweaked version of the combined public key, or NULL if Taproot is unused
 *   pubkey_untweaked: the untweaked version of the combined public key, or NULL if Taproot is unused
 *     taproot_commit: a 32-byte message the public key was Taproot-tweaked with, or NULL if Taproot is unused
 *             hashfp: pointer to a hashing function. If NULL, secp256k1_taproot_hash_default is used
 *             hdata: pointer to arbitrary data used by the Taproot hash function (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_combine_partial_sigs(
    const secp256k1_context* ctx,
    secp256k1_musig_signature *sig,
    secp256k1_musig_signature *partial_sig,
    size_t n_sigs,
    const unsigned char *msg32,
    const secp256k1_pubkey *pk_tweaked,
    const secp256k1_pubkey *pk_untweaked,
    const unsigned char *taproot_commit,
    secp256k1_taproot_hash_function hashfp,
    void *hdata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Verify a MuSig signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature being verified (cannot be NULL)
 *         msg32: the 32-byte message hash being verified (cannot be NULL)
 *        pubkey: pointer to a public key to verify with (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_verify_1(
    const secp256k1_context* ctx,
    const secp256k1_musig_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verifies a set of MuSig signatures and Taproot commitments
 *
 * Returns 1 if all succeeded, 0 otherwise.
 *
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *       scratch: scratch space used for the multiexponentiation
 *  In:      sig: array of signatures, or NULL if there are no signatures
 *         msg32: array of messages, or NULL if there are no signatures
 *            pk: array of public keys, or NULL if there are no signatures
 *        n_sigs: number of signatures in above arrays (must be 0 if they are NULL)
 *  taproot_untweaked: array of "bare" Taproot keys, or NULL if there are no Taproot commitments
 *    taproot_tweaked: array of Taproot keys, or NULL if there are no Taproot commitments
 *            tweak32: array of committed data, or NULL if there are no Taproot commitments
 *        hashfp: function to use when computing Taproot commitments, or NULL to use the default
 *         hdata: extra data to pass to `hashfp`, ignored by the default function
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_musig_signature *const *sig,
    const unsigned char *const *msg32,
    const secp256k1_pubkey *const *pk,
    size_t n_sigs,
    const secp256k1_pubkey *const *taproot_untweaked,
    const secp256k1_pubkey *const *taproot_tweaked,
    const unsigned char *const *tweak32,
    size_t n_tweaks,
    secp256k1_taproot_hash_function hashfp,
    void *hdata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#endif
