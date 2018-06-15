#ifndef SECP256K1_MUSIC_H
#define SECP256K1_MUSIC_H

/** Opaque data structure that holds a parsed MuSig signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the `secp256k1_musig_signature_serialize` and
 *  `secp256k1_musig_signature_parse` functions.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_musig_signature;

/** Secret key tweaked for MuSig. Create with `secp256k1_musig_tweak_secret_key`.
 *
 * This data structure is not opaque. It is guaranteed to be a 32-byte secret key
 * that works anywhere that ordinary secret keys may be used. It is a separate
 * type to help prevent API users mistakenly using untweaked secret keys with
 * MuSig, which would result in mysteriously invalid signatures being produced.
 */
typedef struct {
    unsigned char data[32];
} secp256k1_musig_secret_key;

/** Opaque data structure that holds a MuSig partial signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 33 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the `secp256k1_musig_partial_signature_serialize` and
 *  `secp256k1_musig_partial_signature_parse` functions.
 */
typedef struct {
    unsigned char data[33];
} secp256k1_musig_partial_signature;

/* Opaque data structure containing auxiallary data needed to validate partial
 * signatures. As above, the only guarantees is that this data will be 65 bytes
 * in size and may be memcpy/memcmp'd. There are no functions to serialize or
 * parse this data structure because it should never be transmitted or stored.
 *
 * TODO it needs to be serialized for memoryless hardware doesn't it
 */
typedef struct {
    unsigned char data[64];
} secp256k1_musig_validation_aux;

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
 *    pubkey: public key that the signer will use for partial signing
 *    pubnon: public nonce, must be a valid curvepoint if the signer is `present`
 * noncommit: pre-commitment to the nonce, used when adhering to the MuSig protocol
 */
typedef struct {
    int present;
    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubnon;
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

/** Serialize a MuSig partial signature or adaptor signature
 *
 *  Returns: 1
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 *
 *  See secp256k1_musig_signature_parse for details about the encoding.
 */
SECP256K1_API int secp256k1_musig_partial_signature_serialize(
    const secp256k1_context* ctx,
    unsigned char *out32,
    const secp256k1_musig_partial_signature* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse and validate a MuSig partial signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in32: pointer to the 32-byte signature to be parsed
 *
 * The signature is simply a single scalar.
 * key (x-coordinate only; the y-coordinate is considered to be the unique
 * y-coordinate satisfying the curve equation that is a quadratic residue)
 * and s is a 32-byte big-endian scalar.
 *
 * After the call, sig will always be initialized. If parsing failed or the
 * encoded numbers are out of range, signature validation with it is
 * guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_musig_partial_signature_parse(
    const secp256k1_context* ctx,
    secp256k1_musig_signature* sig,
    const unsigned char *in32
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
 * Users who want to use Taproot without MuSig, i.e. a single-signer pay-to-contract,
 * are better off manually computing the tweak and using `secp256k1_ec_privkey_tweak_add`
 * and `secp256k1_ec_pubkey_tweak_add` to modify their keys. Otherwise they will need
 * to use the full multisigning API which would be pointlessly inconvenient.
 *
 * Returns 1 on success, 0 on failure.
 *
 *  Args:    ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *  Out:  tweaked_pk: if non-NULL, filled with individual signers' tweaked public keys
 *       combined_pk: tweaked MuSig pubkey, including Taproot commitment if present (cannot be NULL)
 *  In:       pk: input public keys (cannot be NULL)
 *            np: number of keys in the above array
 */
SECP256K1_API int secp256k1_musig_pubkey_combine(
    const secp256k1_context* ctx,
    secp256k1_pubkey *tweaked_pk,
    secp256k1_pubkey *combined_pk,
    const secp256k1_pubkey *pk,
    size_t np
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3);

/** Computes a MuSig multiplier and multiplies a secret key by it.
 *
 * Returns 1 on success, 0 if any input was invalid.
 *
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  Out:     out: tweaked MuSig secret key (cannot be NULL)
 *  In:   seckey: unmodified secret key (cannot be NULL)
 *            pk: input public keys (cannot be NULL)
 *            np: number of keys in the above array
 *      my_index: index of signer (should be consistent with 0-indexed signer data array used in other functions)
 */
SECP256K1_API int secp256k1_musig_tweak_secret_key(
    const secp256k1_context* ctx,
    secp256k1_musig_secret_key *out,
    const unsigned char *seckey,
    const secp256k1_pubkey *pk,
    size_t np,
    size_t my_index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create a single-signer MuSig signature with a pre-Taproot-tweaked (or untweaked) secret key
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
    const secp256k1_musig_secret_key *seckey,
    const unsigned char *msg32,
    const unsigned char *rngseed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Initializes a signer data structure, initially as "missing", at signing-time
 *
 * If the signer in question should be present, `noncommit` should be provided
 * and set to the signer's nonce commitment. Later `secp256k1_musig_set_nonce`
 * will mark the signer actually present, upon receipt of a nonce consistent
 * with the precommitment.
 *
 * For n-of-n signatures, the parameter `pubkey` should be one of the `tweaked_pk`
 * pubkeys that was output from `secp256k1_musig_pubkey_combine` during the setup
 * phase. For k-of-n signatures, `pubkey` should be taken from the `pubkey` array
 * output by `secp256k1_musig_verify_shard`.
 *
 * Always returns 1.
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  In/Out: data: pointer to the signer data to initialize (cannot be NULL)
 *  In:   pubkey: public key that signer will use (cannot be NULL)
 *      noncommit signer's nonce commitment, if available, otherwise NULL
 */
SECP256K1_API int secp256k1_musig_signer_data_initialize(
    const secp256k1_context* ctx,
    secp256k1_musig_signer_data *data,
    const secp256k1_pubkey *pubkey,
    const unsigned char *noncommit
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

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
 *      pubcoeff: array of public shards, which are used to verify shards (cannot be NULL)
 *  In:   seckey: secret signing key to be split (cannot be NULL)
 *             k: number of shards to be required when signing; also the length of the `pubcoeff` array
 *             n: number of signers; also the length of the `shards` array
 *       rngseed: unique seed. Does not need to be random but MUST BE UNIQUE.
 *                May be reused in `secp256k1_musig_multisig_generate_nonce`, though that is a signing-time
 *                function and this is a key-setup-time function. (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_keysplit(
    const secp256k1_context* ctx,
    unsigned char *const *shards,
    secp256k1_pubkey *pubcoeff,
    const secp256k1_musig_secret_key *seckey,
    const size_t k,
    const size_t n,
    const unsigned char *rngseed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(7);

/** Verifies that a shard is valid and updates a set of partial signing keys accordingly
 *
 *  Returns: 1: shard is valid and consistent with list of public coefficients
 *           0: otherwise
 *  Args:    ctx: a secp256k1 context object, initialized for both signing and verification.
 *       scratch: scratch space used for the multiexponentiation
 *  Out:  seckey: set to running sum of secret shards, if non-NULL
 *        pubkey: array of partial signing keys to initialize or update (cannot be NULL)
 *                if the function fails, this array should assume to be trashed.
 *  In:   n_keys: total number of signers
 *    continuing: 0 on first call (set seckey/pubkey), 1 on subsequent calls (update seckey/pubkey)
 *     privshard: secret shard provided by the signer to the verifier; will be checked if non-NULL
 *        my_idx: index of verifier's privaty shard
 *      pubcoeff: list of public coefficients, the first of which will be the signer's public key (cannot be NULL)
 *      n_coeffs: number of shards in the above list (the threshold `k` in a `k`-of-`n` signature)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_verify_shard(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_musig_secret_key *seckey,
    secp256k1_pubkey *pubkey,
    size_t n_keys,
    int continuing,
    const unsigned char *privshard,
    size_t my_idx,
    const secp256k1_pubkey *pubcoeff,
    size_t n_coeffs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(9);

/** Produces a partial signature
 *
 *  Returns: 1: partial signature constructed
 *           0: invalid secret key, invalid keyshards, not enough signers and/or keyshards, calling signer not present
 *  Args:    ctx: pointer to a context object initialized for verification (cannot be NULL)
 *       scratch: scratch space used to compute the total nonce by multiexponentiation
 *  Out:     sig: partial signature (cannot be NULL)
 *           aux: auxillary data needed to verify other partial signatures (cannot be NULL)
 *  In:   seckey: secret signing key to use (cannot be NULL)
 *   combined_pk: combined public key of all signers (cannot be NULL)
 *         msg32: message to be signed (cannot be NULL)
 *        secnon: secret half of signer's nonce (cannot be NULL)
 *          data: array of public nonces and/or keyshards of all signers (cannot be NULL)
 *     n_signers: number of entries in the above array
 *      my_index: index of the caller in the array of signer data
 */
SECP256K1_API int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_musig_partial_signature *sig,
    secp256k1_musig_validation_aux *aux,
    const secp256k1_musig_secret_key *seckey,
    const secp256k1_pubkey *combined_pk,
    const unsigned char *msg32,
    const unsigned char *secnon,
    const secp256k1_musig_signer_data *data,
    size_t n_signers,
    size_t my_index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/** Checks that an individual partial signature is valid
 *
 * It is not essential to use this function, in the sense that if any partial
 * signatures are invalid, the full signature will also be invalid, so the
 * problem will be caught. But this function allows determining the specific
 * party who produced an invalid signature, so that signing can be restarted
 * without them.
 *
 *  Returns: 1: partial signature was valid
 *           0: invalid signature or bad data
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:   partial_sig: signature to check (cannot be NULL)
 *               data: signer data for this signer (not the whole array) (cannot be NULL)
 *                aux: auxillary data from `partial_sign` (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_signer_data *data,
    const secp256k1_musig_validation_aux *aux
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Combines partial signatures
 *
 *  Returns: 1: all partial signatures had valid data. Does NOT mean the resulting signature is valid.
 *           0: some partial signature had s/r out of range
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:          sig: complete signature (cannot be NULL)
 *  In:   partial_sig: array of partial signatures to combine (cannot be NULL)
 *             n_sigs: number of signatures in the above array
 *               data: signer data (cannot be NULL)
 *          n_signers: total number of signers (must be >= n_sigs)
 *                aux: auxillary data from `partial_sign` (cannot be NULL)
 *      taproot_tweak: the Taproot tweak from `pubkey_combine`, or NULL if Taproot is unused
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_combine(
    const secp256k1_context* ctx,
    secp256k1_musig_signature *sig,
    const secp256k1_musig_partial_signature *partial_sig,
    size_t n_sigs,
    const secp256k1_musig_signer_data *data,
    size_t n_signers,
    const secp256k1_musig_validation_aux *aux,
    const unsigned char *taproot_tweak
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(7);

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
