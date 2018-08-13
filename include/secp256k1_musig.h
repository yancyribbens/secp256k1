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

/** Opaque data structure containing MuSig parameters, such as number of keys, threshold, combined
 *  public keys and Taproot commitment.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions.
 *
 *  This structure is initialized with `secp256k1_musig_init` and must be destroyed with
 *  `secp256k1_musig_destroy`.
 *
 *         scratch: scratch space used to store `n` MuSig pubkeys (cannot be NULL)
 *               k: number of partial signatures required to make a combined signature (= threshold)
 *               n: number of public keys involved in the multisignature
 * taproot_tweaked: flag indicating whether `combined_pk` includes a taproot commitment
 *   taproot_tweak: the 32-byte Taproot tweak if taproot_tweaked
 *       musig_pks: `n` MuSig tweaked public keys from the signers
 *     combined_pk: combination of the signers public keys and the taproot commitment (if present)
 */
typedef struct {
    secp256k1_scratch_space *scratch;
    size_t k;
    size_t n;
    int taproot_tweaked;
    unsigned char taproot_tweak[32];
    secp256k1_pubkey *musig_pks;
    secp256k1_pubkey combined_pk;
} secp256k1_musig_config;

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

/* Opaque data structure containing auxiliary data needed to validate partial
 * signatures. As above, the only guarantees is that this data will be 64 bytes
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
 * This structure is initialized with `secp256k1_musig_signer_data_initialize`.
 * If the signer is present, its nonce commitment is stored and before signing
 * completed with that signer's actual public nonce. The structure is used only
 * for a single signing attempt.
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
 * The partial signature is a 32-byte big-endian scalar.
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
 * Except for test cases, this function should hash the public key, commit,
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

/** Creates a MuSig configuration from an array of public keys and a Taproot commitment.
 *
 * The musig_config object must be destroyed with `secp256k1_musig_config_destroy`.
 *
 * Users who want to use Taproot without MuSig, i.e. a single-signer pay-to-contract,
 * are better off manually computing the tweak and using `secp256k1_ec_privkey_tweak_add`
 * and `secp256k1_ec_pubkey_tweak_add` to modify their keys. Otherwise they will need
 * to use the full multisigning API which would be pointlessly inconvenient.
 *
 * Returns 1 on success, 0 on failure.
 *
 *  Args:     ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *        scratch: scratch space used to store `n` MuSig pubkeys (cannot be NULL)
 *  Out: musig_config: filled with the initialized MuSig config data
 *  In:           pks: input public keys (cannot be NULL)
 *                  k: number of partial signatures required to make a combined signature
 *                     (= threshold)
 *                  n: number of public keys involved in the multisignature and number of elements
 *                     in `pks`
 *         commitment: 32-byte Taproot commitment to be included in the combined public key or NULL
 *                     if Taproot is unused
 *             hashfp: function to use when computing Taproot commitments, or NULL to use the
 *                     default
 *              hdata: extra data to pass to `hashfp`, ignored by the default function
 */
SECP256K1_API int secp256k1_musig_init(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_musig_config *musig_config,
    const secp256k1_pubkey *pks,
    const size_t k,
    const size_t n,
    const unsigned char *commitment,
    secp256k1_taproot_hash_function hashfp,
    void *hdata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Destroy a secp256k1 MuSig configuration.
 *
 *  The pointer may not be used afterwards.
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *      musig_config: MuSig configuration to destroy (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_config_destroy(
    const secp256k1_context* ctx,
    secp256k1_musig_config *musig_config
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Get the MuSig pubkey from the MuSig configuration
 *
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  Out: combined_pk: combined public key encoding the MuSig signing policy and the taproot
 *                    commitment if present (cannot be NULL)
 *  In: musig_config: MuSig configuration for `combined_pk` (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_pubkey(
    const secp256k1_context* ctx,
    secp256k1_pubkey *combined_pk,
    const secp256k1_musig_config *musig_config
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Get the individual MuSig-tweaked pubkey from the MuSig configuration
 *
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  Out:   musig_pks: `n` MuSig-tweaked public keys (cannot be NULL)
 *  In: musig_config: MuSig configuration for `musig_pks` (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_tweaked_pubkeys(
    const secp256k1_context* ctx,
    secp256k1_pubkey *musig_pks,
    const secp256k1_musig_config *musig_config
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

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

/** Create a single-signer MuSig signature.
 * Before signing the secret key can be tweaked with a Taproot commitment using
 * `secp256k1_ec_pubkey_tweak_add`.
 *
 * Returns 1 on success, 0 on failure.
 *
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
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

/** Generate a uniformly random nonce for a MuSig multisignature or threshold signature
 *
 *  Returns 1 always.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:  secnon: pointer to the returned 32-byte secret nonce (cannot be NULL)
 *        pubnon: returned public nonce (cannot be NULL)
 *     noncommit: returned 32-byte nonce commitment, if non-NULL
 *  In:   seckey: secret signing key (cannot be NULL)
 *         msg32: 32-byte message to be signed (cannot be NULL)
 *       rngseed: unique 32-byte seed. Does not need to be random but MUST BE UNIQUE (cannot be NULL)
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
 * and set to the signer's nonce commitment. After all nonce commitments have
 * been received, the signers start to send out nonces.
 * `secp256k1_musig_set_nonce` will mark the signer actually present, upon
 * receipt of a nonce consistent with the precommitment.
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
 *           0: commitment was invalid, nothing happened
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
 *  In: musig_config: MuSig configuration (cannot be NULL)
 *            seckey: secret signing key to be split (cannot be NULL)
 *           rngseed: unique seed. Does not need to be random but MUST BE UNIQUE.
 *                    May be reused in `secp256k1_musig_multisig_generate_nonce`, though that is a
 *                    signing-time function and this is a key-setup-time function. (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_keysplit(
    const secp256k1_context* ctx,
    unsigned char *const *shards,
    secp256k1_pubkey *pubcoeff,
    const secp256k1_musig_config *musig_config,
    const secp256k1_musig_secret_key *seckey,
    const unsigned char *rngseed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Verifies that a shard is valid and updates a set of partial signing keys accordingly
 *
 *  Returns: 1: shard is valid and consistent with list of public coefficients
 *           0: otherwise
 *  Args:    ctx: a secp256k1 context object, initialized for both signing and verification.
 *       scratch: scratch space used for the multiexponentiation
 *  Out:  seckey: set to running sum of secret shards, if non-NULL
 *        pubkey: array of partial signing keys to initialize or update (cannot be NULL)
 *                if the function fails, this array should assume to be trashed.
 *  In: musig_config: MuSig configuration (cannot be NULL)
 *        continuing: 0 on first call (set seckey/pubkey), 1 on subsequent calls (update seckey/pubkey)
 *         privshard: secret shard provided by the signer to the verifier; will be checked if non-NULL
 *            my_idx: index of verifier's privaty shard
 *          pubcoeff: list of public coefficients, the first of which will be the signer's public
 *                    key (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_verify_shard(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_musig_secret_key *seckey,
    secp256k1_pubkey *pubkey,
    const secp256k1_musig_config *musig_config,
    int continuing,
    const unsigned char *privshard,
    size_t my_idx,
    const secp256k1_pubkey *pubcoeff
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(9);

/** Produces a partial signature
 *
 *  Returns: 1: partial signature constructed
 *           0: invalid secret key, invalid keyshards, not enough signers and/or keyshards, calling signer not present
 *  Args:    ctx: pointer to a context object initialized for verification (cannot be NULL)
 *       scratch: scratch space used to compute the total nonce by multiexponentiation
 *  Out:
 *   partial_sig: partial signature (cannot be NULL)
 *           aux: auxillary data needed to verify other partial signatures (cannot be NULL)
 *  In/Out:
 *        secnon: 32-byte secret half of signer's nonce (cannot be NULL). Will be set to 0 during
 *                signing if no adaptor signature is produced, i.e. sec_adaptor is NULL. Fresh
 *                nonces must be generated with secp256k1_musig_multisig_generate_nonce using a
 *                unique rngseed. secnon is a nonce and therefore only to be used ONCE, no more.
 *                One shall be the number of uses, and the number of uses shall be one. Once the
 *                nonce is used in musig_partial_sign it shall be never reused. Failure to do this
 *                will result in the secret key being leaked. If adaptor signatures are produced
 *                then the nonce is effectively the tuple (secnon, sec_adaptor) and every tuple MUST
 *                only be used once. In practice that means calling partial_sign with (secnon,
 *                sec_adaptor) and then with (secnon, NULL).
 *  In: musig_config: MuSig configuration (cannot be NULL)
 *            seckey: secret signing key to use (cannot be NULL)
 *             msg32: 32-byte message to be signed (cannot be NULL)
 *              data: array of public nonces and/or keyshards of all signers including this signer (cannot be NULL).
 *                    The order of signers must be the same as in combine_pubkey.
 *          my_index: index of the caller in the array of signer data
 *       sec_adaptor: 32-byte secret value to be subtracted from the signature, if an adaptor
 *                    signature is to be produced. Should be set to NULL for a normal
 *                    partial signature.
 */
SECP256K1_API int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_musig_partial_signature *partial_sig,
    secp256k1_musig_validation_aux *aux,
    unsigned char *secnon,
    const secp256k1_musig_config *musig_config,
    const secp256k1_musig_secret_key *seckey,
    const unsigned char *msg32,
    const secp256k1_musig_signer_data *data,
    size_t my_index,
    const unsigned char *sec_adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9);

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

/** Extracts the public tweak implied by an adaptor signature
 *
 *  Returns: 1: adaptor signature was correctly encoded and had nontrivial tweak
 *           0: invalid adaptor signature or valid (untweaked) partial signature
 *  Args:         ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *  Out:     pub_tweak: public tweak (cannot be NULL)
 *  In:   partial_sig: adaptor signature to extract tweak from (cannot be NULL)
 *               data: signer data for this signer (not the whole array) (cannot be NULL)
 *                aux: auxillary partial-signature validation data (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_adaptor_signature_extract(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pub_tweak,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_signer_data *data,
    const secp256k1_musig_validation_aux *aux
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Converts an adaptor signature to a partial signature by adding a given tweak
 *
 *  Returns: 1: signature and tweak contained valid values
 *           0: otherwise
 *  Args:         ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *  Out:  partial_sig: partial signature to produce (cannot be NULL)
 *  In:   adaptor_sig: adaptor signature to tweak (cannot be NULL)
 *        sec_adaptor: tweak to apply
 */
SECP256K1_API int secp256k1_musig_adaptor_signature_adapt(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_partial_signature *adaptor_sig,
    const unsigned char *sec_adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Combines partial signatures
 *
 *  Returns: 1: all partial signatures had valid data. Does NOT mean the resulting signature is valid.
 *           0: some partial signature had s/r out of range
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:          sig: complete signature (cannot be NULL)
 *  In:  musig_config: MuSig configuration (cannot be NULL)
 *        partial_sig: array of partial signatures to combine (cannot be NULL)
 *             n_sigs: number of signatures in the above array
 *               data: signer data of all signers including missing ones (cannot be NULL).
 *                     The order of signers must be the same as in combine_pubkey.
 *                aux: auxillary data from `partial_sign` (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_combine(
    const secp256k1_context* ctx,
    secp256k1_musig_signature *sig,
    const secp256k1_musig_config *musig_config,
    const secp256k1_musig_partial_signature *partial_sig,
    size_t n_sigs,
    const secp256k1_musig_signer_data *data,
    const secp256k1_musig_validation_aux *aux
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7);

/** Extracts a secret from a complete signature and an earlier-received adaptor signature
 *
 *  Returns: 1: successfully extracted the secret
 *           0: signatures were invalid or didn't have same nonce
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  sec_adaptor: pointer to array to be filled with 32-byte extracted secret (cannot be NULL)
 *  In:  musig_config: MuSig configuration (cannot be NULL)
 *           full_sig: complete signature (cannot be NULL)
 *        partial_sig: partial non-adaptor signature (in a many-party scheme this should be the
 *                     sum of all partial signatures that are not the adaptor signature) (cannot be NULL)
 *        adaptor_sig: adaptor signature to extract secret from (cannot be NULL)
 *                aux: auxillary data from `partial_sign` (cannot be NULL if Taproot is used)
 */
SECP256K1_API int secp256k1_musig_adaptor_signature_extract_secret(
    const secp256k1_context* ctx,
    unsigned char *sec_adaptor,
    const secp256k1_musig_config *musig_config,
    const secp256k1_musig_signature *full_sig,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_partial_signature *adaptor_sig,
    const secp256k1_musig_validation_aux *aux
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Uses a secret to adapt an adaptor signature into a partial signature
 *
 *  Returns: 1: success
 *           0: invalid adaptor signature or secret
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  partial_sig: partial signature (cannot be NULL)
 *  In:   adaptor_sig: adaptor signature (cannot be NULL)
 *        sec_adaptor: 32-byte secret to tweak adaptor signature with (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_adaptor_signature_apply_secret(
    const secp256k1_context* ctx,
    secp256k1_musig_signature *partial_sig,
    const secp256k1_musig_signature *adaptor_sig,
    const unsigned char *sec_adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

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
 *            tweak32: array of committed 32-byte data, or NULL if there are no Taproot commitments
 *           n_tweaks: array of elements in above array
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
