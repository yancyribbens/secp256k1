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
