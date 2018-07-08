/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_MAIN_
#define _SECP256K1_MODULE_MUSIG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_musig.h"
#include "hash.h"

/* Partial signature data structure:
 * 32 bytes partial s
 * 1 byte indicating whether the public nonce should be flipped
 *
 * Aux data structure:
 * 32 bytes message hash
 * 32 bytes R.x
 */

static int taproot_hash_default(unsigned char *tweak32, const secp256k1_pubkey *pk, const unsigned char *commit, void *data) {
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    secp256k1_ge pkg;
    secp256k1_sha256 sha;

    (void) data;

    secp256k1_pubkey_load(NULL, &pkg, pk);
    secp256k1_eckey_pubkey_serialize(&pkg, buf, &buflen, 1);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, buf, 33);
    secp256k1_sha256_write(&sha, commit, 32);
    secp256k1_sha256_finalize(&sha, tweak32);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, tweak32, 32);
    secp256k1_sha256_finalize(&sha, tweak32);

    return 1;
}

const secp256k1_taproot_hash_function secp256k1_taproot_hash_default = taproot_hash_default;

int secp256k1_musig_signature_serialize(const secp256k1_context* ctx, unsigned char *out64, const secp256k1_musig_signature* sig) {
    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out64 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out64, sig->data, 64);
    return 1;
}

int secp256k1_musig_signature_parse(const secp256k1_context* ctx, secp256k1_musig_signature* sig, const unsigned char *in64) {
    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in64 != NULL);
    memcpy(sig->data, in64, 64);
    return 1;
}

static void secp256k1_musig_coefficient(secp256k1_scalar *r, const unsigned char *ell, size_t idx) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, ell, 32);
    while (idx > 0) {
        unsigned char c = idx;
        secp256k1_sha256_write(&sha, &c, 1);
        idx /= 0x100;
    }
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(r, buf, NULL);
}

static int secp256k1_musig_compute_ell(const secp256k1_context *ctx, unsigned char *ell, const secp256k1_pubkey *pk, size_t np) {
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[33];
        size_t serlen = sizeof(ser);
        if (!secp256k1_ec_pubkey_serialize(ctx, ser, &serlen, &pk[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        secp256k1_sha256_write(&sha, ser, serlen);
    }
    secp256k1_sha256_finalize(&sha, ell);
    return 1;
}

int secp256k1_musig_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *tweaked_pk, secp256k1_pubkey *combined_pk, const secp256k1_pubkey *pk, size_t np) {
    size_t i;
    unsigned char ell[32];
    secp256k1_gej musigj;
    secp256k1_ge musigp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pk != NULL);

    if (!secp256k1_musig_compute_ell(ctx, ell, pk, np)) {
        return 0;
    }

    secp256k1_gej_set_infinity(&musigj);
    for (i = 0; i < np; i++) {
        secp256k1_gej termj;
        secp256k1_gej pkj;
        secp256k1_ge pkp;
        secp256k1_scalar mc;

        if (!secp256k1_pubkey_load(ctx, &pkp, &pk[i])) {
            return 0;
        }
        secp256k1_gej_set_ge(&pkj, &pkp);
        secp256k1_musig_coefficient(&mc, ell, i);
        secp256k1_ecmult(&ctx->ecmult_ctx, &termj, &pkj, &mc, NULL);

        secp256k1_gej_add_var(&musigj, &musigj, &termj, NULL);

        if (tweaked_pk != NULL) {
            secp256k1_ge_set_gej(&pkp, &termj);
            secp256k1_pubkey_save(&tweaked_pk[i], &pkp);
        }
    }
    if (secp256k1_gej_is_infinity(&musigj)) {
        return 0;
    }

    secp256k1_ge_set_gej(&musigp, &musigj);
    secp256k1_pubkey_save(combined_pk, &musigp);
    return 1;
}

int secp256k1_musig_tweak_secret_key(const secp256k1_context* ctx, secp256k1_musig_secret_key *out, const unsigned char *seckey, const secp256k1_pubkey *pk, size_t np, size_t my_index) {
    int overflow;
    unsigned char ell[32];
    secp256k1_scalar x, y;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(pk != NULL);

    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_musig_compute_ell(ctx, ell, pk, np)) {
        return 0;
    }
    secp256k1_musig_coefficient(&y, ell, my_index);

    secp256k1_scalar_mul(&x, &x, &y);
    secp256k1_scalar_get_b32(out->data, &x);

    return 1;
}

int secp256k1_musig_single_sign(const secp256k1_context* ctx, secp256k1_musig_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata) {
    secp256k1_scalar x;
    int overflow;
    int ret = 0;
    secp256k1_gej pkj;
    secp256k1_ge pk;
    unsigned count = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey != NULL);

    if (noncefp == NULL) {
        noncefp = nonce_function_bitmetas;
    }
    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || secp256k1_scalar_is_zero(&x)) {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pkj, &x);
    secp256k1_ge_set_gej(&pk, &pkj);

    do {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        secp256k1_scalar k;

        ret = noncefp(ctx, buf, msg32, seckey, NULL, (void*)ndata, count);
        secp256k1_scalar_set_b32(&k, buf, NULL);
        ret &= !secp256k1_scalar_is_zero(&k);

        if (ret == 1) {
            secp256k1_sha256 sha;
            secp256k1_gej rj;
            secp256k1_ge r;
            secp256k1_scalar e;

            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
            secp256k1_ge_set_gej(&r, &rj);

            if (!secp256k1_fe_is_quad_var(&r.y)) {
                secp256k1_scalar_negate(&k, &k);
            }
            secp256k1_fe_normalize(&r.x);
            secp256k1_fe_get_b32(&sig->data[0], &r.x);

            secp256k1_sha256_initialize(&sha);
            secp256k1_sha256_write(&sha, &sig->data[0], 32);
            secp256k1_eckey_pubkey_serialize(&pk, buf, &buflen, 1);
            secp256k1_sha256_write(&sha, buf, buflen);
            secp256k1_sha256_write(&sha, msg32, 32);
            secp256k1_sha256_finalize(&sha, buf);

            secp256k1_scalar_set_b32(&e, buf, NULL);
            ret &= !secp256k1_scalar_is_zero(&e);

            secp256k1_scalar_mul(&e, &e, &x);
            secp256k1_scalar_add(&e, &e, &k);

            secp256k1_scalar_get_b32(&sig->data[32], &e);
            secp256k1_scalar_clear(&x);
            secp256k1_scalar_clear(&k);
        }
        count++;
    } while (ret == 0);
    secp256k1_scalar_clear(&x);

    return 1;
}

int secp256k1_musig_signer_data_initialize(const secp256k1_context* ctx, secp256k1_musig_signer_data *data, const secp256k1_pubkey *pubkey, const unsigned char *noncommit) {
    (void) ctx;
    ARG_CHECK(data != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(data, 0, sizeof(*data));
    memcpy(&data->pubkey, pubkey, sizeof(*pubkey));
    if (noncommit != NULL) {
        memcpy(data->noncommit, noncommit, 32);
    }
    return 1;
}

int secp256k1_musig_multisig_generate_nonce(const secp256k1_context* ctx, unsigned char *secnon, secp256k1_pubkey *pubnon, unsigned char *noncommit, const secp256k1_musig_secret_key *seckey, const unsigned char *msg32, const unsigned char *rngseed) {
    unsigned char commit[33];
    size_t commit_size = sizeof(commit);
    secp256k1_sha256 sha;
    secp256k1_scalar secs;
    secp256k1_gej rj;
    secp256k1_ge rp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secnon != NULL);
    ARG_CHECK(pubnon != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(rngseed != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, seckey->data, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_write(&sha, rngseed, 32);
    secp256k1_sha256_finalize(&sha, secnon);

    secp256k1_scalar_set_b32(&secs, secnon, NULL);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &secs);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(pubnon, &rp);

    if (noncommit != NULL) {
        secp256k1_sha256_initialize(&sha);
        secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, pubnon, SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, commit, commit_size);
        secp256k1_sha256_finalize(&sha, noncommit);
    }
    return 1;
}

int secp256k1_musig_set_nonce(const secp256k1_context* ctx, secp256k1_musig_signer_data *data, const secp256k1_pubkey *pubnon) {
    unsigned char commit[33];
    size_t commit_size = sizeof(commit);
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(pubnon != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, pubnon, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, commit, commit_size);
    secp256k1_sha256_finalize(&sha, commit);

    if (memcmp(commit, data->noncommit, 32) != 0) {
        return 0;
    }
    memcpy(&data->pubnon, pubnon, sizeof(*pubnon));
    data->present = 1;
    return 1;
}

/* `data` is just used as a binary array indicating which signers are present, i.e.
 * which ones to exclude from the interpolation. */
static void secp256k1_musig_lagrange_coefficient(secp256k1_scalar *r, const secp256k1_musig_signer_data *data, size_t n_indices, size_t coeff_index, int invert) {
    size_t i;
    int kofn;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar indexs;

    /* Special-case the n-of-n case where all our "Lagrange coefficients" should be 1,
     * since in that case we do a simple sum rather than polynomial interpolation */
    kofn = 0;
    for (i = 0; i < n_indices; i++) {
        if (data[i].present == 0) {
            kofn = 1;
            break;
        }
    }
    if (!kofn) {
        secp256k1_scalar_set_int(r, 1);
        return;
    }

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    secp256k1_scalar_set_int(&indexs, (int) coeff_index + 1);
    for (i = 0; i < n_indices; i++) {
        secp256k1_scalar mul;
        if ((data[i].present == 0) || i == coeff_index) {
            continue;
        }

        secp256k1_scalar_set_int(&mul, (int) i + 1);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);

        secp256k1_scalar_add(&mul, &mul, &indexs);
        secp256k1_scalar_mul(&den, &den, &mul);
    }

    if (invert) {
        secp256k1_scalar_inverse_var(&num, &num);
    } else {
        secp256k1_scalar_inverse_var(&den, &den);
    }
    secp256k1_scalar_mul(r, &num, &den);
}

int secp256k1_musig_keysplit(const secp256k1_context *ctx, unsigned char *const *shards, secp256k1_pubkey *pubcoeff, const secp256k1_musig_secret_key *seckey, const size_t k, const size_t n, const unsigned char *rngseed) {
    size_t i;
    int overflow;
    secp256k1_scalar init;
    secp256k1_scalar rand[2];
    secp256k1_gej rj;
    secp256k1_ge rp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(shards != NULL);
    ARG_CHECK(pubcoeff != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(rngseed != NULL);

    if (k == 0 || k >= n) {
        return 0;
    }
    secp256k1_scalar_set_b32(&init, seckey->data, &overflow);
    /* Reject invalid secret keys */
    if (overflow) {
        return 0;
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &init);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(&pubcoeff[0], &rp);

    for (i = 0; i < n; i++) {
        secp256k1_scalar shard_i;
        secp256k1_scalar scalar_i;
        size_t j;

        secp256k1_scalar_clear(&shard_i);
        secp256k1_scalar_set_int(&scalar_i, i + 1);
        for (j = 0; j < k - 1; j++) {
            if (j % 2 == 0) {
                secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, j);
            }
            secp256k1_scalar_add(&shard_i, &shard_i, &rand[j % 2]);
            secp256k1_scalar_mul(&shard_i, &shard_i, &scalar_i);
        }
        secp256k1_scalar_add(&shard_i, &shard_i, &init);
        secp256k1_scalar_get_b32(shards[i], &shard_i);
    }

    for (i = 0; i < k-1; i++) {
        if (i % 2 == 0) {
            secp256k1_scalar_chacha20(&rand[0], &rand[1], rngseed, i);
        }
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &rand[i % 2]);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubcoeff[k - i - 1], &rp);
    }

    return 1;
}

typedef struct {
    secp256k1_scalar idx;
    secp256k1_scalar idxn;
    const secp256k1_pubkey *pubcoeff;
} secp256k1_musig_verify_shard_ecmult_context;

static int secp256k1_musig_verify_shard_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_verify_shard_ecmult_context *ctx = (secp256k1_musig_verify_shard_ecmult_context *) data;

    *sc = ctx->idxn;
    secp256k1_scalar_mul(&ctx->idxn, &ctx->idxn, &ctx->idx);
    secp256k1_pubkey_load(NULL, pt, &ctx->pubcoeff[idx]);
    return 1;
}

int secp256k1_musig_verify_shard(const secp256k1_context *ctx, secp256k1_scratch *scratch, secp256k1_musig_secret_key *seckey, secp256k1_pubkey *pubkey, size_t n_keys, int continuing, const unsigned char *privshard, size_t my_idx, const secp256k1_pubkey *pubcoeff, size_t n_coeffs) {
    secp256k1_musig_verify_shard_ecmult_context ecmult_data;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(pubcoeff != NULL);

    ecmult_data.pubcoeff = pubcoeff;

    /* For each participant... */
    for (i = 0; i < n_keys; i++) {
        secp256k1_ge shardp;
        secp256k1_gej shardj;

        /* ...compute the participant's public shard by evaluating the public polynomial at their index */
        secp256k1_scalar_set_int(&ecmult_data.idx, i + 1);
        secp256k1_scalar_set_int(&ecmult_data.idxn, 1);

        if (!secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &shardj, NULL, secp256k1_musig_verify_shard_ecmult_callback, (void *) &ecmult_data, n_coeffs)) {
            return 0;
        }

        /* If we computed our _own_ public shard, check that it is consistent with our private
         * shard. This check is equation (*) in the Pedersen VSS paper. This is the only part
         * of the function that handles secret data and which must be constant-time. */
        if (i == my_idx && privshard != NULL) {
            int overflow;
            secp256k1_gej expectedj;
            secp256k1_scalar shards;
            secp256k1_scalar_set_b32(&shards, privshard, &overflow);
            if (overflow) {
                return 0;
            }
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &expectedj, &shards);
            secp256k1_gej_neg(&expectedj, &expectedj);
            secp256k1_gej_add_var(&expectedj, &expectedj, &shardj, NULL);
            if (!secp256k1_gej_is_infinity(&expectedj)) {
                return 0;
            }

            if (seckey != NULL) {
                if (continuing) {
                    secp256k1_scalar current;
                    secp256k1_scalar_set_b32(&current, seckey->data, &overflow);
                    if (overflow) {
                        return 0;
                    }
                    secp256k1_scalar_add(&shards, &shards, &current);
                }
                secp256k1_scalar_get_b32(seckey->data, &shards);
            }
        }

        /* Add the shard to the public key we expect them to use when signing (well, when
         * signing they will additionally multiply the pubkey by a Lagrange coefficient,
         * but this cannot be determined until signing time). */
        if (continuing) {
            secp256k1_ge ge;
            if (!secp256k1_pubkey_load(ctx, &ge, &pubkey[i])) {
                return 0;
            }
            secp256k1_gej_add_ge_var(&shardj, &shardj, &ge, NULL);
        }
        if (secp256k1_gej_is_infinity(&shardj)) {
            return 0;
        }
        secp256k1_ge_set_gej(&shardp, &shardj);
        secp256k1_pubkey_save(&pubkey[i], &shardp);
    }

    return 1;
}

typedef struct {
    size_t index;
    size_t n_signers;
    const secp256k1_musig_signer_data *data;
} secp256k1_musig_nonce_ecmult_context;

static int secp256k1_musig_nonce_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_nonce_ecmult_context *ctx = (secp256k1_musig_nonce_ecmult_context *) data;

    (void) idx;
    while (!ctx->data[ctx->index].present) {
        ctx->index++;
    }
    secp256k1_musig_lagrange_coefficient(sc, ctx->data, ctx->n_signers, ctx->index, 0);
    if (!secp256k1_pubkey_load(NULL, pt, &ctx->data[ctx->index].pubnon)) {
        return 0;
    }
    ctx->index++;
    return 1;
}

int secp256k1_musig_partial_sign(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, secp256k1_musig_partial_signature *sig, secp256k1_musig_validation_aux *aux, const secp256k1_musig_secret_key *seckey, const secp256k1_pubkey *combined_pk, const unsigned char *msg32, const unsigned char *secnon, const secp256k1_musig_signer_data *data, size_t n_signers, size_t my_index, const unsigned char *sec_adaptor) {
    secp256k1_musig_nonce_ecmult_context ecmult_data;
    unsigned char buf[33];
    size_t bufsize = 33;
    secp256k1_gej total_rj;
    secp256k1_ge total_r;
    secp256k1_sha256 sha;
    size_t i;
    size_t n_present;
    int overflow;
    secp256k1_scalar sk;
    secp256k1_scalar e, k;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(aux != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(secnon != NULL);
    ARG_CHECK(data != NULL);

    /* Should this be an ARG_CHECK ? */
    if (!data[my_index].present) {
        return 0;
    }

    secp256k1_scalar_set_b32(&sk, seckey->data, &overflow);
    if (overflow) {
        return 0;
    }

    secp256k1_scalar_set_b32(&k, secnon, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k)) {
        return 0;
    }

    /* compute aggregate R, saving partial-R in the partial_signature structure */
    n_present = 0;
    for (i = 0; i < n_signers; i++) {
        if (data[i].present != 0) {
            n_present++;
        }
    }
    ecmult_data.index = 0;
    ecmult_data.n_signers = n_signers;
    ecmult_data.data = data;
    if (!secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &total_rj, NULL, secp256k1_musig_nonce_ecmult_callback, (void *) &ecmult_data, n_present)) {
        return 0;
    }
    if (secp256k1_gej_is_infinity(&total_rj)) {
        return 0;
    }
    if (!secp256k1_gej_has_quad_y_var(&total_rj)) {
        secp256k1_gej_neg(&total_rj, &total_rj);
        secp256k1_scalar_negate(&k, &k);
        sig->data[32] = 1;
    } else {
        sig->data[32] = 0;
    }
    secp256k1_ge_set_gej(&total_r, &total_rj);

    /* build message hash */
    secp256k1_sha256_initialize(&sha);
    secp256k1_fe_normalize(&total_r.x);
    secp256k1_fe_get_b32(buf, &total_r.x);
    secp256k1_sha256_write(&sha, buf, 32);
    memcpy(&aux->data[32], buf, 32);
    secp256k1_ec_pubkey_serialize(ctx, buf, &bufsize, combined_pk, SECP256K1_EC_COMPRESSED);
    VERIFY_CHECK(bufsize == 33);
    secp256k1_sha256_write(&sha, buf, bufsize);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, aux->data);

    secp256k1_scalar_set_b32(&e, aux->data, NULL);

    /* Sign */
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    if (sec_adaptor != NULL) {
        secp256k1_scalar offs;
        secp256k1_scalar_set_b32(&offs, sec_adaptor, &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_negate(&offs, &offs);
        secp256k1_scalar_add(&e, &e, &offs);
    }
    secp256k1_scalar_get_b32(&sig->data[0], &e);
    secp256k1_scalar_clear(&sk);
    secp256k1_scalar_clear(&k);

    return 1;
}

int secp256k1_musig_partial_sig_combine(const secp256k1_context* ctx, secp256k1_musig_signature *sig, const secp256k1_musig_partial_signature *partial_sig, size_t n_sigs, const secp256k1_musig_signer_data *data, size_t n_signers, const secp256k1_musig_validation_aux *aux, const unsigned char *taproot_tweak) {
    size_t i, j;
    secp256k1_scalar s;
    secp256k1_ge rp;
    secp256k1_gej rj;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(aux != NULL);
    ARG_CHECK(n_signers >= n_sigs);

    secp256k1_scalar_clear(&s);
    secp256k1_gej_set_infinity(&rj);
    j = 0;
    for (i = 0; i < n_signers; i++) {
        int overflow;
        secp256k1_scalar term;
        secp256k1_scalar coeff;

        if (!data[i].present) {
            continue;
        }

        secp256k1_scalar_set_b32(&term, partial_sig[j].data, &overflow);
        if (overflow) {
            return 0;
        }
        if (!secp256k1_pubkey_load(ctx, &rp, &data[i].pubnon)) {
            return 0;
        }

        secp256k1_musig_lagrange_coefficient(&coeff, data, n_signers, i, 0);
        secp256k1_scalar_mul(&term, &term, &coeff);
        secp256k1_scalar_add(&s, &s, &term);
        j++;
    }
    if (j != n_sigs) {
        return 0;
    }

    /* Add taproot tweak to final signature */
    if (taproot_tweak != NULL) {
        secp256k1_scalar tweaks;
        secp256k1_scalar e;

        secp256k1_scalar_set_b32(&tweaks, taproot_tweak, NULL);
        secp256k1_scalar_set_b32(&e, aux->data, NULL);
        secp256k1_scalar_mul(&tweaks, &tweaks, &e);
        secp256k1_scalar_add(&s, &s, &tweaks);
    }

    memcpy(&sig->data[0], &aux->data[32], 32);
    secp256k1_scalar_get_b32(&sig->data[32], &s);

    return 1;
}

int secp256k1_musig_adaptor_signature_extract_secret(const secp256k1_context* ctx, unsigned char *sec_adaptor, const secp256k1_musig_signature *full_sig, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_partial_signature *adaptor_sig, const secp256k1_musig_validation_aux *aux, const unsigned char *taproot_tweak) {
    secp256k1_scalar s;
    secp256k1_scalar term;
    int overflow;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor != NULL);
    ARG_CHECK(full_sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    if (taproot_tweak != NULL) {
        ARG_CHECK(aux != NULL);
    }

    secp256k1_scalar_set_b32(&s, &full_sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&term, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&term, &term);
    secp256k1_scalar_add(&s, &s, &term);
    secp256k1_scalar_set_b32(&term, adaptor_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&term, &term);
    secp256k1_scalar_add(&s, &s, &term);

    if (taproot_tweak != NULL) {
        secp256k1_scalar tweaks;
        secp256k1_scalar e;

        secp256k1_scalar_set_b32(&tweaks, taproot_tweak, NULL);
        secp256k1_scalar_set_b32(&e, aux->data, NULL);
        secp256k1_scalar_mul(&tweaks, &tweaks, &e);
        secp256k1_scalar_negate(&tweaks, &tweaks);
        secp256k1_scalar_add(&s, &s, &tweaks);
    }

    secp256k1_scalar_get_b32(sec_adaptor, &s);
    return 1;
}

int secp256k1_musig_adaptor_signature_adapt(const secp256k1_context* ctx, secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_partial_signature *adaptor_sig, const unsigned char *sec_adaptor) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;

    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    ARG_CHECK(sec_adaptor != NULL);

    secp256k1_scalar_set_b32(&s, adaptor_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor, &overflow);
    if (overflow) {
        return 0;
    }

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(partial_sig->data, &s);
    partial_sig->data[32] = adaptor_sig->data[32];

    return 1;
}

int secp256k1_musig_adaptor_signature_apply_secret(const secp256k1_context* ctx, secp256k1_musig_signature *partial_sig, const secp256k1_musig_signature *adaptor_sig, const unsigned char *sec_adaptor) {
    secp256k1_scalar s;
    secp256k1_scalar term;
    int overflow;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    ARG_CHECK(sec_adaptor != NULL);

    secp256k1_scalar_set_b32(&s, &adaptor_sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&term, sec_adaptor, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_add(&s, &s, &term);

    memcpy(&partial_sig->data[0], &adaptor_sig->data[0], 32);
    secp256k1_scalar_get_b32(&partial_sig->data[32], &s);
    return 1;
}

/* Helper function that computes R = sG - eP */
static int secp256k1_musig_real_verify(const secp256k1_context* ctx, secp256k1_gej *rj, const secp256k1_scalar *s, const secp256k1_scalar *e, const secp256k1_pubkey *pk) {
    secp256k1_scalar nege;
    secp256k1_ge pkp;
    secp256k1_gej pkj;

    secp256k1_scalar_negate(&nege, e);

    if (!secp256k1_pubkey_load(ctx, &pkp, pk)) {
        return 0;
    }
    secp256k1_gej_set_ge(&pkj, &pkp);

    secp256k1_ecmult(&ctx->ecmult_ctx, rj, &pkj, &nege, s);
    return 1;
}

int secp256k1_musig_adaptor_signature_extract(const secp256k1_context* ctx, secp256k1_pubkey *pub_adaptor, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_signer_data *data, const secp256k1_musig_validation_aux *aux) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pub_adaptor != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(aux != NULL);

    if (!data->present) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&e, aux->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_pubkey_load(ctx, &rp, &data->pubkey);

    if (!secp256k1_pubkey_load(ctx, &rp, &data->pubnon)) {
        return 0;
    }

    if (!secp256k1_musig_real_verify(ctx, &rj, &s, &e, &data->pubkey)) {
        return 0;
    }
    if (!partial_sig->data[32]) {
        secp256k1_ge_neg(&rp, &rp);
    }

    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);
    if (secp256k1_gej_is_infinity(&rj)) {
        return 0;
    }

    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(pub_adaptor, &rp);
    return 1;
}

int secp256k1_musig_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_signer_data *data, const secp256k1_musig_validation_aux *aux) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(aux != NULL);

    if (!data->present) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&e, aux->data, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &rp, &data->pubnon)) {
        return 0;
    }

    if (!secp256k1_musig_real_verify(ctx, &rj, &s, &e, &data->pubkey)) {
        return 0;
    }
    if (!partial_sig->data[32]) {
        secp256k1_ge_neg(&rp, &rp);
    }
    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);

    return secp256k1_gej_is_infinity(&rj);
}

int secp256k1_musig_verify_1(const secp256k1_context* ctx, const secp256k1_musig_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pk) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_fe rx;
    secp256k1_sha256 sha;
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(sig != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(pk != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, &sig->data[0], 32);
    secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pk, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, buf, buflen);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(&s, &sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&e, buf, NULL);

    if (!secp256k1_fe_set_b32(&rx, &sig->data[0]) ||
        !secp256k1_musig_real_verify(ctx, &rj, &s, &e, pk) ||
        !secp256k1_gej_has_quad_y_var(&rj) ||
        !secp256k1_gej_eq_x_var(&rx, &rj)) {
        return 0;
    }

    return 1;
}

typedef struct {
    const secp256k1_context *ctx;
    unsigned char chacha_seed[32];
    secp256k1_scalar randomizer_cache[2];
    const secp256k1_musig_signature *const *sig;
    const unsigned char *const *msg32;
    const secp256k1_pubkey *const *pk;
    secp256k1_ge *taproot_pkdiff;
    size_t n_sigs;
} secp256k1_musig_verify_ecmult_context;

/*
 * Fills r[0] and r[1] with randomizer scalars to be used in batch
 * verification.
 */
static void secp256k1_musig_batch_randomizer(secp256k1_scalar *r, const unsigned char *seed, uint64_t idx) {
    secp256k1_scalar_chacha20(&r[0], &r[1], seed, idx);
    if(idx == 0) {
        secp256k1_scalar_set_int(&r[0], 1);
    }
}

static int secp256k1_musig_verify_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_verify_ecmult_context *ctx = (secp256k1_musig_verify_ecmult_context *) data;

    if (idx < 2 * ctx->n_sigs) {
        if (idx % 4 == 0) {
            secp256k1_musig_batch_randomizer(ctx->randomizer_cache, ctx->chacha_seed, idx / 4);
        }

        /* -R */
        if (idx % 2 == 0) {
            secp256k1_fe rx;
            secp256k1_scalar_negate(sc, &ctx->randomizer_cache[(idx / 2) % 2]);
            if (!secp256k1_fe_set_b32(&rx, &ctx->sig[idx / 2]->data[0])) {
                return 0;
            }
            if (!secp256k1_ge_set_xquad(pt, &rx)) {
                return 0;
            }
        /* -eP */
        } else {
            unsigned char buf[33];
            size_t buflen = sizeof(buf);
            secp256k1_sha256 sha;
            secp256k1_sha256_initialize(&sha);
            secp256k1_sha256_write(&sha, &ctx->sig[idx / 2]->data[0], 32);
            secp256k1_ec_pubkey_serialize(ctx->ctx, buf, &buflen, ctx->pk[idx / 2], SECP256K1_EC_COMPRESSED);
            secp256k1_sha256_write(&sha, buf, buflen);
            secp256k1_sha256_write(&sha, ctx->msg32[idx / 2], 32);
            secp256k1_sha256_finalize(&sha, buf);

            secp256k1_scalar_set_b32(sc, buf, NULL);
            secp256k1_scalar_negate(sc, sc);
            secp256k1_scalar_mul(sc, sc, &ctx->randomizer_cache[(idx / 2) % 2]);

            if (!secp256k1_pubkey_load(ctx->ctx, pt, ctx->pk[idx / 2])) {
                return 0;
            }
        }
    } else {
        if (idx % 2 == 0) {
            secp256k1_musig_batch_randomizer(ctx->randomizer_cache, ctx->chacha_seed, idx / 2);
        }
        *sc = ctx->randomizer_cache[idx % 2];
        *pt = ctx->taproot_pkdiff[idx - 2 * ctx->n_sigs];
    }

    return 1;
}

int secp256k1_musig_verify(const secp256k1_context* ctx, secp256k1_scratch *scratch, const secp256k1_musig_signature *const *sig, const unsigned char *const *msg32, const secp256k1_pubkey *const *pk, size_t n_sigs, const secp256k1_pubkey *const *taproot_untweaked, const secp256k1_pubkey *const *taproot_tweaked, const unsigned char *const *tweak32, size_t n_tweaks, secp256k1_taproot_hash_function hashfp, void *hdata) {
    secp256k1_musig_verify_ecmult_context ecmult_data;
    size_t i;
    secp256k1_sha256 sha;
    secp256k1_scalar s;
    secp256k1_gej rj;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    if (n_sigs > 0) {
        ARG_CHECK(sig != NULL);
        ARG_CHECK(msg32 != NULL);
        ARG_CHECK(pk != NULL);
    }
    if (n_tweaks > 0) {
        ARG_CHECK(taproot_untweaked != NULL);
        ARG_CHECK(taproot_tweaked != NULL);
        ARG_CHECK(tweak32 != NULL);
    }

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < n_sigs; i++) {
        secp256k1_sha256_write(&sha, sig[i]->data, 64);
    }
    for (i = 0; i < n_tweaks; i++) {
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        ARG_CHECK(taproot_untweaked != NULL);
        ARG_CHECK(taproot_tweaked != NULL);
        ARG_CHECK(tweak32 != NULL);

        secp256k1_sha256_write(&sha, tweak32[i], 32);
        secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, taproot_untweaked[i], SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, buf, 33);
        secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, taproot_tweaked[i], SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, buf, 33);
    }
    secp256k1_sha256_finalize(&sha, ecmult_data.chacha_seed);
    ecmult_data.ctx = ctx;
    ecmult_data.sig = sig;
    ecmult_data.msg32 = msg32;
    ecmult_data.pk = pk;
    ecmult_data.n_sigs = n_sigs;

    secp256k1_scalar_clear(&s);

    if (n_tweaks > 0) {
        secp256k1_gej *tmpj;

        if (secp256k1_scratch_allocate_frame(scratch, n_tweaks * sizeof(secp256k1_ge), 1) == 0) {
            return 0;
        }
        ecmult_data.taproot_pkdiff = (secp256k1_ge *)secp256k1_scratch_alloc(scratch, n_tweaks * sizeof(secp256k1_ge));

        if (secp256k1_scratch_allocate_frame(scratch, n_tweaks * sizeof(secp256k1_gej), 1) == 0) {
            secp256k1_scratch_deallocate_frame(scratch);
            return 0;
        }
        tmpj = (secp256k1_gej *)secp256k1_scratch_alloc(scratch, n_tweaks * sizeof(*tmpj));

        if (hashfp == NULL) {
            hashfp = secp256k1_taproot_hash_default;
        }

        for (i = 0; i < n_tweaks; i++) {
            secp256k1_ge untweaked;
            secp256k1_ge tweaked;
            unsigned char tweak[32];
            secp256k1_scalar tweaks;

            /* compute tweaked - untweaked point */
            secp256k1_pubkey_load(ctx, &untweaked, taproot_untweaked[i]);
            secp256k1_pubkey_load(ctx, &tweaked, taproot_tweaked[i]);

            secp256k1_gej_set_ge(&tmpj[i], &tweaked);
            secp256k1_gej_neg(&tmpj[i], &tmpj[i]);
            secp256k1_gej_add_ge_var(&tmpj[i], &tmpj[i], &untweaked, NULL);

            /* compute (rerandomized) addition to s */
            if (i % 2 == 0) {
                secp256k1_musig_batch_randomizer(ecmult_data.randomizer_cache, ecmult_data.chacha_seed, n_sigs + i / 2);
            }
            if(!hashfp(tweak, taproot_untweaked[i], tweak32[i], hdata)) {
                secp256k1_scratch_deallocate_frame(scratch);
                secp256k1_scratch_deallocate_frame(scratch);
                return 0;
            }
            secp256k1_scalar_set_b32(&tweaks, tweak, NULL);
            secp256k1_scalar_mul(&tweaks, &tweaks, &ecmult_data.randomizer_cache[i % 2]);
            secp256k1_scalar_add(&s, &s, &tweaks);
        }
        secp256k1_ge_set_all_gej_var(ecmult_data.taproot_pkdiff, tmpj, n_tweaks);
        secp256k1_scratch_deallocate_frame(scratch);
    }

    for (i = 0; i < n_sigs; i++) {
        int overflow;
        secp256k1_scalar term;
        if (i % 2 == 0) {
            secp256k1_musig_batch_randomizer(ecmult_data.randomizer_cache, ecmult_data.chacha_seed, i / 2);
        }

        secp256k1_scalar_set_b32(&term, &sig[i]->data[32], &overflow);
        if (overflow) {
            ret = 0;
            break;
        }
        secp256k1_scalar_mul(&term, &term, &ecmult_data.randomizer_cache[i % 2]);
        secp256k1_scalar_add(&s, &s, &term);
    }

    ret &= secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &rj, &s, secp256k1_musig_verify_ecmult_callback, (void *) &ecmult_data, 2 * n_sigs + n_tweaks);
    ret &= secp256k1_gej_is_infinity(&rj);

    if (n_tweaks > 0) {
        secp256k1_scratch_deallocate_frame(scratch);
    }

    return ret;
}

#endif
