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

typedef struct {
    unsigned char ell[32]; /* hash of all public keys */
    const secp256k1_pubkey *pk;
} secp256k1_musig_pkcombine_ecmult_context;

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

static int secp256k1_musig_pkcombine_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_pkcombine_ecmult_context *ctx = (secp256k1_musig_pkcombine_ecmult_context *) data;
    secp256k1_pubkey_load(NULL, pt, &ctx->pk[idx]);
    secp256k1_musig_coefficient(sc, ctx->ell, idx);
    return 1;
}

int secp256k1_musig_pubkey_combine(const secp256k1_context* ctx, secp256k1_scratch *scratch, secp256k1_pubkey *combined_pk, secp256k1_pubkey *combined_pk_untweaked, unsigned char *ell, const secp256k1_pubkey *pk, size_t np, const unsigned char *taproot_commit, secp256k1_taproot_hash_function hashfp, void *hdata) {
    size_t i;
    secp256k1_musig_pkcombine_ecmult_context ecmult_data;
    secp256k1_gej musigj;
    secp256k1_ge musigp;
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pk != NULL);

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[33];
        size_t serlen = sizeof(ser);
        secp256k1_ec_pubkey_serialize(ctx, ser, &serlen, &pk[i], SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, ser, serlen);
    }
    secp256k1_sha256_finalize(&sha, ecmult_data.ell);
    if (ell != NULL) {
        memcpy(ell, ecmult_data.ell, 32);
    }
    ecmult_data.pk = pk;

    /* Compute musig combination */
    if (secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &musigj, NULL, secp256k1_musig_pkcombine_ecmult_callback, (void *) &ecmult_data, np) != 1 ||
        secp256k1_gej_is_infinity(&musigj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&musigp, &musigj);
    if (combined_pk_untweaked != NULL) {
        secp256k1_pubkey_save(combined_pk_untweaked, &musigp);
    }

    /* Add taproot tweak */
    if (taproot_commit != NULL) {
        secp256k1_pubkey musigpk;
        unsigned char tweak[32];
        secp256k1_scalar tweaks;
        secp256k1_scalar one;

        if (hashfp == NULL) {
            hashfp = secp256k1_taproot_hash_default;
        }
        secp256k1_pubkey_save(&musigpk, &musigp);
        if (!hashfp(tweak, &musigpk, taproot_commit, hdata)) {
            return 0;
        }

        secp256k1_scalar_set_b32(&tweaks, tweak, NULL);
        secp256k1_scalar_set_int(&one, 1);
        secp256k1_ecmult(&ctx->ecmult_ctx, &musigj, &musigj, &one, &tweaks);
        secp256k1_ge_set_gej(&musigp, &musigj);
    }

    secp256k1_pubkey_save(combined_pk, &musigp);
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

int secp256k1_musig_signer_data_initialize(const secp256k1_context* ctx, secp256k1_musig_signer_data *data, const unsigned char *keyshard, const unsigned char *noncommit) {
    (void) ctx;
    ARG_CHECK(data != NULL);
    ARG_CHECK(keyshard != NULL || noncommit != NULL);
    memset(data, 0, sizeof(*data));
    if (keyshard != NULL) {
        memcpy(data->keyshard, keyshard, 32);
    }
    if (noncommit != NULL) {
        memcpy(data->noncommit, noncommit, 32);
    }
    return 1;
}

int secp256k1_musig_multisig_generate_nonce(const secp256k1_context* ctx, unsigned char *secnon, secp256k1_pubkey *pubnon, unsigned char *noncommit, const unsigned char *seckey, const unsigned char *msg32, const unsigned char *rngseed) {
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
    secp256k1_sha256_write(&sha, seckey, 32);
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
    memset(data->keyshard, 0, 32);
    data->present = 1;
    return 1;
}

/* `data` is just used as a binary array indicating which signers are present, i.e.
 * which ones to exclude from the interpolation. If `data` is NULL assume no signers
 * are present, used when verifying public shards. */
static void secp256k1_musig_lagrange_coefficient(secp256k1_scalar *r, const secp256k1_musig_signer_data *data, size_t n_indices, size_t coeff_index) {
    size_t i;
    secp256k1_scalar num;
    secp256k1_scalar den;
    secp256k1_scalar indexs;

    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);
    secp256k1_scalar_set_int(&indexs, (int) coeff_index + 1);
    for (i = 0; i < n_indices; i++) {
        secp256k1_scalar mul;
        if ((data && data[i].present == 0) || i == coeff_index) {
            continue;
        }

        secp256k1_scalar_set_int(&mul, (int) i + 1);
        secp256k1_scalar_negate(&mul, &mul);
        secp256k1_scalar_mul(&num, &num, &mul);

        secp256k1_scalar_add(&mul, &mul, &indexs);
        secp256k1_scalar_mul(&den, &den, &mul);
    }

    secp256k1_scalar_inverse_var(&den, &den);
    secp256k1_scalar_mul(r, &num, &den);
}

int secp256k1_musig_keysplit(const secp256k1_context *ctx, unsigned char *const *shards, secp256k1_pubkey *pubshard, const unsigned char *seckey, const size_t k, const size_t n, const unsigned char *rngseed) {
    size_t i;
    int overflow;
    secp256k1_scalar init;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(shards != NULL);
    ARG_CHECK(pubshard != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(rngseed != NULL);

    if (k == 0 || k >= n) {
        return 0;
    }
    secp256k1_scalar_set_b32(&init, seckey, &overflow);
    /* Reject invalid secret keys */
    if (overflow) {
        return 0;
    }

    for (i = 0; i < n; i++) {
        secp256k1_gej rj;
        secp256k1_ge rp;
        secp256k1_scalar shard_i;
        secp256k1_scalar scalar_i;
        size_t j;
        secp256k1_scalar rand[2];

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

        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &shard_i);
        secp256k1_ge_set_gej(&rp, &rj);
        secp256k1_pubkey_save(&pubshard[i], &rp);
    }

    return 1;
}

typedef struct {
    const secp256k1_pubkey *shard;
    size_t n_shards;
} secp256k1_musig_verify_shard_ecmult_context;

static int secp256k1_musig_verify_shard_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_verify_shard_ecmult_context *ctx = (secp256k1_musig_verify_shard_ecmult_context *) data;
    secp256k1_pubkey_load(NULL, pt, &ctx->shard[idx]);
    secp256k1_musig_lagrange_coefficient(sc, NULL, ctx->n_shards, idx);
    return 1;
}

int secp256k1_musig_verify_shard(const secp256k1_context *ctx, secp256k1_scratch *scratch, const secp256k1_pubkey *pubkey, const unsigned char *shard, size_t my_idx, const secp256k1_pubkey *pubshard, size_t n_pubshards) {
    secp256k1_musig_verify_shard_ecmult_context ecmult_data;
    secp256k1_scalar shards;
    secp256k1_gej expectedj;
    secp256k1_ge actual;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(pubshard != NULL);

    if (my_idx >= n_pubshards) {
        return 0;
    }

    ecmult_data.shard = pubshard;
    ecmult_data.n_shards = n_pubshards;

    if (shard != NULL) {
        /* Step one: check the secret shard matches its corresponding public shard.
         * Deriving our expected public shard from our secret shard is the only
         * operation in this function that uses secret data and therefore needs to
         * be constant time. Everything else, including the comparison against the
         * actual public shard, can be vartime. */
        secp256k1_scalar_set_b32(&shards, shard, &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &expectedj, &shards);
        secp256k1_pubkey_load(ctx, &actual, &pubshard[my_idx]);
        secp256k1_gej_neg(&expectedj, &expectedj);
        secp256k1_gej_add_ge_var(&expectedj, &expectedj, &actual, NULL);
        if (!secp256k1_gej_is_infinity(&expectedj)) {
            return 0;
        }
    }

    /* Step 2: check that the public shards all add up to the expect pubkey */
    if (!secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &expectedj, NULL, secp256k1_musig_verify_shard_ecmult_callback, (void *) &ecmult_data, n_pubshards)) {
        return 0;
    }
    secp256k1_gej_neg(&expectedj, &expectedj);
    secp256k1_pubkey_load(ctx, &actual, pubkey);
    secp256k1_gej_add_ge_var(&expectedj, &expectedj, &actual, NULL);
    return secp256k1_gej_is_infinity(&expectedj);
}

int secp256k1_musig_partial_sign(const secp256k1_context* ctx, secp256k1_musig_signature *sig, const unsigned char *seckey, const secp256k1_pubkey *combined_pk, const unsigned char *ell, const unsigned char *msg32, const unsigned char *secnon, const secp256k1_musig_signer_data *data, size_t n_signers, size_t my_index) {
    unsigned char buf[33];
    size_t buf_size = sizeof(buf);
    secp256k1_gej total_rj;
    secp256k1_ge total_r;
    secp256k1_sha256 sha;
    size_t i;
    int overflow;
    secp256k1_scalar sk;
    secp256k1_scalar coeff;
    secp256k1_scalar e, k;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(ell != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(secnon != NULL);
    ARG_CHECK(data != NULL);

    /* Should this be an ARG_CHECK ? */
    if (!data[my_index].present) {
        return 0;
    }

    /* Compute combined secret key */
    secp256k1_scalar_set_b32(&sk, seckey, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_musig_coefficient(&coeff, ell, my_index);
    secp256k1_scalar_mul(&sk, &sk, &coeff);

    for (i = 0; i < n_signers; i++) {
        if (data[i].present == 0) {
            secp256k1_scalar tmps;
            secp256k1_scalar_set_b32(&tmps, data[i].keyshard, &overflow);
            if (overflow) {
                return 0;
            }
            secp256k1_musig_coefficient(&coeff, ell, i);
            secp256k1_scalar_mul(&tmps, &tmps, &coeff);
            secp256k1_musig_lagrange_coefficient(&coeff, data, n_signers, my_index);
            secp256k1_scalar_mul(&tmps, &tmps, &coeff);
            secp256k1_scalar_add(&sk, &sk, &tmps);
        }
    }

    /* compute aggregate R */
    secp256k1_gej_set_infinity(&total_rj);
    for (i = 0; i < n_signers; i++) {
        if (data[i].present != 0) {
            secp256k1_ge rp;
            secp256k1_pubkey_load(ctx, &rp, &data[i].pubnon);
            secp256k1_gej_add_ge_var(&total_rj, &total_rj, &rp, NULL);
        }
    }
    if (secp256k1_gej_is_infinity(&total_rj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&total_r, &total_rj);
    secp256k1_fe_normalize(&total_r.x);
    secp256k1_fe_get_b32(&sig->data[0], &total_r.x);

    secp256k1_scalar_set_b32(&k, secnon, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k)) {
        return 0;
    }
    if (!secp256k1_fe_is_quad_var(&total_r.y)) {
        secp256k1_scalar_negate(&k, &k);
    }

    /* build message hash */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, &sig->data[0], 32);
    secp256k1_ec_pubkey_serialize(ctx, buf, &buf_size, combined_pk, SECP256K1_EC_COMPRESSED);
    VERIFY_CHECK(buf_size == 33);
    secp256k1_sha256_write(&sha, buf, buf_size);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&e, buf, NULL);

    /* Sign */
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&sig->data[32], &e);
    secp256k1_scalar_clear(&sk);
    secp256k1_scalar_clear(&k);

    return 1;
}

int secp256k1_musig_combine_partial_sigs(const secp256k1_context* ctx, secp256k1_musig_signature *sig, secp256k1_musig_signature *partial_sig, size_t n_sigs, const unsigned char *msg32, const secp256k1_pubkey *pk_tweaked, const secp256k1_pubkey *pk_untweaked, const unsigned char *taproot_commit, secp256k1_taproot_hash_function hashfp, void *hdata) {
    size_t i;
    secp256k1_scalar s;
    secp256k1_scalar taproot_tweak;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    if (msg32 != NULL) {
        ARG_CHECK(pk_tweaked != NULL);
        ARG_CHECK(pk_untweaked != NULL);
        ARG_CHECK(taproot_commit != NULL);
        if (hashfp == NULL) {
            hashfp = secp256k1_taproot_hash_default;
        }
    }

    secp256k1_scalar_clear(&s);
    for (i = 0; i < n_sigs; i++) {
        int overflow;
        secp256k1_scalar term;
        secp256k1_scalar_set_b32(&term, &partial_sig[i].data[32], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_add(&s, &s, &term);
        if (memcmp(&partial_sig[i].data[0], &partial_sig[i].data[0], 32) != 0) {
            return 0;
        }
    }

    if (msg32 != NULL) {
        unsigned char tweak[32];
        unsigned char buf[33];
        size_t buflen = sizeof(buf);
        secp256k1_scalar e;

        secp256k1_sha256 sha;
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, &partial_sig[0].data[0], 32);
        secp256k1_ec_pubkey_serialize(ctx, buf, &buflen, pk_tweaked, SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, buf, buflen);
        secp256k1_sha256_write(&sha, msg32, 32);
        secp256k1_sha256_finalize(&sha, buf);

        if (!hashfp(tweak, pk_untweaked, taproot_commit, hdata)) {
            return 0;
        }
        secp256k1_scalar_set_b32(&taproot_tweak, tweak, NULL);

        secp256k1_scalar_set_b32(&e, buf, NULL);
        secp256k1_scalar_mul(&taproot_tweak, &taproot_tweak, &e);
        secp256k1_scalar_add(&s, &s, &taproot_tweak);
    }

    memcpy(&sig->data[0], &partial_sig[0].data[0], 32);
    secp256k1_scalar_get_b32(&sig->data[32], &s);

    return 1;
}

int secp256k1_musig_verify_1(const secp256k1_context* ctx, const secp256k1_musig_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pk) {
    secp256k1_ge pkp;
    secp256k1_gej rj;
    secp256k1_fe rx;
    secp256k1_gej pkj;
    secp256k1_scalar e, s;
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

    secp256k1_scalar_set_b32(&e, buf, NULL);
    secp256k1_scalar_negate(&e, &e);

    secp256k1_scalar_set_b32(&s, &sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_pubkey_load(ctx, &pkp, pk)) {
        return 0;
    }
    secp256k1_gej_set_ge(&pkj, &pkp);

    secp256k1_ecmult(&ctx->ecmult_ctx, &rj, &pkj, &e, &s);
    if (!secp256k1_gej_has_quad_y_var(&rj)) {
        return 0;
    }

    if (!secp256k1_fe_set_b32(&rx, &sig->data[0])) {
        return 0;
    }

    return secp256k1_gej_eq_x_var(&rx, &rj);
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
            if (!hashfp(tweak, taproot_untweaked[i], tweak32[i], hdata)) {
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
