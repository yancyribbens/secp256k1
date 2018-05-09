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

        ret = noncefp(buf, msg32, seckey, NULL, (void*)ndata, count);
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

#endif
