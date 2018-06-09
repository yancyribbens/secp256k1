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
    ARG_CHECK(out64 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out64, sig->data, 64);
    return 1;
}

int secp256k1_musig_signature_parse(const secp256k1_context* ctx, secp256k1_musig_signature* sig, const unsigned char *in64) {
    (void) ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in64 != NULL);
    memcpy(sig->data, in64, 64);
    return 1;
}

typedef struct {
    unsigned char ell[32]; /* hash of all public keys */
    const secp256k1_pubkey *pk;
} secp256k1_musig_pkcombine_ecmult_context;

static int secp256k1_musig_tweak(secp256k1_scalar *r, const unsigned char *ell, size_t idx) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    int overflow;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, ell, 32);
    while (idx > 0) {
        unsigned char c = idx;
        secp256k1_sha256_write(&sha, &c, 1);
        idx /= 0x100;
    }
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(r, buf, &overflow);
    return !overflow;
}

static int secp256k1_musig_pkcombine_ecmult_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_pkcombine_ecmult_context *ctx = (secp256k1_musig_pkcombine_ecmult_context *) data;
    secp256k1_pubkey_load(NULL, pt, &ctx->pk[idx]);
    return secp256k1_musig_tweak(sc, ctx->ell, idx);
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
        int overflow;

        if (hashfp == NULL) {
            hashfp = secp256k1_taproot_hash_default;
        }
        secp256k1_pubkey_save(&musigpk, &musigp);
        hashfp(tweak, &musigpk, taproot_commit, hdata);

        secp256k1_scalar_set_b32(&tweaks, tweak, &overflow);
        if (overflow) {
            return 0;
        }
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
        secp256k1_scalar_set_b32(&k, buf, &overflow);
        ret &= !secp256k1_scalar_is_zero(&k);
        ret &= !overflow;

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

            secp256k1_scalar_set_b32(&e, buf, &overflow);
            ret &= !secp256k1_scalar_is_zero(&e);
            ret &= !overflow;

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
            int overflow;

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
            hashfp(tweak, taproot_untweaked[i], tweak32[i], hdata);
            secp256k1_scalar_set_b32(&tweaks, tweak, &overflow);
            if (overflow) {
                secp256k1_scratch_deallocate_frame(scratch);
                secp256k1_scratch_deallocate_frame(scratch);
                return 0;
            }
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
