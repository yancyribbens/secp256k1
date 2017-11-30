/**********************************************************************
 * Copyright (c) 2017 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <stdio.h>
#include <sys/types.h>

#include "include/secp256k1.h"


#include "util.h"
#include "hash_impl.h"
#include "num_impl.h"
#include "field_impl.h"
#include "group_impl.h"
#include "scalar_impl.h"
#include "ecmult_impl.h"
#include "bench.h"
#include "secp256k1.c"
#include "testrand_impl.h"

void random_field_element_test(secp256k1_fe *fe) {
    do {
        unsigned char b32[32];
        secp256k1_rand256_test(b32);
        if (secp256k1_fe_set_b32(fe, b32)) {
            break;
        }
    } while(1);
}

void random_group_element_test(secp256k1_ge *ge) {
    secp256k1_fe fe;
    do {
        random_field_element_test(&fe);
        if (secp256k1_ge_set_xo_var(ge, &fe, secp256k1_rand_bits(1))) {
            secp256k1_fe_normalize(&ge->y);
            break;
        }
    } while(1);
}

void random_scalar_order(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_rand256(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

typedef struct {
    secp256k1_scalar *sc;
    secp256k1_ge *pt;
} ecmult_multi_data;


static int ecmult_multi_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ecmult_multi_data *data = (ecmult_multi_data*) cbdata;
    *sc = data->sc[idx];
    *pt = data->pt[idx];
    return 1;
}

void fill_ecmult_multi_data(ecmult_multi_data *cbdata, char *data, size_t n) {
    cbdata->sc = malloc(sizeof(secp256k1_scalar) * n);
    memcpy(cbdata->sc, data, sizeof(secp256k1_scalar) * n);
    cbdata->pt = malloc(sizeof(secp256k1_ge) * n);
    memcpy(cbdata->pt, data + sizeof(secp256k1_scalar) * n, sizeof(secp256k1_ge) * n);
}

int ecmult_multi(secp256k1_context *ctx, char *data, size_t ndata) {
    secp256k1_scratch *scratch;
    secp256k1_gej r;
    secp256k1_gej r2;
    secp256k1_gej r3;
    secp256k1_scalar scG;
    secp256k1_scalar szero;
    secp256k1_scalar sone;
    int overflow;
    size_t n;
    ecmult_multi_data cbdata;
    size_t n_batches;
    size_t n_batch_points;
    size_t pippenger_scratch_size;
    size_t strauss_scratch_size;
    int bucket_window;
    unsigned int i;
    size_t n_points;

    if (ndata < 8) {
        return 0;
    }
    secp256k1_scalar_set_b32(&scG, (unsigned char*)data, &overflow);
    data += 8;
    if (overflow) {
        return 0;
    }

    n = (ndata - 8)/(sizeof(secp256k1_scalar) + sizeof(secp256k1_ge));
    if(n == 0) {
        return 0;
    }
    fill_ecmult_multi_data(&cbdata, data, n);

    n_batches = (n+ECMULT_PIPPENGER_THRESHOLD-1)/ECMULT_PIPPENGER_THRESHOLD;
    n_batch_points = (n+n_batches-1)/n_batches;

    bucket_window = secp256k1_pippenger_bucket_window(n);
    pippenger_scratch_size = secp256k1_pippenger_scratch_size(n, bucket_window) + ALIGNMENT*PIPPENGER_SCRATCH_OBJECTS;
    strauss_scratch_size = secp256k1_strauss_scratch_size(n_batch_points) + ALIGNMENT*STRAUSS_SCRATCH_OBJECTS;

    if (pippenger_scratch_size > strauss_scratch_size) {
        scratch = secp256k1_scratch_create(&ctx->error_callback, 0, pippenger_scratch_size);
    } else {
        scratch = secp256k1_scratch_create(&ctx->error_callback, 0, strauss_scratch_size);
    }
    if (scratch == NULL) {
        secp256k1_scratch_destroy(scratch);
        return 0;
    }

    n_points = n;

    secp256k1_gej_set_infinity(&r3);
    secp256k1_scalar_set_int(&szero, 0);
    secp256k1_scalar_set_int(&sone, 1);
    for(i = 0; i < n_points; i++) {
        if(!secp256k1_ge_is_valid_var(&cbdata.pt[i])) {
            secp256k1_scratch_destroy(scratch);
            free(cbdata.sc);
            free(cbdata.pt);
            return 0;
        }

        secp256k1_scalar_mul(&cbdata.sc[i], &sone, &cbdata.sc[i]);
    }

    for(i = 0; i < n_batches; i++) {
        size_t nbp = n < n_batch_points ? n : n_batch_points;
        size_t offset = n_batch_points*i;
        secp256k1_gej tmp;
        CHECK(secp256k1_ecmult_strauss_batch(&ctx->ecmult_ctx, scratch, &tmp, i == 0 ? &scG : NULL, ecmult_multi_callback, &cbdata, nbp, offset));

        secp256k1_gej_add_var(&r, &r, &tmp, NULL);
        n -= nbp;
    }

    CHECK(secp256k1_ecmult_pippenger_batch(&ctx->ecmult_ctx, scratch, &r2, &scG, ecmult_multi_callback, &cbdata, n_points, 0));
    secp256k1_gej_neg(&r2, &r2);
    secp256k1_gej_add_var(&r, &r, &r2, NULL);
    CHECK(secp256k1_gej_is_infinity(&r));
    printf("ok %lu\n", n_points);

    secp256k1_scratch_destroy(scratch);
    free(cbdata.sc);
    free(cbdata.pt);
    return 1;
}

int ecmult_multi_testcase(secp256k1_context *ctx, char *data, size_t *ndata) {
    size_t n_points = 1;
    secp256k1_scalar scG;
    secp256k1_scalar *sc = (secp256k1_scalar *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_scalar) * n_points);
    secp256k1_ge *pt = (secp256k1_ge *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge) * n_points);
    unsigned int i;
    size_t offset = 0;

    random_scalar_order(&scG);
    secp256k1_scalar_get_b32((unsigned char*)(data+offset), &scG);
    offset += 8;

    for(i = 0; i < n_points; i++) {
        secp256k1_ge ptg;
        secp256k1_gej ptgj;
        random_group_element_test(&ptg);
        secp256k1_gej_set_ge(&ptgj, &ptg);
        pt[i] = ptg;
        random_scalar_order(&sc[i]);
    }
    memcpy(data+offset, sc, n_points * sizeof(secp256k1_scalar));
    memcpy(data+offset+n_points*sizeof(secp256k1_scalar), pt, n_points * sizeof(secp256k1_ge));

    *ndata=offset+n_points*(sizeof(secp256k1_scalar) + sizeof(secp256k1_ge));


    free(sc);
    free(pt);
    return 1;
}

int main(int argc, char** argv) {
    char *buf;
    ssize_t nread;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    (void)argv;

#define BUFSIZE 37704
    buf = malloc(BUFSIZE);

    if (argc < 2) {
#ifdef __AFL_COMPILER
        while (__AFL_LOOP(1000)) {
#endif
            if ((nread = fread(buf, sizeof(char), BUFSIZE, stdin)) >= 0) {
               ecmult_multi(ctx, buf, nread);
            }
#ifdef __AFL_COMPILER
        }
#endif
    } else {
        size_t ndata;
        ecmult_multi_testcase(ctx, buf, &ndata);
        fwrite(buf, sizeof(char), ndata, stdout);
    }
    free(buf);
    secp256k1_context_destroy(ctx);
    return 0;
}
