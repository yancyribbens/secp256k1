/**********************************************************************
 * Copyright (c) 2017 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <stdio.h>
#include <sys/types.h>
#include <limits.h>

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

int ecmult_multi(secp256k1_context *ctx, char *data, size_t ndata) {
    size_t max_size;
    secp256k1_scratch *scratch;
    secp256k1_gej r;
    secp256k1_scalar scG;
    size_t has_scG;
    secp256k1_scalar *pscG = &scG;
    int overflow;
    size_t n;
    ecmult_multi_data mdata;
    int ret;

    if (ndata < 24) {
        return 0;
    }
    memcpy(&max_size, data, sizeof(size_t));
    data += sizeof(size_t);
    if (max_size > 5000000) {
        return 0;
    }
    scratch = secp256k1_scratch_create(&ctx->error_callback, 0, max_size);
    if (scratch == NULL) {
        secp256k1_scratch_destroy(scratch);
        return 0;
    }

    memcpy(&has_scG, data, sizeof(size_t));
    data += sizeof(size_t);
    if (has_scG >= SIZE_MAX/2) {
        secp256k1_scalar_set_b32(pscG, (unsigned char*)data, &overflow);
        if (overflow) {
            secp256k1_scratch_destroy(scratch);
            return 0;
        }
    } else {
        pscG = NULL;
    }
    data += 8;

    memcpy(&n, data, sizeof(size_t));
    data += sizeof(size_t);
    if (n > 99999999 || ndata < 24 + n * (sizeof(secp256k1_scalar) + sizeof(secp256k1_ge))) {
        secp256k1_scratch_destroy(scratch);
        return 0;
    }
    mdata.sc = (secp256k1_scalar*)data;
    mdata.pt = (secp256k1_ge*)(data + sizeof(secp256k1_scalar)*n);
    ret = secp256k1_ecmult_multi_var(&ctx->ecmult_ctx, scratch, &r, pscG, ecmult_multi_callback, &mdata, n);
    printf("%d\n", ret);
    secp256k1_scratch_destroy(scratch);
    return ret;
}


int ecmult_multi_testcase(secp256k1_context *ctx, char *data, size_t *ndata) {
    size_t n_points = 2*ECMULT_PIPPENGER_THRESHOLD+2;
    size_t max_size;
    secp256k1_scalar scG;
    secp256k1_scalar *sc = (secp256k1_scalar *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_scalar) * n_points);
    secp256k1_ge *pt = (secp256k1_ge *)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge) * n_points);
    unsigned int i;
    size_t offset = 0;
    int bucket_window;
    const size_t has_scG = SIZE_MAX/2;

    bucket_window = secp256k1_pippenger_bucket_window(n_points/2);
    max_size = secp256k1_pippenger_scratch_size(n_points/2, bucket_window) + PIPPENGER_SCRATCH_OBJECTS*ALIGNMENT;
    memcpy(data+offset, &max_size, sizeof(size_t));
    offset += sizeof(size_t);

    /* indicate that scG != NULL */
    memcpy(data+offset, &has_scG, sizeof(size_t));
    offset += 8;
    random_scalar_order(&scG);
    secp256k1_scalar_get_b32((unsigned char*)(data+offset), &scG);
    offset += 8;

    memcpy(data+offset, &n_points, sizeof(size_t));
    offset += sizeof(size_t);

    for(i = 0; i < n_points; i++) {
        secp256k1_ge ptg;
        secp256k1_gej ptgj;
        random_group_element_test(&ptg);
        secp256k1_gej_set_ge(&ptgj, &ptg);
        pt[i] = ptg;
        memcpy(data+offset+n_points*sizeof(secp256k1_scalar)+i*sizeof(secp256k1_ge), &pt[i], sizeof(secp256k1_ge));

        random_scalar_order(&sc[i]);
        memcpy(data+offset+i*sizeof(secp256k1_scalar), &sc[i], sizeof(secp256k1_scalar));

    }
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

#define BUFSIZE 38672
    buf = (char*)malloc(BUFSIZE);

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
