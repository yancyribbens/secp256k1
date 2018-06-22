/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <string.h>
#include <stdlib.h>

#include "include/secp256k1.h"
#include "include/secp256k1_musig.h"
#include "util.h"
#include "bench.h"

#define MAX_SIGS	(32768)

typedef struct {
    secp256k1_context *ctx;
    secp256k1_scratch_space *scratch;
    size_t n;
    const unsigned char **pk;
    const secp256k1_musig_signature **sigs;
    const unsigned char **msgs;
    const unsigned char **untweaked_pk;
    const unsigned char **tweaked_pk;
    const unsigned char **tweak;
} bench_musig_data;

void bench_musig_sign(void* arg) {
    bench_musig_data *data = (bench_musig_data *)arg;
    size_t i;
    unsigned char sk[32] = "benchmarkexample secrettemplate";
    unsigned char msg[32] = "benchmarkexamplemessagetemplate";
    secp256k1_musig_signature sig;

    for (i = 0; i < 1000; i++) {
        msg[0] = i;
        msg[1] = i >> 8;
        sk[0] = i;
        sk[1] = i >> 8;
        CHECK(secp256k1_musig_single_sign(data->ctx, &sig, msg, sk, NULL, NULL));
    }
}

void bench_musig_verify_taproot(void* arg) {
    bench_musig_data *data = (bench_musig_data *)arg;
    size_t i;

    for (i = 0; i < 1000; i++) {
        secp256k1_pubkey untweaked_pk;
        secp256k1_pubkey tweaked_pk;
        const secp256k1_pubkey *untweaked_pk_arr = &untweaked_pk;
        const secp256k1_pubkey *tweaked_pk_arr = &tweaked_pk;
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &untweaked_pk, data->untweaked_pk[i], 33) == 1);
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &tweaked_pk, data->tweaked_pk[i], 33) == 1);

        CHECK(secp256k1_musig_verify(data->ctx, data->scratch, NULL, NULL, NULL, 0, &untweaked_pk_arr, &tweaked_pk_arr, &data->tweak[i], 1, NULL, NULL));
    }
}

void bench_musig_verify_1(void* arg) {
    bench_musig_data *data = (bench_musig_data *)arg;
    size_t i;

    for (i = 0; i < 1000; i++) {
        secp256k1_pubkey pk;
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pk, data->pk[i], 33) == 1);
        CHECK(secp256k1_musig_verify_1(data->ctx, data->sigs[i], data->msgs[i], &pk));
    }
}

void bench_musig_verify_n(void* arg) {
    bench_musig_data *data = (bench_musig_data *)arg;
    size_t i, j;
    const secp256k1_pubkey **pk = (const secp256k1_pubkey **)malloc(data->n * sizeof(*pk));

    CHECK(pk != NULL);
    for (j = 0; j < MAX_SIGS/data->n; j++) {
        for (i = 0; i < data->n; i++) {
            secp256k1_pubkey *pk_nonconst = (secp256k1_pubkey *)malloc(sizeof(*pk_nonconst));
            CHECK(secp256k1_ec_pubkey_parse(data->ctx, pk_nonconst, data->pk[i], 33) == 1);
            pk[i] = pk_nonconst;
        }
        CHECK(secp256k1_musig_verify(data->ctx, data->scratch, data->sigs, data->msgs, pk, data->n, NULL, NULL, NULL, 0, NULL, NULL));
        for (i = 0; i < data->n; i++) {
            free((void *)pk[i]);
        }
    }
    free(pk);
}

int main(void) {
    size_t i;
    bench_musig_data data;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 1024 * 1024 * 1024);
    data.pk = (const unsigned char **)malloc(MAX_SIGS * 33);
    data.untweaked_pk = (const unsigned char **)malloc(MAX_SIGS * 33);
    data.tweaked_pk = (const unsigned char **)malloc(MAX_SIGS * 33);
    data.tweak = (const unsigned char **)malloc(MAX_SIGS * 33);
    data.msgs = (const unsigned char **)malloc(MAX_SIGS * 32);
    data.sigs = (const secp256k1_musig_signature **)malloc(MAX_SIGS * sizeof(*data.sigs));

    for (i = 0; i < MAX_SIGS; i++) {
        unsigned char sk[32];
        unsigned char buf[32];
        unsigned char *msg = malloc(32);
        secp256k1_musig_signature *sig = (secp256k1_musig_signature *)malloc(sizeof(*sig));
        unsigned char *pk_char = (unsigned char *)malloc(33);
        unsigned char *untweaked_pk_char = (unsigned char *)malloc(33);
        unsigned char *tweaked_pk_char = (unsigned char *)malloc(33);
        secp256k1_pubkey untweaked_pk;
        secp256k1_pubkey tweaked_pk;
        secp256k1_pubkey pk;
        size_t pk_len = 33;
        msg[0] = sk[0] = i;
        msg[1] = sk[1] = i >> 8;
        msg[2] = sk[2] = i >> 16;
        msg[3] = sk[3] = i >> 24;
        memset(&msg[4], 'm', 28);
        memset(&sk[4], 's', 28);

        data.pk[i] = pk_char;
        data.msgs[i] = msg;
        data.sigs[i] = sig;
        data.tweak[i] = (unsigned char *)"scripty mcscriptface            ";

        CHECK(secp256k1_ec_pubkey_create(data.ctx, &pk, sk));
        CHECK(secp256k1_ec_pubkey_serialize(data.ctx, pk_char, &pk_len, &pk, SECP256K1_EC_COMPRESSED) == 1);
        CHECK(secp256k1_musig_single_sign(data.ctx, sig, msg, sk, NULL, NULL));
        CHECK(secp256k1_musig_pubkey_combine(data.ctx, NULL, &untweaked_pk, &pk, 1));
        CHECK(secp256k1_musig_pubkey_combine(data.ctx, NULL, &tweaked_pk, &pk, 1));
        CHECK(secp256k1_taproot_hash_default(buf, &tweaked_pk, data.tweak[i], NULL));
        CHECK(secp256k1_ec_pubkey_tweak_add(data.ctx, &tweaked_pk, buf));
        CHECK(secp256k1_ec_pubkey_serialize(data.ctx, untweaked_pk_char, &pk_len, &untweaked_pk, SECP256K1_EC_COMPRESSED) == 1);
        CHECK(secp256k1_ec_pubkey_serialize(data.ctx, tweaked_pk_char, &pk_len, &tweaked_pk, SECP256K1_EC_COMPRESSED) == 1);
        CHECK(secp256k1_musig_single_sign(data.ctx, sig, msg, sk, NULL, NULL));
        data.untweaked_pk[i] = untweaked_pk_char;
        data.tweaked_pk[i] = tweaked_pk_char;
    }

    run_benchmark("musig_sign", bench_musig_sign, NULL, NULL, (void *) &data, 10, 1000);
    run_benchmark("musig_verify_taproot", bench_musig_verify_taproot, NULL, NULL, (void *) &data, 10, 1000);
    run_benchmark("musig_verify_1", bench_musig_verify_1, NULL, NULL, (void *) &data, 10, 1000);
    for (i = 1; i <= MAX_SIGS; i *= 2) {
        char name[64];
        sprintf(name, "musig_batch_verify_%d", (int) i);

        data.n = i;
        run_benchmark(name, bench_musig_verify_n, NULL, NULL, (void *) &data, 3, MAX_SIGS);
    }

    for (i = 0; i < MAX_SIGS; i++) {
        free((void *)data.pk[i]);
        free((void *)data.msgs[i]);
        free((void *)data.sigs[i]);
        free((void *)data.untweaked_pk[i]);
        free((void *)data.tweaked_pk[i]);
    }
    free(data.pk);
    free(data.msgs);
    free(data.sigs);
    free(data.untweaked_pk);
    free(data.tweaked_pk);
    free(data.tweak);

    secp256k1_scratch_space_destroy(data.scratch);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
