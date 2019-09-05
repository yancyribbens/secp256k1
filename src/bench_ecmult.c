/**********************************************************************
 * Copyright (c) 2017 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <stdio.h>

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

#define POINTS 32768
#define ITERS 10000

typedef struct {
    /* Setup once in advance */
    secp256k1_context* ctx;
    secp256k1_scratch_space* scratch;
    secp256k1_scalar* scalars;
    secp256k1_ge* pubkeys;
    secp256k1_gej* pubkeys_gej;
    secp256k1_scalar* seckeys;
    secp256k1_gej* expected_output;
    secp256k1_ecmult_multi_func ecmult_multi;

    /* Changes per test */
    size_t count;
    int includes_g;

    /* Changes per test iteration, used to pick different scalars and pubkeys
     * in each run. */
    size_t offset1;
    size_t offset2;

    /* Test output. */
    secp256k1_gej* output;
} bench_data;

/* Hashes x into [0, POINTS) twice and store the result in offset1 and offset2. */
static void hash_into_offset(bench_data* data, size_t x) {
    data->offset1 = (x * 0x537b7f6f + 0x8f66a481) % POINTS;
    data->offset2 = (x * 0x7f6f537b + 0x6a1a8f49) % POINTS;
}

/* Check correctness of the benchmark by computing
 * sum(outputs) ?= (sum(scalars_gen) + sum(seckeys)*sum(scalars))*G */
static void bench_ecmult_teardown_helper(bench_data* data, size_t* seckey_offset, size_t* scalar_offset, size_t* scalar_gen_offset) {
    size_t iter;
    secp256k1_gej sum_output, tmp;
    secp256k1_scalar sum_scalars;

    secp256k1_gej_set_infinity(&sum_output);
    secp256k1_scalar_clear(&sum_scalars);
    for (iter = 0; iter < ITERS; ++iter) {
        secp256k1_gej_add_var(&sum_output, &sum_output, &data->output[iter], NULL);
        if (scalar_gen_offset != NULL) {
            secp256k1_scalar_add(&sum_scalars, &sum_scalars, &data->scalars[(*scalar_gen_offset+iter) % POINTS]);
        }
        if (seckey_offset != NULL) {
            secp256k1_scalar s = data->seckeys[(*seckey_offset+iter) % POINTS];
            secp256k1_scalar_mul(&s, &s, &data->scalars[(*scalar_offset+iter) % POINTS]);
            secp256k1_scalar_add(&sum_scalars, &sum_scalars, &s);
        }
    }
    secp256k1_ecmult_gen(&data->ctx->ecmult_gen_ctx, &tmp, &sum_scalars);
    secp256k1_gej_neg(&tmp, &tmp);
    secp256k1_gej_add_var(&tmp, &tmp, &sum_output, NULL);
    CHECK(secp256k1_gej_is_infinity(&tmp));
}

static void bench_ecmult_setup(void* arg) {
    bench_data* data = (bench_data*)arg;
    /* Re-randomize offset to ensure that we're using different scalars and
     * group elements in each run. */
    hash_into_offset(data, data->offset1);
}

static void bench_ecmult_gen(void* arg) {
    bench_data* data = (bench_data*)arg;
    size_t iter;

    for (iter = 0; iter < ITERS; ++iter) {
        secp256k1_ecmult_gen(&data->ctx->ecmult_gen_ctx, &data->output[iter], &data->scalars[(data->offset1+iter) % POINTS]);
    }
}

static void bench_ecmult_gen_teardown(void* arg) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, NULL, NULL, &data->offset1);
}

static void bench_ecmult_const(void* arg) {
    bench_data* data = (bench_data*)arg;
    size_t iter;

    for (iter = 0; iter < ITERS; ++iter) {
        secp256k1_ecmult_const(&data->output[iter], &data->pubkeys[(data->offset1+iter) % POINTS], &data->scalars[(data->offset2+iter) % POINTS], 256);
    }
}

static void bench_ecmult_const_teardown(void* arg) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, &data->offset1, &data->offset2, NULL);
}

static void bench_ecmult_1(void* arg) {
    bench_data* data = (bench_data*)arg;
    size_t iter;

    for (iter = 0; iter < ITERS; ++iter) {
        secp256k1_ecmult(&data->ctx->ecmult_ctx, &data->output[iter], &data->pubkeys_gej[(data->offset1+iter) % POINTS], &data->scalars[(data->offset2+iter) % POINTS], NULL);
    }
}

static void bench_ecmult_1_teardown(void* arg) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, &data->offset1, &data->offset2, NULL);
}

static void bench_ecmult_1g(void* arg) {
    bench_data* data = (bench_data*)arg;
    secp256k1_scalar zero;
    size_t iter;

    secp256k1_scalar_set_int(&zero, 0);
    for (iter = 0; iter < ITERS; ++iter) {
        secp256k1_ecmult(&data->ctx->ecmult_ctx, &data->output[iter], NULL, &zero, &data->scalars[(data->offset1+iter) % POINTS]);
    }
}

static void bench_ecmult_1g_teardown(void* arg) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, NULL, NULL, &data->offset1);
}

static void bench_ecmult_2g(void* arg) {
    bench_data* data = (bench_data*)arg;
    size_t iter;

    for (iter = 0; iter < ITERS; ++iter) {
        secp256k1_ecmult(&data->ctx->ecmult_ctx, &data->output[iter], &data->pubkeys_gej[(data->offset1+iter) % POINTS], &data->scalars[(data->offset2+iter) % POINTS], &data->scalars[(data->offset1+iter) % POINTS]);
    }
}

static void bench_ecmult_2g_teardown(void* arg) {
    bench_data* data = (bench_data*)arg;
    bench_ecmult_teardown_helper(data, &data->offset1, &data->offset2, &data->offset1);
}

static void run_ecmult_test(bench_data* data) {
    char str[32];
    sprintf(str, "ecmult_gen");
    run_benchmark(str, bench_ecmult_gen, bench_ecmult_setup, bench_ecmult_gen_teardown, data, 10, ITERS);
    sprintf(str, "ecmult_const");
    run_benchmark(str, bench_ecmult_const, bench_ecmult_setup, bench_ecmult_const_teardown, data, 10, ITERS);
    /* ecmult with non generator point */
    sprintf(str, "ecmult 1");
    run_benchmark(str, bench_ecmult_1, bench_ecmult_setup, bench_ecmult_1_teardown, data, 10, ITERS);
    /* ecmult with generator point */
    sprintf(str, "ecmult 1g");
    run_benchmark(str, bench_ecmult_1g, bench_ecmult_setup, bench_ecmult_1g_teardown, data, 10, ITERS);
    /* ecmult with generator and non-generator point. The reported time is per point. */
    sprintf(str, "ecmult 2g");
    run_benchmark(str, bench_ecmult_2g, bench_ecmult_setup, bench_ecmult_2g_teardown, data, 10, ITERS*2);
}

static int bench_ecmult_multi_callback(secp256k1_scalar* sc, secp256k1_ge* ge, size_t idx, void* arg) {
    bench_data* data = (bench_data*)arg;
    if (data->includes_g) ++idx;
    if (idx == 0) {
        *sc = data->scalars[data->offset1];
        *ge = secp256k1_ge_const_g;
    } else {
        *sc = data->scalars[(data->offset1 + idx) % POINTS];
        *ge = data->pubkeys[(data->offset2 + idx - 1) % POINTS];
    }
    return 1;
}

static void bench_ecmult_multi(void* arg) {
    bench_data* data = (bench_data*)arg;

    size_t count = data->count;
    int includes_g = data->includes_g;
    size_t iters = 1 + ITERS / count;
    size_t iter;

    for (iter = 0; iter < iters; ++iter) {
        data->ecmult_multi(&data->ctx->error_callback, &data->ctx->ecmult_ctx, data->scratch, &data->output[iter], data->includes_g ? &data->scalars[data->offset1] : NULL, bench_ecmult_multi_callback, arg, count - includes_g);
        data->offset1 = (data->offset1 + count) % POINTS;
        data->offset2 = (data->offset2 + count - 1) % POINTS;
    }
}

static void bench_ecmult_multi_setup(void* arg) {
    bench_data* data = (bench_data*)arg;
    hash_into_offset(data, data->count);
}

static void bench_ecmult_multi_teardown(void* arg) {
    bench_data* data = (bench_data*)arg;
    size_t iters = 1 + ITERS / data->count;
    size_t iter;
    /* Verify the results in teardown, to avoid doing comparisons while benchmarking. */
    for (iter = 0; iter < iters; ++iter) {
        secp256k1_gej tmp;
        secp256k1_gej_add_var(&tmp, &data->output[iter], &data->expected_output[iter], NULL);
        CHECK(secp256k1_gej_is_infinity(&tmp));
    }
}

static void run_ecmult_multi_test(bench_data* data, size_t count, int includes_g) {
    char str[32];
    static const secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    size_t iters = 1 + ITERS / count;
    size_t iter;

    data->count = count;
    data->includes_g = includes_g;

    /* Compute (the negation of) the expected results directly. */
    hash_into_offset(data, data->count);
    for (iter = 0; iter < iters; ++iter) {
        secp256k1_scalar tmp;
        secp256k1_scalar total = data->scalars[(data->offset1++) % POINTS];
        size_t i = 0;
        for (i = 0; i + 1 < count; ++i) {
            secp256k1_scalar_mul(&tmp, &data->seckeys[(data->offset2++) % POINTS], &data->scalars[(data->offset1++) % POINTS]);
            secp256k1_scalar_add(&total, &total, &tmp);
        }
        secp256k1_scalar_negate(&total, &total);
        secp256k1_ecmult(&data->ctx->ecmult_ctx, &data->expected_output[iter], NULL, &zero, &total);
    }

    /* Run the benchmark. */
    sprintf(str, includes_g ? "ecmult_multi %ig" : "ecmult_multi %i", (int)count);
    run_benchmark(str, bench_ecmult_multi, bench_ecmult_multi_setup, bench_ecmult_multi_teardown, data, 10, count * (1 + ITERS / count));
}

static void generate_scalar(uint32_t num, secp256k1_scalar* scalar) {
    secp256k1_sha256 sha256;
    unsigned char c[11] = {'e', 'c', 'm', 'u', 'l', 't', 0, 0, 0, 0};
    unsigned char buf[32];
    int overflow = 0;
    c[6] = num;
    c[7] = num >> 8;
    c[8] = num >> 16;
    c[9] = num >> 24;
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, c, sizeof(c));
    secp256k1_sha256_finalize(&sha256, buf);
    secp256k1_scalar_set_b32(scalar, buf, &overflow);
    CHECK(!overflow);
}

int main(int argc, char **argv) {
    bench_data data;
    int i, p;
    size_t scratch_size;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    scratch_size = secp256k1_strauss_scratch_size(POINTS) + STRAUSS_SCRATCH_OBJECTS*16;
    data.scratch = secp256k1_scratch_space_create(data.ctx, scratch_size);
    data.ecmult_multi = secp256k1_ecmult_multi_var;

    printf("Note: In the following output the number after the function name is the number of points that are multiplied. The letter 'g' indicates that one of the points is the generator.\n");
    if (argc > 1) {
        if(have_flag(argc, argv, "pippenger_wnaf")) {
            printf("Using pippenger_wnaf:\n");
            data.ecmult_multi = secp256k1_ecmult_pippenger_batch_single;
        } else if(have_flag(argc, argv, "strauss_wnaf")) {
            printf("Using strauss_wnaf:\n");
            data.ecmult_multi = secp256k1_ecmult_strauss_batch_single;
        } else if(have_flag(argc, argv, "simple")) {
            printf("Using simple algorithm:\n");
            data.ecmult_multi = secp256k1_ecmult_multi_var;
            secp256k1_scratch_space_destroy(data.ctx, data.scratch);
            data.scratch = NULL;
        } else {
            fprintf(stderr, "%s: unrecognized argument '%s'.\n", argv[0], argv[1]);
            fprintf(stderr, "Use 'pippenger_wnaf', 'strauss_wnaf', 'simple' or no argument to benchmark a combined algorithm.\n");
            return 1;
        }
    }

    /* Allocate stuff */
    data.scalars = malloc(sizeof(secp256k1_scalar) * POINTS);
    data.seckeys = malloc(sizeof(secp256k1_scalar) * POINTS);
    data.pubkeys = malloc(sizeof(secp256k1_ge) * POINTS);
    data.pubkeys_gej = malloc(sizeof(secp256k1_gej) * POINTS);
    data.expected_output = malloc(sizeof(secp256k1_gej) * (ITERS + 1));
    data.output = malloc(sizeof(secp256k1_gej) * (ITERS + 1));

    /* Generate a set of scalars, and private/public keypairs. */
    secp256k1_gej_set_ge(&data.pubkeys_gej[0], &secp256k1_ge_const_g);
    secp256k1_scalar_set_int(&data.seckeys[0], 1);
    for (i = 0; i < POINTS; ++i) {
        generate_scalar(i, &data.scalars[i]);
        if (i) {
            secp256k1_gej_double_var(&data.pubkeys_gej[i], &data.pubkeys_gej[i - 1], NULL);
            secp256k1_scalar_add(&data.seckeys[i], &data.seckeys[i - 1], &data.seckeys[i - 1]);
        }
    }
    secp256k1_ge_set_all_gej_var(data.pubkeys, data.pubkeys_gej, POINTS);


    /* Initialize offset1 and offset2 */
    hash_into_offset(&data, 0);
    run_ecmult_test(&data);

    for (i = 1; i <= 8; ++i) {
        run_ecmult_multi_test(&data, i, 1);
    }

    for (p = 0; p <= 11; ++p) {
        for (i = 9; i <= 16; ++i) {
            run_ecmult_multi_test(&data, i << p, 1);
        }
    }
    if (data.scratch != NULL) {
        secp256k1_scratch_space_destroy(data.ctx, data.scratch);
    }
    secp256k1_context_destroy(data.ctx);
    free(data.scalars);
    free(data.pubkeys);
    free(data.pubkeys_gej);
    free(data.seckeys);
    free(data.output);
    free(data.expected_output);

    return(0);
}
