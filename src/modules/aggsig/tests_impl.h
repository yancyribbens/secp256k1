/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_AGGSIG_TESTS_
#define _SECP256K1_MODULE_AGGSIG_TESTS_

#include "secp256k1_aggsig.h"

void test_aggsig_api(void) {
    /* Setup contexts that just count errors */
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(none, 1024, 32768);
    unsigned char seckeys[5][32];
    secp256k1_pubkey pubkeys[5];
    secp256k1_aggsig_partial_signature partials[5];
    secp256k1_aggsig_context *aggctx;
    unsigned char seed[32] = { 1, 2, 3, 4, 0 };
    unsigned char sig[64];
    unsigned char *msg = seed;  /* shh ;) */
    int32_t ecount = 0;
    size_t i;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    for (i = 0; i < 5; i++) {
        secp256k1_scalar tmp_s;
        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(seckeys[i], &tmp_s);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkeys[i], seckeys[i]) == 1);
    }

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 5, seed);
    CHECK(ecount == 0);
    CHECK(aggctx != NULL);
    secp256k1_aggsig_context_destroy(NULL);  /* harmless */
    secp256k1_aggsig_context_destroy(aggctx);

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 0, seed);
    CHECK(ecount == 0);
    CHECK(aggctx != NULL);
    secp256k1_aggsig_context_destroy(aggctx);

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 0, NULL);
    CHECK(ecount == 1);
    CHECK(aggctx == NULL);
    aggctx = secp256k1_aggsig_context_create(none, NULL, 0, seed);
    CHECK(ecount == 2);
    CHECK(aggctx == NULL);

    aggctx = secp256k1_aggsig_context_create(none, pubkeys, 5, seed);

    CHECK(!secp256k1_aggsig_generate_nonce(none, aggctx, 0));
    CHECK(ecount == 3);
    CHECK(secp256k1_aggsig_generate_nonce(sign, aggctx, 0));
    CHECK(ecount == 3);
    CHECK(!secp256k1_aggsig_generate_nonce(vrfy, aggctx, 0));
    CHECK(ecount == 4);
    CHECK(!secp256k1_aggsig_generate_nonce(both, aggctx, 0));  /* double-generate, not API error */
    CHECK(ecount == 4);
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 1));
    CHECK(ecount == 4);
    CHECK(!secp256k1_aggsig_generate_nonce(both, NULL, 2));
    CHECK(ecount == 5);
    CHECK(!secp256k1_aggsig_generate_nonce(both, aggctx, 5));   /* out of range, API error */
    CHECK(ecount == 6);

    CHECK(!secp256k1_aggsig_partial_sign(both, aggctx, &partials[0], msg, seckeys[0], 0));  /* not all nonces generated, not API error */
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 2));
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 3));
    CHECK(secp256k1_aggsig_generate_nonce(both, aggctx, 4));
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[0], msg, seckeys[0], 0));
    CHECK(!secp256k1_aggsig_partial_sign(both, aggctx, &partials[0], msg, seckeys[0], 0));  /* double sign, not API error */
    CHECK(ecount == 6);

    CHECK(!secp256k1_aggsig_partial_sign(none, aggctx, &partials[1], msg, seckeys[1], 1));
    CHECK(ecount == 7);
    CHECK(!secp256k1_aggsig_partial_sign(vrfy, aggctx, &partials[1], msg, seckeys[1], 1));
    CHECK(ecount == 8);
    CHECK(secp256k1_aggsig_partial_sign(sign, aggctx, &partials[1], msg, seckeys[1], 1));
    CHECK(ecount == 8);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, NULL, msg, seckeys[2], 2));
    CHECK(ecount == 9);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, &partials[2], NULL, seckeys[2], 2));
    CHECK(ecount == 10);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, &partials[2], msg, NULL, 2));
    CHECK(ecount == 11);
    CHECK(!secp256k1_aggsig_partial_sign(sign, aggctx, &partials[2], msg, seckeys[2], 5));  /* out of range, API error */
    CHECK(ecount == 12);
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[2], msg, seckeys[2], 2));
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[3], msg, seckeys[3], 3));
    CHECK(secp256k1_aggsig_partial_sign(both, aggctx, &partials[4], msg, seckeys[4], 4));
    CHECK(ecount == 12);

    CHECK(secp256k1_aggsig_combine_signatures(none, aggctx, sig, partials));
    CHECK(ecount == 12);
    CHECK(!secp256k1_aggsig_combine_signatures(none, NULL, sig, partials));
    CHECK(ecount == 13);
    CHECK(!secp256k1_aggsig_combine_signatures(none, aggctx, NULL, partials));
    CHECK(ecount == 14);
    CHECK(!secp256k1_aggsig_combine_signatures(none, aggctx, sig, NULL));
    CHECK(ecount == 15);

    memset(sig, 0, sizeof(sig));
    CHECK(!secp256k1_aggsig_verify(none, scratch, sig, msg, pubkeys, 5));
    CHECK(ecount == 16);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 5));
    CHECK(secp256k1_aggsig_combine_signatures(none, aggctx, sig, partials));
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 4));
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 0));
    CHECK(secp256k1_aggsig_verify(vrfy, scratch, sig, msg, pubkeys, 5));
    CHECK(ecount == 16);

    CHECK(!secp256k1_aggsig_verify(vrfy, NULL, sig, msg, pubkeys, 5));
    CHECK(ecount == 17);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, NULL, msg, pubkeys, 5));
    CHECK(ecount == 18);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, NULL, pubkeys, 5));
    CHECK(ecount == 19);
    CHECK(!secp256k1_aggsig_verify(vrfy, scratch, sig, msg, NULL, 5));
    CHECK(ecount == 20);

    /* cleanup */
    secp256k1_aggsig_context_destroy(aggctx);
    secp256k1_scratch_space_destroy(scratch);
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

#define N_KEYS 200
void test_aggsig_onesigner(void) {
    secp256k1_pubkey pubkeys[N_KEYS];
    unsigned char seckeys[N_KEYS][32];
    secp256k1_aggsig_partial_signature partials[N_KEYS];
    const size_t n_pubkeys = sizeof(pubkeys) / sizeof(pubkeys[0]);
    secp256k1_scalar tmp_s;
    size_t i;
    size_t n_signers[] = { 1, 2, N_KEYS / 5, N_KEYS - 1, N_KEYS };
    const size_t n_n_signers = sizeof(n_signers) / sizeof(n_signers[0]);
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024, 32768);

    unsigned char msg[32];

    random_scalar_order_test(&tmp_s);
    secp256k1_scalar_get_b32(msg, &tmp_s);

    for (i = 0; i < n_pubkeys; i++) {
        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(seckeys[i], &tmp_s);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkeys[i], seckeys[i]) == 1);
    }

    for (i = 0; i < n_n_signers; i++) {
        size_t j;
        unsigned char seed[32];
        unsigned char sig[64];
        secp256k1_aggsig_context *aggctx;

        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(seed, &tmp_s);
        aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, n_signers[i], seed);

        /* all nonces must be generated before signing */
        for (j = 0; j < n_signers[i]; j++) {
            CHECK(secp256k1_aggsig_generate_nonce(ctx, aggctx, j));
        }
        for (j = 0; j < n_signers[i]; j++) {
            CHECK(secp256k1_aggsig_partial_sign(ctx, aggctx, &partials[j], msg, seckeys[j], j));
        }
        CHECK(secp256k1_aggsig_combine_signatures(ctx, aggctx, sig, partials));
        CHECK(secp256k1_aggsig_verify(ctx, scratch, sig, msg, pubkeys, n_signers[i]));
        /* Make sure verification with 0 pubkeys fails without Bad Things happenings */
        CHECK(!secp256k1_aggsig_verify(ctx, scratch, sig, msg, pubkeys, 0));

        secp256k1_aggsig_context_destroy(aggctx);
    }

    secp256k1_scratch_space_destroy(scratch);
}
#undef N_KEYS

void test_aggsig_state_machine(void) {
    secp256k1_pubkey pubkey;
    unsigned char seckey[32];
    secp256k1_aggsig_partial_signature partial;
    secp256k1_scalar tmp_s;
    unsigned char msg[32];
    unsigned char seed[32];
    unsigned char sig[64];
    secp256k1_aggsig_context *aggctx;

    random_scalar_order_test(&tmp_s);
    secp256k1_scalar_get_b32(msg, &tmp_s);
    random_scalar_order_test(&tmp_s);
    secp256k1_scalar_get_b32(seckey, &tmp_s);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1);
    random_scalar_order_test(&tmp_s);
    secp256k1_scalar_get_b32(seed, &tmp_s);

    aggctx = secp256k1_aggsig_context_create(ctx, &pubkey, 1, seed);
    CHECK(!secp256k1_aggsig_partial_sign(ctx, aggctx, &partial, msg, seckey, 0));
    CHECK(!secp256k1_aggsig_combine_signatures(ctx, aggctx, sig, &partial));

    CHECK(secp256k1_aggsig_generate_nonce(ctx, aggctx, 0));
    CHECK(!secp256k1_aggsig_generate_nonce(ctx, aggctx, 0));
    CHECK(!secp256k1_aggsig_combine_signatures(ctx, aggctx, sig, &partial));

    CHECK(secp256k1_aggsig_partial_sign(ctx, aggctx, &partial, msg, seckey, 0));
    CHECK(!secp256k1_aggsig_generate_nonce(ctx, aggctx, 0));
    CHECK(!secp256k1_aggsig_partial_sign(ctx, aggctx, &partial, msg, seckey, 0));

    CHECK(secp256k1_aggsig_combine_signatures(ctx, aggctx, sig, &partial));
    CHECK(!secp256k1_aggsig_generate_nonce(ctx, aggctx, 0));
    CHECK(!secp256k1_aggsig_partial_sign(ctx, aggctx, &partial, msg, seckey, 0));
    CHECK(secp256k1_aggsig_combine_signatures(ctx, aggctx, sig, &partial));
    secp256k1_aggsig_context_destroy(aggctx);
}

struct secp256k1_test_signer {
    secp256k1_aggsig_context *aggctx;
    unsigned char seckeys[32];
};

void test_aggsig_multiparty(void) {
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024, 32768);
    int n_signers = 2;
    struct secp256k1_test_signer signer[2];
    int i;
    secp256k1_pubkey nonces[2];
    unsigned char seed[32] = { 0 };
    size_t indices0[1] = { 0 };
    size_t indices1[1] = { 1 };
    unsigned char msg[32] = { 99 };
    secp256k1_aggsig_partial_signature partial[2];
    unsigned char sig641[64];
    unsigned char sig642[64];
    secp256k1_gej nonce;
    secp256k1_gej pubnonce1;
    secp256k1_gej pubnonce2;

    for(i = 0; i < n_signers; i++) {
        secp256k1_pubkey pubkeys[1];
        secp256k1_scalar tmp_s;
        seed[0] = i;
        random_scalar_order_test(&tmp_s);
        secp256k1_scalar_get_b32(signer[i].seckeys, &tmp_s);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkeys[0], signer[i].seckeys) == 1);
        signer[i].aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, 1, seed);
        CHECK(secp256k1_aggsig_generate_nonce(ctx, signer[i].aggctx, 0));
        secp256k1_aggsig_export_nonce(signer[i].aggctx, &nonces[i]);
    }

    pubnonce1 = signer[0].aggctx->pubnonce_sum;
    pubnonce2 = signer[1].aggctx->pubnonce_sum;
    CHECK(secp256k1_aggsig_import_pubkeys(ctx, signer[0].aggctx, signer[1].aggctx->pubkeys, indices1, 1, &nonces[1], 1));
    CHECK(secp256k1_aggsig_import_pubkeys(ctx, signer[1].aggctx, signer[0].aggctx->pubkeys, indices0, 1, &nonces[0], 1));
    printf("res %d\n", memcmp(signer[0].aggctx->pubkeys[0].data, signer[0].aggctx->pubkeys[0].data, 64));
    CHECK(memcmp(signer[0].aggctx->pubkeys[0].data, signer[1].aggctx->pubkeys[0].data, 64) == 0);
    CHECK(memcmp(signer[0].aggctx->pubkeys[1].data, signer[1].aggctx->pubkeys[1].data, 64) == 0);
    secp256k1_gej_neg(&nonce, &signer[0].aggctx->pubnonce_sum);
    secp256k1_gej_add_var(&nonce, &nonce, &signer[1].aggctx->pubnonce_sum, NULL);
    CHECK(secp256k1_gej_is_infinity(&nonce));
    secp256k1_gej_add_var(&nonce, &pubnonce1, &pubnonce2, NULL);
    secp256k1_gej_neg(&nonce, &signer[0].aggctx->pubnonce_sum);
    secp256k1_gej_add_var(&nonce, &nonce, &signer[1].aggctx->pubnonce_sum, NULL);
    CHECK(secp256k1_gej_is_infinity(&nonce));

    CHECK(secp256k1_aggsig_partial_sign(ctx, signer[0].aggctx, &partial[0], msg, &signer[0].seckeys[0], 0));
    CHECK(secp256k1_aggsig_partial_sign(ctx, signer[1].aggctx, &partial[1], msg, &signer[1].seckeys[0], 1));

    CHECK(secp256k1_aggsig_combine_signatures(ctx, signer[0].aggctx, sig641, partial));
    CHECK(secp256k1_aggsig_combine_signatures(ctx, signer[1].aggctx, sig642, partial));
    CHECK(memcmp(sig641, sig642, 64) == 0);
    CHECK(secp256k1_aggsig_verify(ctx, scratch, sig641, msg, signer[0].aggctx->pubkeys, signer[0].aggctx->n_sigs));
    CHECK(secp256k1_aggsig_verify(ctx, scratch, sig642, msg, signer[1].aggctx->pubkeys, signer[1].aggctx->n_sigs));

    for(i = 0; i < n_signers; i++) {
        secp256k1_aggsig_context_destroy(signer[i].aggctx);
    }
    secp256k1_scratch_space_destroy(scratch);
}

#define N_SIGNERS 3
#define MAX_N_PUBKEYS 3
void test_aggsig_multiparty2(void) {
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024, 32768);
    struct secp256k1_test_signer signer[N_SIGNERS];
    int i, j;
    size_t indices0[1] = { 0 };
    size_t indices1[1] = { 1 };
    unsigned char msg[32] = { 99 };
    secp256k1_aggsig_partial_signature partial[2];
    unsigned char sig641[64];
    unsigned char sig642[64];
    secp256k1_gej nonce;
    secp256k1_gej pubnonce1;
    secp256k1_gej pubnonce2;

    for(i = 0; i < n_signers; i++) {
        unsigned char seed[32];
        secp256k1_rand256(seed);
        secp256k1_pubkey pubkeys[MAX_N_PUBKEYS];
        secp256k1_scalar tmp_s;
        int n_pubkeys = secp256k1_rand_int(5)+1;

        for(j = 0; j < n_pubkeys; j++) {
            random_scalar_order_test(&tmp_s);
            secp256k1_scalar_get_b32(signer[i].seckeys, &tmp_s);
            CHECK(secp256k1_ec_pubkey_create(ctx, &pubkeys[j], signer[i].seckeys) == 1);
        }
        signer[i].aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, n_pubkeys, seed);
        for(j = 0; j < n_pubkeys; j++) {
            CHECK(secp256k1_aggsig_generate_nonce(ctx, signer[i].aggctx, j));
        }   
    }

    pubnonce1 = signer[0].aggctx->pubnonce_sum;
    pubnonce2 = signer[1].aggctx->pubnonce_sum;
    for(i = 0; i < n_signers; i++) {
        secp256k1_pubkey nonces[N_SIGNERS];
        secp256k1_pubkey pubkeys[N_SIGNERS*MAX_N_PUBKEYS];
        size_t indices[N_SIGNERS*MAX_N_PUBKEYS];
        int idx = 0;
        for(j = 0; j < n_signers; j++) {
            if (j == i) {
                continue;
            }
            secp256k1_aggsig_export_nonce(signer[i].aggctx, &nonces[idx]);
            idx+=1;
        
        }   
        CHECK(secp256k1_aggsig_import_pubkeys(ctx, signer[i].aggctx, pubkeys, indices, 1, nonces, 1));
    }

    CHECK(secp256k1_aggsig_import_pubkeys(ctx, signer[0].aggctx, signer[1].aggctx->pubkeys, indices1, 1, &nonces[1], 1));
    CHECK(secp256k1_aggsig_import_pubkeys(ctx, signer[1].aggctx, signer[0].aggctx->pubkeys, indices0, 1, &nonces[0], 1));
    printf("res %d\n", memcmp(signer[0].aggctx->pubkeys[0].data, signer[0].aggctx->pubkeys[0].data, 64));
    CHECK(memcmp(signer[0].aggctx->pubkeys[0].data, signer[1].aggctx->pubkeys[0].data, 64) == 0);
    CHECK(memcmp(signer[0].aggctx->pubkeys[1].data, signer[1].aggctx->pubkeys[1].data, 64) == 0);
    secp256k1_gej_neg(&nonce, &signer[0].aggctx->pubnonce_sum);
    secp256k1_gej_add_var(&nonce, &nonce, &signer[1].aggctx->pubnonce_sum, NULL);
    CHECK(secp256k1_gej_is_infinity(&nonce));
    secp256k1_gej_add_var(&nonce, &pubnonce1, &pubnonce2, NULL);
    secp256k1_gej_neg(&nonce, &signer[0].aggctx->pubnonce_sum);
    secp256k1_gej_add_var(&nonce, &nonce, &signer[1].aggctx->pubnonce_sum, NULL);
    CHECK(secp256k1_gej_is_infinity(&nonce));

    CHECK(secp256k1_aggsig_partial_sign(ctx, signer[0].aggctx, &partial[0], msg, &signer[0].seckeys[0], 0));
    CHECK(secp256k1_aggsig_partial_sign(ctx, signer[1].aggctx, &partial[1], msg, &signer[1].seckeys[0], 1));

    CHECK(secp256k1_aggsig_combine_signatures(ctx, signer[0].aggctx, sig641, partial));
    CHECK(secp256k1_aggsig_combine_signatures(ctx, signer[1].aggctx, sig642, partial));
    CHECK(memcmp(sig641, sig642, 64) == 0);
    CHECK(secp256k1_aggsig_verify(ctx, scratch, sig641, msg, signer[0].aggctx->pubkeys, signer[0].aggctx->n_sigs));
    CHECK(secp256k1_aggsig_verify(ctx, scratch, sig642, msg, signer[1].aggctx->pubkeys, signer[1].aggctx->n_sigs));

    for(i = 0; i < n_signers; i++) {
        secp256k1_aggsig_context_destroy(signer[i].aggctx);
    }
    secp256k1_scratch_space_destroy(scratch);
}


void run_aggsig_tests(void) {
    test_aggsig_api();
    test_aggsig_onesigner();
    test_aggsig_state_machine();
    test_aggsig_multiparty();
    test_aggsig_multiparty2();
}

#endif
