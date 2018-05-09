/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_TESTS_
#define _SECP256K1_MODULE_MUSIG_TESTS_

#include "secp256k1_musig.h"

void musig_api_tests(secp256k1_scratch_space *scratch) {
    unsigned char sk1[32];
    unsigned char sk2[32];
    unsigned char msg[32];
    unsigned char ell[32];
    unsigned char commit[32];
    unsigned char sig64[64];
    secp256k1_pubkey pk[2];
    secp256k1_pubkey combined_pk;
    secp256k1_pubkey combined_pk_untweaked;
    secp256k1_musig_signature sig;
    const secp256k1_musig_signature *sigptr = &sig;
    const unsigned char *msgptr = msg;
    const unsigned char *commitptr = commit;
    const secp256k1_pubkey *pkptr = &pk[0];
    const secp256k1_pubkey *tptr = &combined_pk;
    const secp256k1_pubkey *utptr = &combined_pk_untweaked;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);

    secp256k1_rand256(sk1);
    secp256k1_rand256(sk2);
    secp256k1_rand256(msg);
    secp256k1_rand256(commit);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[0], sk1) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[1], sk2) == 1);

    /** main test body **/
    ecount = 0;
    CHECK(secp256k1_musig_pubkey_combine(none, scratch, &combined_pk, &combined_pk_untweaked, ell, pk, 2, commit, NULL, NULL) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubkey_combine(sign, scratch, &combined_pk, &combined_pk_untweaked, ell, pk, 2, commit, NULL, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &combined_pk_untweaked, ell, pk, 2, commit, NULL, NULL) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, NULL, &combined_pk, &combined_pk_untweaked, ell, pk, 2, commit, NULL, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, NULL, &combined_pk_untweaked, ell, pk, 2, commit, NULL, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, NULL, ell, pk, 2, commit, NULL, NULL) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &combined_pk_untweaked, NULL, pk, 2, commit, NULL, NULL) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &combined_pk_untweaked, ell, NULL, 2, commit, NULL, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &combined_pk_untweaked, ell, pk, 0, commit, NULL, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &combined_pk_untweaked, ell, pk, 2, NULL, NULL, NULL) == 1);
    CHECK(ecount == 5);

    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &combined_pk_untweaked, ell, pk, 2, commit, NULL, NULL) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_single_sign(none, &sig, msg, sk1, NULL, NULL) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_single_sign(vrfy, &sig, msg, sk1, NULL, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_single_sign(sign, &sig, msg, sk1, NULL, NULL) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_single_sign(sign, NULL, msg, sk1, NULL, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_single_sign(sign, &sig, NULL, sk1, NULL, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_single_sign(sign, &sig, msg, NULL, NULL, NULL) == 0);
    CHECK(ecount == 5);

    ecount = 0;
    CHECK(secp256k1_musig_signature_serialize(none, sig64, &sig) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_signature_serialize(none, NULL, &sig) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_signature_serialize(none, sig64, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_signature_parse(none, &sig, sig64) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_signature_parse(none, NULL, sig64) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_signature_parse(none, &sig, NULL) == 0);
    CHECK(ecount == 4);

    ecount = 0;
    CHECK(secp256k1_musig_verify_1(none, &sig, msg, &pk[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_verify_1(sign, &sig, msg, &pk[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_verify_1(vrfy, &sig, msg, &pk[0]) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_verify_1(vrfy, NULL, msg, &pk[0]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_verify_1(vrfy, &sig, NULL, &pk[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_verify_1(vrfy, &sig, msg, NULL) == 0);
    CHECK(ecount == 5);

    ecount = 0;
    CHECK(secp256k1_musig_verify(none, scratch, &sigptr, &msgptr, &pkptr, 1, &utptr, &tptr, &commitptr, 1, NULL, NULL) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_verify(sign, scratch, &sigptr, &msgptr, &pkptr, 1, &utptr, &tptr, &commitptr, 1, NULL, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_verify(vrfy, scratch, &sigptr, &msgptr, &pkptr, 1, &utptr, &tptr, &commitptr, 1, NULL, NULL) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_verify(vrfy, scratch, NULL, NULL, NULL, 0, &utptr, &tptr, &commitptr, 1, NULL, NULL) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_verify(vrfy, scratch, NULL, &msgptr, &pkptr, 1, &utptr, &tptr, &commitptr, 1, NULL, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_verify(vrfy, scratch, &sigptr, NULL, &pkptr, 1, &utptr, &tptr, &commitptr, 1, NULL, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_verify(vrfy, scratch, &sigptr, &msgptr, NULL, 1, &utptr, &tptr, &commitptr, 1, NULL, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_verify(vrfy, scratch, &sigptr, &msgptr, &pkptr, 1, NULL, NULL, NULL, 0, NULL, NULL) == 1);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_verify(vrfy, scratch, &sigptr, &msgptr, &pkptr, 1, NULL, &tptr, &commitptr, 1, NULL, NULL) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_verify(vrfy, scratch, &sigptr, &msgptr, &pkptr, 1, &utptr, NULL, &commitptr, 1, NULL, NULL) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_verify(vrfy, scratch, &sigptr, &msgptr, &pkptr, 1, &utptr, &tptr, NULL, 1, NULL, NULL) == 0);
    CHECK(ecount == 8);

    /** cleanup **/
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
}

void musig_test_serialize(void) {
    secp256k1_musig_signature sig;
    unsigned char in[64];
    unsigned char out[64];

    memset(in, 0x12, 64);
    CHECK(secp256k1_musig_signature_parse(ctx, &sig, in));
    CHECK(secp256k1_musig_signature_serialize(ctx, out, &sig));
    CHECK(memcmp(in, out, 64) == 0);
}

static int hashfp_false(unsigned char *tweak32, const secp256k1_pubkey *pk, const unsigned char *commit, void *data) {
    (void) tweak32;
    (void) pk;
    (void) commit;
    (void) data;
    return 0;
}

static int hashfp_constant_overflow(unsigned char *tweak32, const secp256k1_pubkey *pk, const unsigned char *commit, void *data) {
    (void) tweak32;
    (void) pk;
    (void) commit;
    (void) data;
    memset(tweak32, 0xFF, 32);
    return 1;
}

#define N_SIGS	200
#define N_TAPROOT	50
void musig_sign_verify(secp256k1_scratch_space *scratch) {
    const unsigned char sk[32] = "shhhhhhhh! this key is a secret.";
    unsigned char msg[N_SIGS][32];
    secp256k1_musig_signature sig[N_SIGS];
    size_t i;
    const secp256k1_musig_signature *sig_arr[N_SIGS];
    const unsigned char *msg_arr[N_SIGS];
    const secp256k1_pubkey *pk_arr[N_SIGS];
    secp256k1_pubkey pk;

    secp256k1_pubkey tweaked[N_TAPROOT];
    secp256k1_pubkey untweaked[N_TAPROOT];
    unsigned char tweak[N_TAPROOT][32];
    const unsigned char *tweak_arr[N_TAPROOT];
    const secp256k1_pubkey *tweaked_arr[N_TAPROOT];
    const secp256k1_pubkey *untweaked_arr[N_TAPROOT];
    secp256k1_scratch_space *scratch_small;

    CHECK(secp256k1_ec_pubkey_create(ctx, &pk, sk));

    CHECK(secp256k1_musig_verify(ctx, scratch, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL, NULL));

    for (i = 0; i < N_SIGS; i++) {
        secp256k1_rand256(msg[i]);
        CHECK(secp256k1_musig_single_sign(ctx, &sig[i], msg[i], sk, NULL, NULL));
        CHECK(secp256k1_musig_verify_1(ctx, &sig[i], msg[i], &pk));
        sig_arr[i] = &sig[i];
        msg_arr[i] = msg[i];
        pk_arr[i] = &pk;
    }

    CHECK(secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, 1, NULL, NULL, NULL, 0, NULL, NULL));
    CHECK(secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, 2, NULL, NULL, NULL, 0, NULL, NULL));
    CHECK(secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, 4, NULL, NULL, NULL, 0, NULL, NULL));
    CHECK(secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, N_SIGS, NULL, NULL, NULL, 0, NULL, NULL));

    for (i = 0; i < N_TAPROOT; i++) {
        secp256k1_pubkey tmp_untweaked;
        secp256k1_rand256(tweak[i]);
        CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &untweaked[i], &tmp_untweaked, NULL, &pk, 1, NULL, NULL, NULL));
        CHECK(memcmp(&untweaked[i], &tmp_untweaked, sizeof(tmp_untweaked)) == 0);
        CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &untweaked[i], NULL, NULL, &pk, 1, NULL, NULL, NULL));
        CHECK(memcmp(&untweaked[i], &tmp_untweaked, sizeof(tmp_untweaked)) == 0);
        CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &tweaked[i], &untweaked[i], NULL, &pk, 1, tweak[i], NULL, NULL));
        CHECK(memcmp(&untweaked[i], &tmp_untweaked, sizeof(tmp_untweaked)) == 0);

        untweaked_arr[i] = &untweaked[i];
        tweaked_arr[i] = &tweaked[i];
        tweak_arr[i] = tweak[i];
    }

    CHECK(secp256k1_musig_verify(ctx, scratch, NULL, NULL, NULL, 0, untweaked_arr, tweaked_arr, tweak_arr, 1, NULL, NULL));
    CHECK(secp256k1_musig_verify(ctx, scratch, NULL, NULL, NULL, 0, untweaked_arr, tweaked_arr, tweak_arr, 2, NULL, NULL));
    CHECK(secp256k1_musig_verify(ctx, scratch, NULL, NULL, NULL, 0, untweaked_arr, tweaked_arr, tweak_arr, N_TAPROOT, NULL, NULL));

    CHECK(secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, N_SIGS, untweaked_arr, tweaked_arr, tweak_arr, N_TAPROOT, NULL, NULL));

    /* Small scratch space: fail in first `allocate_frame` */
    scratch_small = secp256k1_scratch_space_create(ctx, N_TAPROOT * sizeof(secp256k1_ge) - 1);
    CHECK(!secp256k1_musig_verify(ctx, scratch_small, sig_arr, msg_arr, pk_arr, N_SIGS, untweaked_arr, tweaked_arr, tweak_arr, N_TAPROOT, NULL, NULL));
    secp256k1_scratch_space_destroy(scratch_small);
    /* Small scratch space: fail in second `allocate_frame` */
    scratch_small = secp256k1_scratch_space_create(ctx, 2 * N_TAPROOT * sizeof(secp256k1_ge) + ALIGNMENT - 1);
    CHECK(!secp256k1_musig_verify(ctx, scratch_small, sig_arr, msg_arr, pk_arr, N_SIGS, untweaked_arr, tweaked_arr, tweak_arr, N_TAPROOT, NULL, NULL));
    secp256k1_scratch_space_destroy(scratch_small);
    /* Small scratch space: fail in ecmult */
    scratch_small = secp256k1_scratch_space_create(ctx, 1 * (sizeof(secp256k1_ge) + sizeof(secp256k1_gej)) + 32);
    CHECK(!secp256k1_musig_verify(ctx, scratch_small, sig_arr, msg_arr, pk_arr, N_SIGS, untweaked_arr, tweaked_arr, tweak_arr, 1, NULL, NULL));
    secp256k1_scratch_space_destroy(scratch_small);

    /* Taproot hashing returns false */
    CHECK(!secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, N_SIGS, untweaked_arr, tweaked_arr, tweak_arr, N_TAPROOT, hashfp_false, NULL));
    /* Taproot hashing overflows */
    CHECK(!secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, N_SIGS, untweaked_arr, tweaked_arr, tweak_arr, N_TAPROOT, hashfp_constant_overflow, NULL));
}
#undef N_SIGS
#undef N_TAPROOT

void musig_taproot_verify(secp256k1_scratch_space *scratch) {
    const unsigned char sk[32] = " untweaked secret key untweaked ";
    const unsigned char tweak[32] = "scripty mcscriptface            ";
    secp256k1_pubkey untweaked_pk;
    secp256k1_pubkey tweaked_pk;

    const unsigned char *tweak_arr = tweak;
    const secp256k1_pubkey *untweaked_pk_arr = &untweaked_pk;
    const secp256k1_pubkey *tweaked_pk_arr = &tweaked_pk;

    CHECK(secp256k1_ec_pubkey_create(ctx, &untweaked_pk, sk));
    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &tweaked_pk, &untweaked_pk, NULL, &untweaked_pk, 1, tweak, NULL, NULL));

    CHECK(secp256k1_musig_verify(ctx, scratch, NULL, NULL, NULL, 0, &untweaked_pk_arr, &tweaked_pk_arr, &tweak_arr, 1, NULL, NULL));
}

void secp256k1_musig_test_verify(int expected, const secp256k1_musig_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pk, secp256k1_scratch_space *scratch) {
    const unsigned char *msg_arr[1];
    const secp256k1_musig_signature *sig_arr[1];
    const secp256k1_pubkey *pk_arr[1];

    sig_arr[0] = sig;
    msg_arr[0] = msg32;
    pk_arr[0] = pk;

    CHECK(expected == secp256k1_musig_verify_1(ctx, sig, msg32, pk));
    CHECK(expected == secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, 1, NULL, NULL, NULL, 0, NULL, NULL));
}

void metas_schnorr_bip_vectors(secp256k1_scratch_space *scratch) {
    const unsigned char sk32[32] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };
    const secp256k1_scalar sk = SECP256K1_SCALAR_CONST(0,0,0,0,0,0,0,3);
    secp256k1_ge tmpg;
    secp256k1_gej tmpj;
    secp256k1_pubkey pk;
    secp256k1_musig_signature sig;

    const unsigned char *msg_arr[3];
    const secp256k1_musig_signature *sig_arr[3];
    const secp256k1_pubkey *pk_arr[3];

    const unsigned char msg1[32] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
    };
    /* Good sig */
    const secp256k1_musig_signature sig1 = {{
        0x76, 0x2a, 0x13, 0xc5, 0x59, 0x48, 0xd5, 0xd0,
        0xaf, 0xc3, 0x12, 0x01, 0x4a, 0x13, 0xfb, 0x68,
        0x98, 0xac, 0x55, 0xfd, 0x9a, 0x85, 0xfa, 0xe9,
        0x87, 0x8b, 0x26, 0x2e, 0xdd, 0xf6, 0x5f, 0x99,
        0x6e, 0xe5, 0x0b, 0x14, 0xeb, 0xef, 0x1c, 0x15,
        0x9f, 0x09, 0x68, 0x8e, 0x84, 0xa9, 0x5b, 0xff,
        0xe9, 0x54, 0xa0, 0xdb, 0x0e, 0x71, 0xa9, 0x07,
        0x1c, 0x3b, 0xf9, 0xbe, 0x5e, 0x97, 0x46, 0xba
    }};
    /* R with wrong residuosity */
    const secp256k1_musig_signature sig2 = {{
        0x76, 0x2a, 0x13, 0xc5, 0x59, 0x48, 0xd5, 0xd0,
        0xaf, 0xc3, 0x12, 0x01, 0x4a, 0x13, 0xfb, 0x68,
        0x98, 0xac, 0x55, 0xfd, 0x9a, 0x85, 0xfa, 0xe9,
        0x87, 0x8b, 0x26, 0x2e, 0xdd, 0xf6, 0x5f, 0x99,
        0xf8, 0x4f, 0x86, 0x79, 0x76, 0x12, 0x0f, 0x72,
        0x2f, 0xa6, 0xec, 0xc5, 0x92, 0x5f, 0xe4, 0xb0,
        0x42, 0x64, 0xfe, 0x95, 0x84, 0x66, 0x09, 0xc7,
        0xc8, 0x45, 0x39, 0xb9, 0xa7, 0x85, 0xf5, 0x75
    }};
    /* Bad s, sig does not validate */
    const secp256k1_musig_signature sig3 = {{
        0x76, 0x2a, 0x13, 0xc5, 0x59, 0x48, 0xd5, 0xd0,
        0xaf, 0xc3, 0x12, 0x01, 0x4a, 0x13, 0xfb, 0x68,
        0x98, 0xac, 0x55, 0xfd, 0x9a, 0x85, 0xfa, 0xe9,
        0x87, 0x8b, 0x26, 0x2e, 0xdd, 0xf6, 0x5f, 0x99,
        0x6e, 0xe5, 0x0b, 0x14, 0xeb, 0xef, 0x1c, 0x15,
        0x9f, 0x09, 0x68, 0x8e, 0x84, 0xa9, 0x5b, 0xff,
        0xe9, 0x54, 0xa0, 0xdb, 0x0e, 0x71, 0xa9, 0x07,
        0x1c, 0x3b, 0xf9, 0xbe, 0x5e, 0x97, 0x46, 0xbb
    }};
    /* R not on curve */
    const secp256k1_musig_signature sig4 = {{
        0x76, 0x2a, 0x13, 0xc5, 0x59, 0x48, 0xd5, 0xd0,
        0xaf, 0xc3, 0x12, 0x01, 0x4a, 0x13, 0xfb, 0x68,
        0x98, 0xac, 0x55, 0xfd, 0x9a, 0x85, 0xfa, 0xe9,
        0x87, 0x8b, 0x26, 0x2e, 0xdd, 0xf6, 0x5f, 0x97,
        0x6e, 0xe5, 0x0b, 0x14, 0xeb, 0xef, 0x1c, 0x15,
        0x9f, 0x09, 0x68, 0x8e, 0x84, 0xa9, 0x5b, 0xff,
        0xe9, 0x54, 0xa0, 0xdb, 0x0e, 0x71, 0xa9, 0x07,
        0x1c, 0x3b, 0xf9, 0xbe, 0x5e, 0x97, 0x46, 0xba
    }};
    /* s = 0, legal in general except this doesn't validate */
    const secp256k1_musig_signature sig5 = {{
        0x76, 0x2a, 0x13, 0xc5, 0x59, 0x48, 0xd5, 0xd0,
        0xaf, 0xc3, 0x12, 0x01, 0x4a, 0x13, 0xfb, 0x68,
        0x98, 0xac, 0x55, 0xfd, 0x9a, 0x85, 0xfa, 0xe9,
        0x87, 0x8b, 0x26, 0x2e, 0xdd, 0xf6, 0x5f, 0x99,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }};
    /* r = 0, not on the curve plus this wouldn't validate if it was */
    const secp256k1_musig_signature sig6 = {{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xf8, 0x4f, 0x86, 0x79, 0x76, 0x12, 0x0f, 0x72,
        0x2f, 0xa6, 0xec, 0xc5, 0x92, 0x5f, 0xe4, 0xb0,
        0x42, 0x64, 0xfe, 0x95, 0x84, 0x66, 0x09, 0xc7,
        0xc8, 0x45, 0x39, 0xb9, 0xa7, 0x85, 0xf5, 0x75
    }};
    /* All zeroes */
    const secp256k1_musig_signature sig7 = {{ 0x00 }};
    /* r = field order */
    const secp256k1_musig_signature sig8 = {{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
        0xf8, 0x4f, 0x86, 0x79, 0x76, 0x12, 0x0f, 0x72,
        0x2f, 0xa6, 0xec, 0xc5, 0x92, 0x5f, 0xe4, 0xb0,
        0x42, 0x64, 0xfe, 0x95, 0x84, 0x66, 0x09, 0xc7,
        0xc8, 0x45, 0x39, 0xb9, 0xa7, 0x85, 0xf5, 0x75
    }};
    /* s = scalar order */
    const secp256k1_musig_signature sig9 = {{
        0x76, 0x2a, 0x13, 0xc5, 0x59, 0x48, 0xd5, 0xd0,
        0xaf, 0xc3, 0x12, 0x01, 0x4a, 0x13, 0xfb, 0x68,
        0x98, 0xac, 0x55, 0xfd, 0x9a, 0x85, 0xfa, 0xe9,
        0x87, 0x8b, 0x26, 0x2e, 0xdd, 0xf6, 0x5f, 0x99,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    }};
    /* R has a zillion leading zeroes. Still legal. */
    const secp256k1_musig_signature sig10 = {{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x3b, 0x78, 0xce, 0x56, 0x3f,
        0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28,
        0xad, 0x0d, 0x96, 0xd6, 0x79, 0x5f, 0x9c, 0x63,
        0x63, 0x56, 0xd3, 0x32, 0x2e, 0x73, 0x86, 0x24,
        0x15, 0xe5, 0xe0, 0xd9, 0x53, 0x7a, 0x78, 0x8d,
        0x41, 0x75, 0xb9, 0x9d, 0x6f, 0x2e, 0xa3, 0x02,
        0x11, 0xfe, 0xb9, 0x08, 0x64, 0x89, 0x98, 0x8e
    }};
    /* s has a some leading zeroes. Still legal. */
    const secp256k1_musig_signature sig11 = {{
        0x8f, 0xe5, 0x23, 0x6e, 0x79, 0x8a, 0xf1, 0x07,
        0xa9, 0xaf, 0x89, 0x09, 0x08, 0xb6, 0xe2, 0x15,
        0xd0, 0xc7, 0xe6, 0xcb, 0xd6, 0xe1, 0x29, 0xaf,
        0x83, 0xf1, 0xf3, 0x41, 0x36, 0x2f, 0x46, 0x81,
        0x00, 0x00, 0x00, 0xd7, 0x50, 0x41, 0xdb, 0xfe,
        0xc6, 0x31, 0x48, 0x6f, 0xea, 0x37, 0xa7, 0xdf,
        0x42, 0xf1, 0xd6, 0x01, 0x3a, 0x88, 0x75, 0xfb,
        0x9d, 0x44, 0x79, 0x2a, 0xa7, 0x49, 0x34, 0x12
    }};

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &tmpj, &sk);
    secp256k1_ge_set_gej(&tmpg, &tmpj);
    secp256k1_pubkey_save(&pk, &tmpg);

    CHECK(secp256k1_musig_single_sign(ctx, &sig, msg1, sk32, NULL, NULL));
    CHECK(memcmp(&sig, &sig1, 64) == 0);

    secp256k1_musig_test_verify(1, &sig1, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig2, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig3, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig4, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig5, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig6, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig7, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig8, msg1, &pk, scratch);
    secp256k1_musig_test_verify(0, &sig9, msg1, &pk, scratch);
    secp256k1_musig_test_verify(1, &sig10, msg1, &pk, scratch);
    secp256k1_musig_test_verify(1, &sig11, msg1, &pk, scratch);

    sig_arr[0] = &sig1;
    sig_arr[1] = &sig10;
    sig_arr[2] = &sig11;
    msg_arr[0] = msg_arr[1] = msg_arr[2] = msg1;
    pk_arr[0] = pk_arr[1] = pk_arr[2] = &pk;
    CHECK(secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, 3, NULL, NULL, NULL, 0, NULL, NULL));
}

void run_musig_tests(void) {
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    musig_api_tests(scratch);
    musig_test_serialize();
    musig_sign_verify(scratch);
    musig_taproot_verify(scratch);
    metas_schnorr_bip_vectors(scratch);

    secp256k1_scratch_space_destroy(scratch);
}

#endif
