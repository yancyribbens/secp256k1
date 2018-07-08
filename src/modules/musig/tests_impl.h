/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_TESTS_
#define _SECP256K1_MODULE_MUSIG_TESTS_

#include "secp256k1_musig.h"

void musig_api_tests(secp256k1_scratch_space *scratch) {
    secp256k1_musig_secret_key tweak_sk[3];
    unsigned char sk1[32];
    unsigned char sk2[32];
    unsigned char sk3[32];
    unsigned char msg[32];
    unsigned char secnon1[32];
    unsigned char secnon3[32];
    unsigned char noncom1[32];
    unsigned char noncom3[32];
    unsigned char sig64[64];
    secp256k1_pubkey pk[3];
    secp256k1_pubkey pubnon1;
    secp256k1_pubkey pubnon3;
    secp256k1_pubkey tweak_pk[3];
    secp256k1_pubkey combine_pk;
    secp256k1_pubkey combine_pk_taproot;
    secp256k1_musig_signature sig;
    secp256k1_musig_partial_signature partial_sig[2];
    secp256k1_musig_validation_aux aux;
    const secp256k1_musig_signature *sigptr = &sig;
    const unsigned char *msgptr = msg;

    unsigned char commit[32];
    const unsigned char *commitptr = commit;
    unsigned char tp_tweak[32];
    const secp256k1_pubkey *pkptr = &pk[0];
    const secp256k1_pubkey *tptr = &combine_pk_taproot;
    const secp256k1_pubkey *utptr = &combine_pk;
    secp256k1_musig_signer_data signer_data[3];
    unsigned char shards1_arr[3][32];
    unsigned char shards2_arr[3][32];
    unsigned char shards3_arr[3][32];
    unsigned char *shards1[3];
    unsigned char *shards2[3];
    unsigned char *shards3[3];
    secp256k1_pubkey pubcoeff1[2];
    secp256k1_pubkey pubcoeff2[2];
    secp256k1_pubkey pubcoeff3[2];
    secp256k1_pubkey kn_pubkeys[3];
    size_t i;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    for (i = 0; i < 3; i++) {
        shards1[i] = shards1_arr[i];
        shards2[i] = shards2_arr[i];
        shards3[i] = shards3_arr[i];
    }
    secp256k1_rand256(sk1);
    secp256k1_rand256(sk2);
    secp256k1_rand256(sk3);
    secp256k1_rand256(msg);
    secp256k1_rand256(commit);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[0], sk1) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[1], sk2) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[2], sk3) == 1);

    /** main test body **/
    /** key setup **/
    ecount = 0;
    CHECK(secp256k1_musig_pubkey_combine(none, tweak_pk, &combine_pk, pk, 3) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubkey_combine(sign, tweak_pk, &combine_pk, pk, 3) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, tweak_pk, &combine_pk, pk, 3) == 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, NULL, &combine_pk, pk, 3) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, tweak_pk, NULL, pk, 3) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, tweak_pk, &combine_pk, NULL, 3) == 0);
    CHECK(ecount == 4);

    CHECK(secp256k1_musig_pubkey_combine(vrfy, tweak_pk, &combine_pk, pk, 3) == 1);
    CHECK(secp256k1_taproot_hash_default(tp_tweak, &combine_pk, commit, NULL));
    memcpy(&combine_pk_taproot, &combine_pk, sizeof(combine_pk));
    CHECK(secp256k1_ec_pubkey_tweak_add(vrfy, &combine_pk_taproot, tp_tweak));

    ecount = 0;
    CHECK(secp256k1_musig_tweak_secret_key(none, &tweak_sk[0], sk1, pk, 3, 0) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(none, NULL, sk1, pk, 3, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_tweak_secret_key(none, &tweak_sk[0], NULL, pk, 3, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_tweak_secret_key(none, &tweak_sk[0], sk1, NULL, 3, 0) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_musig_tweak_secret_key(none, &tweak_sk[0], sk1, pk, 3, 0) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(none, &tweak_sk[1], sk2, pk, 3, 1) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(none, &tweak_sk[2], sk3, pk, 3, 2) == 1);

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

    ecount = 0;
    CHECK(secp256k1_musig_keysplit(none, shards2, pubcoeff2, &tweak_sk[1], 1, 3, commit) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_keysplit(vrfy, shards2, pubcoeff2, &tweak_sk[1], 1, 3, commit) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_keysplit(sign, shards2, pubcoeff2, &tweak_sk[1], 1, 3, commit) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_keysplit(sign, NULL, pubcoeff2, &tweak_sk[1], 1, 3, commit) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_keysplit(sign, shards2, NULL, &tweak_sk[1], 1, 3, commit) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_keysplit(sign, shards2, pubcoeff2, NULL, 1, 3, commit) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_keysplit(sign, shards2, pubcoeff2, &tweak_sk[1], 0, 3, commit) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_keysplit(sign, shards2, pubcoeff2, &tweak_sk[1], 3, 3, commit) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_keysplit(sign, shards2, pubcoeff2, &tweak_sk[1], 0, 0, commit) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_keysplit(sign, shards2, pubcoeff2, &tweak_sk[1], 2, 3, NULL) == 0);
    CHECK(ecount == 6);

    CHECK(secp256k1_musig_keysplit(sign, shards1, pubcoeff1, &tweak_sk[0], 2, 3, commit) == 1);
    CHECK(secp256k1_musig_keysplit(sign, shards2, pubcoeff2, &tweak_sk[1], 2, 3, commit) == 1);
    CHECK(secp256k1_musig_keysplit(sign, shards3, pubcoeff3, &tweak_sk[2], 2, 3, commit) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_verify_shard(none, scratch, &tweak_sk[0], kn_pubkeys, 3, 0, shards1[0], 0, pubcoeff1, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_verify_shard(sign, scratch, &tweak_sk[0], kn_pubkeys, 3, 0, shards1[0], 0, pubcoeff1, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_verify_shard(vrfy, scratch, &tweak_sk[0], kn_pubkeys, 3, 0, shards1[0], 0, pubcoeff1, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_verify_shard(both, scratch, &tweak_sk[0], kn_pubkeys, 3, 0, shards1[0], 0, pubcoeff1, 2) == 1);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_verify_shard(both, NULL, &tweak_sk[0], kn_pubkeys, 3, 0, shards1[0], 0, pubcoeff1, 2) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_verify_shard(both, scratch, NULL, kn_pubkeys, 3, 0, shards1[0], 0, pubcoeff1, 2) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_verify_shard(both, scratch, &tweak_sk[0], NULL, 3, 0, shards1[0], 0, pubcoeff1, 2) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_verify_shard(both, scratch, &tweak_sk[0], kn_pubkeys, 3, 0, NULL, 0, pubcoeff1, 2) == 1);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_verify_shard(both, scratch, &tweak_sk[0], kn_pubkeys, 3, 0, shards1[0], 0, NULL, 2) == 0);
    CHECK(ecount == 6);

    for (i = 0; i < 3; i++) {
        secp256k1_pubkey tmp[3];

        CHECK(secp256k1_musig_verify_shard(both, scratch, &tweak_sk[i], tmp, 3, 0, shards1[i], i, pubcoeff1, 2) == 1);
        CHECK(secp256k1_musig_verify_shard(both, scratch, &tweak_sk[i], tmp, 3, 1, shards2[i], i, pubcoeff2, 2) == 1);
        CHECK(secp256k1_musig_verify_shard(both, scratch, &tweak_sk[i], tmp, 3, 1, shards3[i], i, pubcoeff3, 2) == 1);
        if (i == 0) {
            memcpy(kn_pubkeys, tmp, sizeof(kn_pubkeys));
        } else {
            CHECK(!memcmp(kn_pubkeys, tmp, sizeof(kn_pubkeys)));
        }
    }
    /* TODO check correct key and attest pubshards */


    /** signing (shards, etc., are gone, i.e. not assumed to have been stored after key setup.
     *  only available data is tweaked_pk array and tweaked_sk. For this signature we will
     *  have signers 0 and 2 present, and 1 missing.
     *
     * For the API tests we will only generate `signer_data` once and use it for both signers,
     * since it contains only public data that should be the same for all signers.
     */
    ecount = 0;
    CHECK(secp256k1_musig_multisig_generate_nonce(none, secnon1, &pubnon1, noncom1, &tweak_sk[0], msg, commit) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, &tweak_sk[0], msg, commit) == 1);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_multisig_generate_nonce(vrfy, secnon1, &pubnon1, noncom1, &tweak_sk[0], msg, commit) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, NULL, &pubnon1, noncom1, &tweak_sk[0], msg, commit) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, NULL, noncom1, &tweak_sk[0], msg, commit) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, NULL, &tweak_sk[0], msg, commit) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, NULL, msg, commit) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, &tweak_sk[0], NULL, commit) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, &tweak_sk[0], msg, NULL) == 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, &tweak_sk[0], msg, commit) == 1);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon3, &pubnon3, noncom3, &tweak_sk[2], msg, commit) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[0], &kn_pubkeys[0], noncom1) == 1);
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[0], NULL, noncom1) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[1], &kn_pubkeys[1], NULL) == 1);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[2], &kn_pubkeys[2], noncom3) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[0], &pubnon1) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_set_nonce(none, NULL, &pubnon1) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[0], NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[1], &pubnon1) == 0);
    CHECK(ecount == 2);

    CHECK(secp256k1_musig_set_nonce(none, &signer_data[0], &pubnon1) == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[2], &pubnon3) == 1);
    CHECK(ecount == 2);

    ecount = 0;
    CHECK(secp256k1_musig_partial_sign(none, scratch, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk, msg, secnon1, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk, msg, secnon1, signer_data, 3, 0, NULL) == 1);
    CHECK(secp256k1_musig_partial_sign(vrfy, NULL, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk, msg, secnon1, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, NULL, &aux, &tweak_sk[0], &combine_pk, msg, secnon1, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], NULL, &tweak_sk[0], &combine_pk, msg, secnon1, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, NULL, &combine_pk, msg, secnon1, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, &tweak_sk[0], NULL, msg, secnon1, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk, NULL, secnon1, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk, msg, NULL, signer_data, 3, 0, NULL) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk, msg, secnon1, NULL, 3, 0, NULL) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk, msg, secnon1, signer_data, 3, 1, NULL) == 0); /* sign as missing signer */
    CHECK(ecount == 9);

    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, &tweak_sk[0], &combine_pk_taproot, msg, secnon1, signer_data, 3, 0, NULL) == 1);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[1], &aux, &tweak_sk[2], &combine_pk_taproot, msg, secnon3, signer_data, 3, 2, NULL) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_verify(none, &partial_sig[0], &signer_data[0], &aux) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_verify(sign, &partial_sig[0], &signer_data[0], &aux) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &signer_data[0], &aux) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &signer_data[1], &aux) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &signer_data[2], &aux) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, partial_sig, 2, signer_data, 3, &aux, NULL) == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, NULL, partial_sig, 2, signer_data, 3, &aux, NULL) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, NULL, 2, signer_data, 3, &aux, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, partial_sig, 4, signer_data, 3, &aux, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, partial_sig, 2, NULL, 3, &aux, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, partial_sig, 2, signer_data, 3, NULL, NULL) == 0);
    CHECK(ecount == 5);

    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, partial_sig, 2, signer_data, 3, &aux, tp_tweak) == 1);
    CHECK(secp256k1_musig_verify_1(vrfy, &sig, msg, &combine_pk_taproot) == 1);

    /** cleanup **/
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
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
        unsigned char buf[32];
        secp256k1_rand256(tweak[i]);

        CHECK(secp256k1_musig_pubkey_combine(ctx, NULL, &untweaked[i], &pk, 1));
        CHECK(secp256k1_musig_pubkey_combine(ctx, NULL, &tweaked[i], &pk, 1));
        CHECK(secp256k1_taproot_hash_default(buf, &tweaked[i], tweak[i], NULL));
        CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &tweaked[i], buf));

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
    unsigned char buf[32];
    secp256k1_pubkey pk;
    secp256k1_pubkey untweaked_pk;
    secp256k1_pubkey tweaked_pk;

    const unsigned char *tweak_arr = tweak;
    const secp256k1_pubkey *untweaked_pk_arr = &untweaked_pk;
    const secp256k1_pubkey *tweaked_pk_arr = &tweaked_pk;

    CHECK(secp256k1_ec_pubkey_create(ctx, &pk, sk));

    CHECK(secp256k1_musig_pubkey_combine(ctx, NULL, &untweaked_pk, &pk, 1));
    CHECK(secp256k1_musig_pubkey_combine(ctx, NULL, &tweaked_pk, &pk, 1));
    CHECK(secp256k1_taproot_hash_default(buf, &tweaked_pk, tweak, NULL));
    CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &tweaked_pk, buf));

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

void metas_schnorr_bip_vectors_signing_check(const unsigned char *sk, const unsigned char *pk_serialized, const unsigned char *msg, const unsigned char *expected_sig) {
    secp256k1_musig_signature sig;
    unsigned char serialized_sig[64];
    secp256k1_pubkey pk;

    CHECK(secp256k1_musig_single_sign(ctx, &sig, msg, sk, NULL, NULL));
    CHECK(secp256k1_musig_signature_serialize(ctx, serialized_sig, &sig));
    CHECK(memcmp(serialized_sig, expected_sig, 64) == 0);

    CHECK(secp256k1_ec_pubkey_parse(ctx, &pk, pk_serialized, 33));
    CHECK(secp256k1_musig_verify_1(ctx, &sig, msg, &pk));
}

void metas_schnorr_bip_vectors_signing(void) {
    const unsigned char sk1[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    const unsigned char pk1[33] = {
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
        0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
        0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
        0x98
    };
    const unsigned char msg1[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    const unsigned char expected_sig1[64] = {
        0x78, 0x7A, 0x84, 0x8E, 0x71, 0x04, 0x3D, 0x28,
        0x0C, 0x50, 0x47, 0x0E, 0x8E, 0x15, 0x32, 0xB2,
        0xDD, 0x5D, 0x20, 0xEE, 0x91, 0x2A, 0x45, 0xDB,
        0xDD, 0x2B, 0xD1, 0xDF, 0xBF, 0x18, 0x7E, 0xF6,
        0x70, 0x31, 0xA9, 0x88, 0x31, 0x85, 0x9D, 0xC3,
        0x4D, 0xFF, 0xEE, 0xDD, 0xA8, 0x68, 0x31, 0x84,
        0x2C, 0xCD, 0x00, 0x79, 0xE1, 0xF9, 0x2A, 0xF1,
        0x77, 0xF7, 0xF2, 0x2C, 0xC1, 0xDC, 0xED, 0x05
    };

    const unsigned char sk2[32] = {
        0xB7, 0xE1, 0x51, 0x62, 0x8A, 0xED, 0x2A, 0x6A,
        0xBF, 0x71, 0x58, 0x80, 0x9C, 0xF4, 0xF3, 0xC7,
        0x62, 0xE7, 0x16, 0x0F, 0x38, 0xB4, 0xDA, 0x56,
        0xA7, 0x84, 0xD9, 0x04, 0x51, 0x90, 0xCF, 0xEF
    };
    const unsigned char pk2[33] = {
        0x02, 0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C,
        0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41,
        0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE,
        0xD8, 0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6,
        0x59
    };
    const unsigned char msg2[32] = {
        0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
        0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
        0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
        0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89
    };
    const unsigned char expected_sig2[64] = {
        0x2A, 0x29, 0x8D, 0xAC, 0xAE, 0x57, 0x39, 0x5A,
        0x15, 0xD0, 0x79, 0x5D, 0xDB, 0xFD, 0x1D, 0xCB,
        0x56, 0x4D, 0xA8, 0x2B, 0x0F, 0x26, 0x9B, 0xC7,
        0x0A, 0x74, 0xF8, 0x22, 0x04, 0x29, 0xBA, 0x1D,
        0x1E, 0x51, 0xA2, 0x2C, 0xCE, 0xC3, 0x55, 0x99,
        0xB8, 0xF2, 0x66, 0x91, 0x22, 0x81, 0xF8, 0x36,
        0x5F, 0xFC, 0x2D, 0x03, 0x5A, 0x23, 0x04, 0x34,
        0xA1, 0xA6, 0x4D, 0xC5, 0x9F, 0x70, 0x13, 0xFD
    };

    const unsigned char sk3[32] = {
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x14, 0xE5, 0xC7
    };
    const unsigned char pk3[33] = {
        0x03, 0xFA, 0xC2, 0x11, 0x4C, 0x2F, 0xBB, 0x09,
        0x15, 0x27, 0xEB, 0x7C, 0x64, 0xEC, 0xB1, 0x1F,
        0x80, 0x21, 0xCB, 0x45, 0xE8, 0xE7, 0x80, 0x9D,
        0x3C, 0x09, 0x38, 0xE4, 0xB8, 0xC0, 0xE5, 0xF8,
        0x4B
    };
    const unsigned char msg3[32] = {
        0x5E, 0x2D, 0x58, 0xD8, 0xB3, 0xBC, 0xDF, 0x1A,
        0xBA, 0xDE, 0xC7, 0x82, 0x90, 0x54, 0xF9, 0x0D,
        0xDA, 0x98, 0x05, 0xAA, 0xB5, 0x6C, 0x77, 0x33,
        0x30, 0x24, 0xB9, 0xD0, 0xA5, 0x08, 0xB7, 0x5C
    };
    const unsigned char expected_sig3[64] = {
        0x00, 0xDA, 0x9B, 0x08, 0x17, 0x2A, 0x9B, 0x6F,
        0x04, 0x66, 0xA2, 0xDE, 0xFD, 0x81, 0x7F, 0x2D,
        0x7A, 0xB4, 0x37, 0xE0, 0xD2, 0x53, 0xCB, 0x53,
        0x95, 0xA9, 0x63, 0x86, 0x6B, 0x35, 0x74, 0xBE,
        0x00, 0x88, 0x03, 0x71, 0xD0, 0x17, 0x66, 0x93,
        0x5B, 0x92, 0xD2, 0xAB, 0x4C, 0xD5, 0xC8, 0xA2,
        0xA5, 0x83, 0x7E, 0xC5, 0x7F, 0xED, 0x76, 0x60,
        0x77, 0x3A, 0x05, 0xF0, 0xDE, 0x14, 0x23, 0x80
    };

    metas_schnorr_bip_vectors_signing_check(sk1, pk1, msg1, expected_sig1);
    metas_schnorr_bip_vectors_signing_check(sk2, pk2, msg2, expected_sig2);
    metas_schnorr_bip_vectors_signing_check(sk3, pk3, msg3, expected_sig3);
}

void musig_kofn(secp256k1_scratch_space *scratch, size_t k, size_t n) {
    const unsigned char msg32[32] = "im so tired of choosing messages";

    secp256k1_pubkey *pk;
    secp256k1_pubkey *tweak_pk;
    secp256k1_pubkey *tweak_pk2;
    secp256k1_pubkey combine_pk;

    unsigned char **sk;
    secp256k1_musig_secret_key *tweak_sk;
    unsigned char ***privshard;
    secp256k1_pubkey **pubcoeff;

    unsigned char **secnon;
    secp256k1_musig_signer_data *data;
    secp256k1_musig_partial_signature *partial_sig;

    secp256k1_musig_validation_aux aux;
    secp256k1_musig_signature sig;
    size_t present_count;
    size_t i;

    CHECK(secp256k1_scratch_allocate_frame(
        scratch,
        n * (sizeof(*pk) +
             sizeof(*tweak_pk) +
             sizeof(*tweak_pk2) +
             sizeof(*sk) + 32 +
             sizeof(*tweak_sk) +
             sizeof(*privshard) + n*sizeof(*privshard) + n*n*32 +
             sizeof(*pubcoeff) + n*k*sizeof(**pubcoeff) +
             sizeof(*secnon) + 32 +
             sizeof(*data)) +
        k * sizeof(*partial_sig),
        10 + 4 * n + n*n
    ));

    pk = (secp256k1_pubkey *)secp256k1_scratch_alloc(scratch, n * sizeof(*pk));
    tweak_pk = (secp256k1_pubkey *)secp256k1_scratch_alloc(scratch, n * sizeof(*tweak_pk));
    tweak_pk2 = (secp256k1_pubkey *)secp256k1_scratch_alloc(scratch, n * sizeof(*tweak_pk2));
    sk = (unsigned char **)secp256k1_scratch_alloc(scratch, n * sizeof(*sk));
    tweak_sk = (secp256k1_musig_secret_key *)secp256k1_scratch_alloc(scratch, n * sizeof(*tweak_sk));
    privshard = (unsigned char ***)secp256k1_scratch_alloc(scratch, n * sizeof(*privshard));
    pubcoeff = (secp256k1_pubkey **)secp256k1_scratch_alloc(scratch, n * sizeof(*pubcoeff));
    secnon = (unsigned char **)secp256k1_scratch_alloc(scratch, n * sizeof(*secnon));
    data = (secp256k1_musig_signer_data *)secp256k1_scratch_alloc(scratch, n * sizeof(*data));
    partial_sig = (secp256k1_musig_partial_signature *)secp256k1_scratch_alloc(scratch, k * sizeof(*partial_sig));

    for (i = 0; i < n; i++) {
        size_t j;

        sk[i] = (unsigned char *)secp256k1_scratch_alloc(scratch, 32);
        privshard[i] = (unsigned char **)secp256k1_scratch_alloc(scratch, n * sizeof(*privshard[i]));
        for (j = 0; j < n; j++) {
            privshard[i][j] = (unsigned char *)secp256k1_scratch_alloc(scratch, 32);
        }
        pubcoeff[i] = (secp256k1_pubkey *)secp256k1_scratch_alloc(scratch, k * sizeof(*pubcoeff[i]));
        secnon[i] = (unsigned char *)secp256k1_scratch_alloc(scratch, 32);
    }

    /* key setup */
    for (i = 0; i < n; i++) {
        secp256k1_rand256(sk[i]);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pk[i], sk[i]) == 1);
    }
    CHECK(secp256k1_musig_pubkey_combine(ctx, tweak_pk, &combine_pk, pk, n));

    for (i = 0; i < n; i++) {
        unsigned char seed[32];
        secp256k1_rand256(seed);

        CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_sk[i], sk[i], pk, n, i) == 1);
    }

    /* we do sharding and splitting only for the k-of-n case; for n-of-n everyone
     * keeps the keys they got from `secp256k1_musig_pubkey_combine`. The two cases
     * are otherwise identical. */
    if (k < n) {
        for (i = 0; i < n; i++) {
            unsigned char seed[32];
            secp256k1_rand256(seed);
            CHECK(secp256k1_musig_keysplit(ctx, privshard[i], pubcoeff[i], &tweak_sk[i], k, n, seed));
        }

        for (i = 0; i < n; i++) {
            size_t j;

            CHECK(secp256k1_musig_verify_shard(ctx, scratch, &tweak_sk[i], tweak_pk2, n, 0, privshard[0][i], i, pubcoeff[0], k) == 1);
            for (j = 1; j < n; j++) {
                CHECK(secp256k1_musig_verify_shard(ctx, scratch, &tweak_sk[i], tweak_pk2, n, 1, privshard[j][i], i, pubcoeff[j], k) == 1);
            }
            if (i == 0) {
                memcpy(tweak_pk, tweak_pk2, n * sizeof(*tweak_pk));
            } else {
                CHECK(memcmp(tweak_pk, tweak_pk2, n * sizeof(*tweak_pk)) == 0);
            }
        }
    }

    /* signing */

    /* We're going to cheat here and generate nonce-commitments and nonces then immediately
     * load them into a shared `signer_data` array. In real life signers need to communicate
     * their commitments, then communicate their nonces, and everyone makes their own array
     * with this data. */
    present_count = 0;
    for (i = 0; i < n; i++) {
        unsigned char seed[32];
        unsigned char noncom[32];
        secp256k1_pubkey pubnon;
        secp256k1_rand256(seed);

        /* flip a coin to decide whether the signer should be present,
         * unless we already have `k` signers, or unless we need all
         * remaining signers to be present in order to hit `k`. */
        if (present_count < k &&
            (n - i == (k - present_count) || seed[0] & 1)) {
            CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon[i], &pubnon, noncom, &tweak_sk[i], msg32, seed) == 1);
            CHECK(secp256k1_musig_signer_data_initialize(ctx, &data[i], &tweak_pk[i], noncom) == 1);
            CHECK(secp256k1_musig_set_nonce(ctx, &data[i], &pubnon) == 1);
            present_count++;
        } else {
            CHECK(secp256k1_musig_signer_data_initialize(ctx, &data[i], &tweak_pk[i], NULL) == 1);
        }
    }
    CHECK(present_count == k);

    present_count = 0;
    for (i = 0; i < n; i++) {
        secp256k1_musig_validation_aux tmp_aux;
        if (!data[i].present) {
            unsigned char tmp_secnon[32] = {1};
            CHECK(!secp256k1_musig_partial_sign(ctx, scratch, &partial_sig[present_count], &tmp_aux, &tweak_sk[i], &combine_pk, msg32, tmp_secnon, data, n, i, NULL));
            continue;
        }

        CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig[present_count], &tmp_aux, &tweak_sk[i], &combine_pk, msg32, secnon[i], data, n, i, NULL));

        CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[present_count], &data[i], &tmp_aux) == 1);
        CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[present_count], &data[!i], &tmp_aux) == 0);
        if (present_count == 0) {
            memcpy(&aux, &tmp_aux, sizeof(aux));
        } else {
            CHECK(!memcmp(&aux, &tmp_aux, sizeof(aux)));
        }
        present_count++;
    }

    CHECK(secp256k1_musig_partial_sig_combine(ctx, &sig, partial_sig, k, data, n, &aux, NULL));
    CHECK(secp256k1_musig_verify_1(ctx, &sig, msg32, &combine_pk));

    secp256k1_scratch_deallocate_frame(scratch);
}

void scriptless_atomic_swap(secp256k1_scratch_space *scratch) {
    /* Thoughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    secp256k1_musig_signature final_sig_a;
    secp256k1_musig_signature final_sig_b;
    secp256k1_musig_partial_signature partial_sig_a[2];
    secp256k1_musig_partial_signature partial_sig_b[2];
    secp256k1_musig_partial_signature adaptor_sig_a;
    secp256k1_musig_partial_signature adaptor_sig_b;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor_a;
    secp256k1_pubkey pub_adaptor_b;
    secp256k1_musig_validation_aux aux_a;
    secp256k1_musig_validation_aux aux_b;

    unsigned char seckey_a[2][32];
    unsigned char seckey_b[2][32];
    secp256k1_musig_secret_key tweak_seckey_a[2];
    secp256k1_musig_secret_key tweak_seckey_b[2];
    secp256k1_pubkey pk_a[2];
    secp256k1_pubkey pk_b[2];
    secp256k1_pubkey combine_pk_a;
    secp256k1_pubkey combine_pk_b;
    unsigned char secnon_a[2][32];
    unsigned char secnon_b[2][32];
    unsigned char noncommit_a[2][32];
    unsigned char noncommit_b[2][32];
    secp256k1_pubkey pubnon_a[2];
    secp256k1_pubkey pubnon_b[2];
    secp256k1_musig_signer_data data_a[2];
    secp256k1_musig_signer_data data_b[2];

    const unsigned char seed[32] = "still tired of choosing seeds...";
    const unsigned char msg32_a[32] = "this is the message blockchain a";
    const unsigned char msg32_b[32] = "this is the message blockchain b";

    /* Step 1: key setup */
    secp256k1_rand256(seckey_a[0]);
    secp256k1_rand256(seckey_a[1]);
    secp256k1_rand256(seckey_b[0]);
    secp256k1_rand256(seckey_b[1]);
    secp256k1_rand256(sec_adaptor);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_a[0], seckey_a[0]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_a[1], seckey_a[1]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_b[0], seckey_b[0]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_b[1], seckey_b[1]));

    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_a[0], seckey_a[0], pk_a, 2, 0) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_a[1], seckey_a[1], pk_a, 2, 1) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_b[0], seckey_b[0], pk_b, 2, 0) == 1);
    CHECK(secp256k1_musig_tweak_secret_key(ctx, &tweak_seckey_b[1], seckey_b[1], pk_b, 2, 1) == 1);

    CHECK(secp256k1_musig_pubkey_combine(ctx, pk_a, &combine_pk_a, pk_a, 2));
    CHECK(secp256k1_musig_pubkey_combine(ctx, pk_b, &combine_pk_b, pk_b, 2));

    /* Step 2: Exchange nonces */
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_a[0], &pubnon_a[0], noncommit_a[0], &tweak_seckey_a[0], msg32_a, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_a[1], &pubnon_a[1], noncommit_a[1], &tweak_seckey_a[1], msg32_a, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_b[0], &pubnon_b[0], noncommit_b[0], &tweak_seckey_b[0], msg32_b, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_b[1], &pubnon_b[1], noncommit_b[1], &tweak_seckey_b[1], msg32_b, seed));

    secp256k1_musig_signer_data_initialize(ctx, &data_a[0], &pk_a[0], noncommit_a[0]);
    secp256k1_musig_signer_data_initialize(ctx, &data_a[1], &pk_a[1], noncommit_a[1]);
    secp256k1_musig_signer_data_initialize(ctx, &data_b[0], &pk_b[0], noncommit_b[0]);
    secp256k1_musig_signer_data_initialize(ctx, &data_b[1], &pk_b[1], noncommit_b[1]);
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[0], &pubnon_a[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[1], &pubnon_a[1]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[0], &pubnon_b[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[1], &pubnon_b[1]));

    /* Step 2: Signer 0 produces adaptor signatures */
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &adaptor_sig_a, &aux_a, &tweak_seckey_a[0], &combine_pk_a, msg32_a, secnon_a[0], data_a, 2, 0, sec_adaptor));
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &adaptor_sig_b, &aux_b, &tweak_seckey_b[0], &combine_pk_b, msg32_b, secnon_b[0], data_b, 2, 0, sec_adaptor));

    /* Step 3: Signer 1 receives adaptor signatures, checks that they used the same tweak, and signs to send B-coins */
    CHECK(secp256k1_musig_adaptor_signature_extract(ctx, &pub_adaptor_a, &adaptor_sig_a, &data_a[0], &aux_a));
    CHECK(secp256k1_musig_adaptor_signature_extract(ctx, &pub_adaptor_b, &adaptor_sig_b, &data_b[0], &aux_b));
    CHECK(memcmp(&pub_adaptor_a, &pub_adaptor_b, sizeof(pub_adaptor_a)) == 0); /* TODO the API says we're not allowed to compare pubkeys like this, but c'mon */
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig_b[1], &aux_b, &tweak_seckey_b[1], &combine_pk_b, msg32_b, secnon_b[1], data_b, 2, 1, NULL));

    /* Step 4: Signer 0 signs to take B-coins, combines signatures and publishes */
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig_b[0], &aux_b, &tweak_seckey_b[0], &combine_pk_b, msg32_b, secnon_b[0], data_b, 2, 0, NULL));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &final_sig_b, partial_sig_b, 2, data_b, 2, &aux_b, NULL) == 1);
    CHECK(secp256k1_musig_verify_1(ctx, &final_sig_b, msg32_b, &combine_pk_b) == 1);

    /* Step 5: Signer 1 extracts secret from published signature, applies it to other adaptor signature, and takes A-coins */
    CHECK(secp256k1_musig_adaptor_signature_extract_secret(ctx, sec_adaptor_extracted, &final_sig_b, &adaptor_sig_b, &partial_sig_b[1], NULL, NULL) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(secp256k1_musig_adaptor_signature_adapt(ctx, &partial_sig_a[0], &adaptor_sig_a, sec_adaptor_extracted));
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig_a[1], &aux_a, &tweak_seckey_a[1], &combine_pk_a, msg32_a, secnon_a[1], data_a, 2, 1, NULL));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &final_sig_a, partial_sig_a, 2, data_a, 2, &aux_a, NULL) == 1);
    CHECK(secp256k1_musig_verify_1(ctx, &final_sig_a, msg32_a, &combine_pk_a) == 1);
}

void run_musig_tests(void) {
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    musig_api_tests(scratch);
    musig_test_serialize();
    musig_sign_verify(scratch);
    musig_taproot_verify(scratch);
    metas_schnorr_bip_vectors(scratch);
    metas_schnorr_bip_vectors_signing();

    musig_kofn(scratch, 2, 3);
    musig_kofn(scratch, 1, 10);
    musig_kofn(scratch, 2, 10);
    musig_kofn(scratch, 3, 10);
    musig_kofn(scratch, 10, 10);
    scriptless_atomic_swap(scratch);

    secp256k1_scratch_space_destroy(scratch);
}

#endif
