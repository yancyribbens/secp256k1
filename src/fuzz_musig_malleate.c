#include <stdio.h>

#include "include/secp256k1.h"
#include "secp256k1.c"
#include "ecmult_static_context.h"

/*
 * This program creates a valid signature for a (key, sig, msg)-tuple. Then it
 * reads data from stdin that is used to malleate the tuple in various ways and
 * checks that on the resulting tuple Schnorr verification fails.
 */

/* Returns data as nonce */
static int nonce_function_fuzz(const secp256k1_context *ctx, unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
    (void) ctx;
    (void) msg32;
    (void) key32;
    (void) algo16;
    (void) counter;
    if(memcmp(nonce32, data, 32) == 0) {
        /* nonce = 0 results in infinite loop during signing */
        ((unsigned char*)data)[31] = 0x01;
    }
    memcpy(nonce32, data, 32);
    return 1;
}

/* Checks that result of single and batch verification is expected */
void check(secp256k1_context *ctx, int expected, const secp256k1_musig_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pk, secp256k1_scratch_space *scratch, const secp256k1_musig_signature *goodsig, const unsigned char *goodmsg32, const secp256k1_pubkey *goodpk) {
    const unsigned char *msg_arr[2];
    const secp256k1_musig_signature *sig_arr[2];
    const secp256k1_pubkey *pk_arr[2];

    sig_arr[0] = sig;
    sig_arr[1] = goodsig;
    msg_arr[0] = msg32;
    msg_arr[1] = goodmsg32;
    pk_arr[0] = pk;
    pk_arr[1] = goodpk;

    CHECK(expected == secp256k1_musig_verify_1(ctx, sig, msg32, pk));
    CHECK(expected == secp256k1_musig_verify(ctx, scratch, sig_arr, msg_arr, pk_arr, 2, NULL, NULL, NULL, 0, NULL, NULL));
}

typedef struct {
    unsigned char *seckey_data;
    unsigned char *privnonce_data;
    unsigned char *new_s;
    unsigned char *new_s_type;
    unsigned char *new_nonce;
    unsigned char *new_nonce_type;
    unsigned char *new_msg;
    unsigned char *new_msg_type;
    unsigned char *new_x;
    unsigned char *new_x_type;
} secp256k1_musig_fuzzer_input;

/*
 * 32 byte privkey, 32 byte privnonce
 *  * 1 byte type (use / ignore) 32 byte new_s
 *  * 1 byte type (use scalar, add scalar, use point, add point), 33 byte nonce
 *  * 1 byte type (use / ignore), 32 byte msg
 *  * 1 byte type (use scalar / add scalar / use point / add point) 33 new_x
 */
int parse(secp256k1_musig_fuzzer_input* input, char *data, size_t ndata) {
    if (ndata < 32 + 32 + 1 + 32 + 1 + 33 + 1 + 32 + 1 + 33) {
        return 0;
    }

    input->seckey_data = (unsigned char*) data;
    data += 32;
    input->privnonce_data = (unsigned char*) data;
    data += 32;
    input->new_s_type = (unsigned char*) data;
    data += 1;
    input->new_s = (unsigned char*) data;
    data += 32;
    input->new_nonce_type = (unsigned char*) data;
    data += 1;
    input->new_nonce = (unsigned char*) data;
    data += 33;
    input->new_msg_type = (unsigned char*) data;
    data += 1;
    input->new_msg = (unsigned char*) data;
    data += 32;
    input->new_x_type = (unsigned char*) data;
    data += 1;
    input->new_x = (unsigned char*) data;
    return 1;
}

void compare(secp256k1_context *ctx, char *data, size_t ndata) {
    secp256k1_musig_signature sig;
    unsigned char msg[32];
    secp256k1_scalar privnonce;
    secp256k1_scalar seckey;
    secp256k1_pubkey pk;
    secp256k1_scratch_space *scratch;
    secp256k1_musig_fuzzer_input input;

    if (!parse(&input, data, ndata)) {
        return;
    }
    /* sign */
    memset(msg, 0, 32);
    if (!secp256k1_musig_single_sign(ctx, &sig, msg, input.seckey_data, nonce_function_fuzz, input.privnonce_data)) {
        return;
    }
    scratch = secp256k1_scratch_space_create(ctx, 4096);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk, input.seckey_data) == 1);
    secp256k1_scalar_set_b32(&seckey, input.seckey_data, NULL);
    secp256k1_scalar_set_b32(&privnonce, input.privnonce_data, NULL);

    /* normal verify */
    check(ctx, 1, &sig, msg, &pk, scratch, &sig, msg, &pk);

    {
        /* alternative sig, pk and msg, prefilled with original data */
        secp256k1_musig_signature sig_alt;
        secp256k1_pubkey pk_alt;
        unsigned char msg_alt[32];
        memcpy(sig_alt.data, sig.data, 64);
        memcpy(pk_alt.data, pk.data, 64);
        memcpy(msg_alt, msg, 32);

        if (input.new_s_type[0] % 2 != 0) {
            /* use new s directly instead of original */
            memcpy(&sig_alt.data[32], input.new_s, 32);
        }

        if (input.new_nonce_type[0] % 4 == 0) {
            /* use x coordinate of new_nonce*G in sig*/
            secp256k1_scalar k_tmp;
            secp256k1_gej rj;
            secp256k1_ge r;
            secp256k1_scalar_set_b32(&k_tmp, input.new_nonce, NULL);
            secp256k1_scalar_add(&k_tmp, &k_tmp, &privnonce);
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k_tmp);
            secp256k1_ge_set_gej(&r, &rj);
            secp256k1_fe_get_b32(&sig_alt.data[0], &r.x);
        }
        if (input.new_nonce_type[0] % 4 == 1) {
            /* use new_nonce as x coordinate in sig */
            memcpy(sig_alt.data, input.new_nonce, 32);
        }
        if ((input.new_nonce_type[0] % 4 == 2) || (input.new_nonce_type[0] % 4 == 3)) {
            /* interpret new_nonce as point and use x coordinate or add to
             * original public nonce and use x coordinate in alt sig*/
            secp256k1_pubkey R;
            secp256k1_ge r;
            if (secp256k1_ec_pubkey_parse(ctx, &R, input.new_nonce, 33)) {
                secp256k1_pubkey_load(ctx, &r, &R);
                if (input.new_nonce_type[0] % 4 == 2) {
                    secp256k1_fe_get_b32(&sig_alt.data[0], &r.x);
                } else {
                    secp256k1_gej rj;
                    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &privnonce);
                    secp256k1_gej_add_ge_var(&rj, &rj, &r, NULL);
                    secp256k1_ge_set_gej(&r, &rj);
                    secp256k1_fe_get_b32(&sig_alt.data[0], &r.x);
                }
            }
        }

        if (input.new_msg_type[0] % 2 != 0) {
            /* use new msg directly instead of original */
            memcpy(msg_alt, input.new_msg, 32);
        }
        if (input.new_x_type[0] % 4 == 0) {
            /* interpret new x as scalar, add it to original seckey and use the resulting pubkey */
            unsigned char buf[32];
            secp256k1_scalar x_tmp;
            secp256k1_scalar_set_b32(&x_tmp, input.new_x, NULL);
            secp256k1_scalar_add(&x_tmp, &x_tmp, &seckey);
            secp256k1_scalar_get_b32(buf, &x_tmp);
            CHECK(secp256k1_ec_pubkey_create(ctx, &pk_alt, buf) == 1);
        }
        if ((input.new_x_type[0] % 4 == 2) || (input.new_x_type[0] % 4 == 3)) {
            /* interpret new x as point and either use it as pubkey or add it to
             * original pubkey */
            secp256k1_pubkey R;
            if (secp256k1_ec_pubkey_parse(ctx, &R, input.new_x, 33)) {
                if (input.new_nonce_type[0] % 4 == 2) {
                    memcpy(pk_alt.data, R.data, 64);
                } else {
                    secp256k1_ge r;
                    secp256k1_gej rj;
                    secp256k1_pubkey_load(ctx, &r, &R);
                    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &seckey);
                    secp256k1_gej_add_ge_var(&rj, &rj, &r, NULL);
                    secp256k1_ge_set_gej(&r, &rj);
                    secp256k1_pubkey_save(&pk_alt, &r);
                }
            }
        }

        /* if any of alternative sig, msg or pk are different to the originals
         * expect verify to fail */
        if (memcmp(&sig.data, &sig_alt.data, 64) != 0
                || memcmp(msg, msg_alt, 32) != 0
                || memcmp(pk.data, pk_alt.data, 64) != 0) {
            check(ctx, 0, &sig_alt, msg_alt, &pk_alt, scratch, &sig, msg, &pk);
        }
    }
    secp256k1_scratch_space_destroy(scratch);
}

int main(void) {
    char *buf;
    size_t nread;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    #define BUFSIZE 256
    buf = malloc(BUFSIZE);
    if ((nread = fread(buf, sizeof(char), BUFSIZE, stdin)) > 0) {
       compare(ctx, buf, nread);
    }

    free(buf);
    secp256k1_context_destroy(ctx);
    return 0;
}
