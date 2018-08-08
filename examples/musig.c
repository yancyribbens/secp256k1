#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_musig.h>

typedef struct {
    size_t idx;
    unsigned char seckey[32];
    secp256k1_musig_secret_key musig_seckey;
    secp256k1_pubkey pubkey;
    secp256k1_pubkey *pubkey_other;
    secp256k1_pubkey combined_pk;
    /* some of these names are confusing */
    unsigned char secnon[32];
    secp256k1_pubkey pubnon;
    unsigned char noncommit[32];
    secp256k1_musig_signer_data signer_data[2];
    secp256k1_musig_partial_signature partial_sigs[2];
    secp256k1_musig_validation_aux aux;
} signer;

void printn(unsigned char *s, size_t n) {
    int i;
    for(i=0; i< n; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");
}


void print_pubkey(const secp256k1_context* ctx, secp256k1_pubkey *pk) {
    unsigned char pkser[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pkser, &len, pk, SECP256K1_EC_COMPRESSED);
    printn(pkser, 33);
}

void print_signer(const secp256k1_context* ctx, signer* s) {
    printf("signer %d\n", s->idx);
    printn(s->seckey, 32);
    print_pubkey(ctx, &s->pubkey);
    print_pubkey(ctx, s->pubkey_other);
    print_pubkey(ctx, &s->combined_pk);
    printn(s->secnon, 32);
    print_pubkey(ctx, &s->pubnon);
    printn(s->noncommit, 32);
}

int get_randomness(unsigned char* rand32) {
    FILE *frand = fopen("/dev/urandom", "r");
    if (frand == NULL || !fread(rand32, 32, 1, frand)) {
        return 0;
    }
    return 1;
}

/* Create a key pair and store it in seckey and pubkey */
int create_key(const secp256k1_context* ctx, unsigned char* seckey, secp256k1_pubkey* pubkey) {
    int ret;
    FILE *frand = fopen("/dev/urandom", "r");
    do {
        if (!get_randomness(seckey)) {
            return 0;
        }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
     ret = secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
    assert(ret);
    fclose(frand);
    return 1;
}

void combine(const secp256k1_context* ctx, signer* s) {
    secp256k1_pubkey pks[2];
    /* 0 for 0, 1 for 1 */
    memcpy(pks[s->idx].data, &s->pubkey.data, 64);
    /* 1 for 0, 0 for 1 */
    memcpy(pks[s->idx ^ 1].data, s->pubkey_other->data, 64);

    assert(secp256k1_musig_tweak_secret_key(ctx, &s->musig_seckey, s->seckey, pks, 2, s->idx));
    assert(secp256k1_musig_pubkey_combine(ctx, NULL, &s->combined_pk, pks, 2));
}

/* TODO: api problem, how do you prevent nonce reuse?!? */
void generate_nonce(const secp256k1_context* ctx, signer* s, unsigned char* msg32) {
    unsigned char rngseed[32];
    /* WARNING: new nonce *must* be drawn when signing fails! */
    get_randomness(rngseed);
    assert(secp256k1_musig_multisig_generate_nonce(ctx, s->secnon, &s->pubnon, s->noncommit, &s->musig_seckey, msg32, rngseed));
    assert(secp256k1_musig_signer_data_initialize(ctx, &s->signer_data[s->idx], &s->pubkey, s->noncommit));
    assert(secp256k1_musig_set_nonce(ctx, &s->signer_data[s->idx], &s->pubnon));
}

void init_signer(const secp256k1_context* ctx, signer* s, unsigned char* noncommit) {
    assert(secp256k1_musig_signer_data_initialize(ctx, &s->signer_data[s->idx ^ 1], s->pubkey_other, noncommit));
}

void set_nonce(const secp256k1_context* ctx, signer* s, secp256k1_pubkey* pubnon, size_t idx) {
    assert(secp256k1_musig_set_nonce(ctx, &s->signer_data[idx], pubnon));
}

void sign(const secp256k1_context* ctx, signer* s, secp256k1_scratch_space *scratch, unsigned char* msg32) {
    assert(secp256k1_musig_partial_sign(ctx, scratch, &s->partial_sigs[s->idx], &s->aux, &s->musig_seckey, &s->combined_pk, msg32, s->secnon, s->signer_data, 2, s->idx, NULL));
}

void combine_sigs(const secp256k1_context* ctx, signer* s, unsigned char* msg32) {
    secp256k1_musig_signature sig;
    assert(secp256k1_musig_partial_sig_combine(ctx, &sig, s->partial_sigs, 2, s->signer_data, 2, &s->aux, NULL));

    assert(secp256k1_musig_verify_1(ctx, &sig, msg32, &s->combined_pk));
}

int main(void) {
    secp256k1_context* ctx;
    signer signers[2];
    unsigned char msg32[32] = "this_should_actually_be_msg_hash";
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* setup */
    signers[0].idx = 0; signers[1].idx = 1;
    assert(create_key(ctx, signers[0].seckey, &signers[0].pubkey));
    signers[1].pubkey_other = &signers[0].pubkey;
    assert(create_key(ctx, signers[1].seckey, &signers[1].pubkey));
    signers[0].pubkey_other = &signers[1].pubkey;

    combine(ctx, &signers[0]);
    combine(ctx, &signers[1]);


    generate_nonce(ctx, &signers[0], msg32);
    generate_nonce(ctx, &signers[1], msg32);

    /* Communication round: exchange nonce commitments */
    init_signer(ctx, &signers[0], signers[1].noncommit);
    init_signer(ctx, &signers[1], signers[0].noncommit);

    /* Communication round: exchange nonces */
    set_nonce(ctx, &signers[0], &signers[1].pubnon, 1);
    set_nonce(ctx, &signers[1], &signers[0].pubnon, 0);

    /* TODO: explain scratch size */
    /* Create "scratch space" to allocate memory for the aggsig verification
     * algorithm. But first, compute the optimal size of the space. */
    /*size_t scratch_size = secp256k1_aggsig_verify_scratch_size(N_PUBKEYS);*/
    size_t scratch_size = 10000;
    secp256k1_scratch_space* scratch;
    /* The scratch space can be limited or set to a fixed size. If it's smaller
     * than the optimum, then the verification algorithm will run slower. But
     * the scratch space must fit at least one public key. */
    if (scratch_size > 9000) {
        scratch_size = 9000;
    }
    scratch = secp256k1_scratch_space_create(ctx, scratch_size);
    if (scratch == NULL) {
        return 0;
    }

    sign(ctx, &signers[0], scratch, msg32);
    sign(ctx, &signers[1], scratch, msg32);
    /* another round of communication */
    signers[1].partial_sigs[0] = signers[0].partial_sigs[0];
    signers[0].partial_sigs[1] = signers[1].partial_sigs[1];

    print_signer(ctx, &signers[0]);
    print_signer(ctx, &signers[1]);
    combine_sigs(ctx, &signers[0], msg32);
    combine_sigs(ctx, &signers[1], msg32);

    secp256k1_context_destroy(ctx);
    secp256k1_scratch_space_destroy(scratch);

    return 0;
}
