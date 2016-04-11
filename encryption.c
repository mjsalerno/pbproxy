#include "encryption.h"

AES_KEY key;

int bytes_read, bytes_written;
unsigned char indata[AES_BLOCK_SIZE];
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char in_iv[AES_BLOCK_SIZE];
unsigned char out_iv[AES_BLOCK_SIZE];
struct ctr_state in_state;
struct ctr_state out_state;

void init_ctr(struct ctr_state *state, const unsigned char iv[16]) {
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the*/

    /* first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

void init_out(const unsigned char *enc_key) {

    if (!RAND_bytes(out_iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Could not create random bytes.");
        exit(1);
    }

    // Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.");
        exit(1);
    }

    init_ctr(&out_state, out_iv); // Counter call
}

void init_in(const unsigned char *enc_key, const unsigned char iv[16]) {

    // Initializing the encryption KEY
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        fprintf(stderr, "Could not set encryption key.");
        exit(1);
    }

    init_ctr(&in_state, iv); // Counter call
}

void send_iv(int fd) { write(fd, out_state.ivec, 8); }
void print_ctr(struct ctr_state ctr) {
    printf("====================\n");
    printf("ivec: %u %u %u %u %u\n", ctr.ivec[0], ctr.ivec[1], ctr.ivec[2], ctr.ivec[3], ctr.ivec[4]);
    printf("ecount: %u %u %u %u %u\n", ctr.ecount[0], ctr.ecount[1], ctr.ecount[2], ctr.ecount[3], ctr.ecount[4]);
    printf("num: %u\n", ctr.num);
    printf("====================\n");
}

void fencrypt(void *dest, const void *src, size_t n) {
    // print_ctr(out_state);
    AES_ctr128_encrypt(src, dest, n, &key, out_state.ivec, out_state.ecount, &out_state.num);
}

void fdecrypt(void *dest, const void *src, size_t n) {
    // print_ctr(in_state);
    AES_ctr128_encrypt(src, dest, n, &key, in_state.ivec, in_state.ecount, &in_state.num);
}
