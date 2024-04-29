/**
 * @file rsa.c
 * @brief Demontration of RSA encryption.
 */

#include <openssl/rsa.h>
#include "utils.h"

/**
 * @brief Main encryption function.
 */
int encrypt(EVP_PKEY *pubkey, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_PKEY_CTX *ctx;
    size_t outlen = EVP_PKEY_size(pubkey);

    if(!(ctx = EVP_PKEY_CTX_new(pubkey, NULL))) handleErrors();
    if(1 != EVP_PKEY_encrypt_init(ctx)) handleErrors();
    if(1 != EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, plaintext_len)) handleErrors();

    EVP_PKEY_CTX_free(ctx);

    return outlen;
}

/**!
 * @brief Main function.
 */
int main(int argc, char** argv) {

    size_t num_trials;
    if (argc > 1) {
        num_trials = atoi(argv[1]); // The number of trials to run the experiment for
    }
    else {
        usage(argv);
    }

    printf("-> Will run RSA encryption.\n");
    printf("[*] OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
    printf("[*] Number of iterations: %lu\n", num_trials);

    // Initialize key
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey = NULL;
    if(!(pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) handleErrors();
    if(1 != EVP_PKEY_keygen_init(pkey_ctx)) handleErrors();
    if(1 != EVP_PKEY_keygen(pkey_ctx, &pkey)) handleErrors();

    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    unsigned char ciphertext[4096];

    int plaintext_len = strlen((char *)plaintext);
    int ciphertext_len;

    // Begin encryption
    for (int n = 0; n < num_trials; n++) {
        for (size_t j = 0; j < ciphertext_len; ++j) plaintext[j] = rand() % 256;
        ciphertext_len = encrypt(pkey, plaintext, plaintext_len, ciphertext);
    }

    printf("\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
    printf("\n");

    // Clean up
    fflush(stdout);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pkey_ctx);
    return EXIT_SUCCESS;
}