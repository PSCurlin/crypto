/**
 * @file aes_256_cbc.c
 * @brief Demontration of AES256 ECB encryption.
 * Adapted from:
 * - https://wiki.openssl.org/images/1/17/Evp-symmetric-encrypt.c
 */

#include <openssl/aes.h>
#include "utils.h"

/**
 * @brief Main encryption function.
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) handleErrors();
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
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

    printf("-> Will run AES-256 CBC encryption.\n");
    printf("[*] OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
    printf("[*] Number of iterations: %lu\n", num_trials);

    // 256-bit key
    unsigned char key[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    unsigned char iv[AES_BLOCK_SIZE] = "0123456789012345";
    unsigned char ciphertext[AES_BLOCK_SIZE];

    int plaintext_len = strlen((char *)plaintext);
    int ciphertext_len;

    // Begin encryption
    for (int n = 0; n < num_trials; n++) {
        // Randomize the plaintext
        for (size_t j = 0; j < plaintext_len; ++j) plaintext[j] = rand() % 256;
        ciphertext_len = encrypt(plaintext, plaintext_len, key, iv, ciphertext);
    }

    printf("\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
    printf("\n");

    // Clean up
    fflush(stdout);
    return EXIT_SUCCESS;
}