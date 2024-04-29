/**
 * @file sha3_224.c
 * @brief Demontration of SHA3-224 hashing.
 */

#include <openssl/sha.h>
#include "utils.h"

/**
 * @brief Main encryption function.
 */
void hash(const char *msg, unsigned char digest[SHA224_DIGEST_LENGTH]) {
    EVP_MD_CTX *ctx;

    if((ctx = EVP_MD_CTX_new()) == NULL) handleErrors();

    if(1 != EVP_DigestInit_ex(ctx, EVP_sha3_224(), NULL)) handleErrors();
    if(1 != EVP_DigestUpdate(ctx, msg, strlen(msg))) handleErrors();
    if(1 != EVP_DigestFinal_ex(ctx, digest, NULL)) handleErrors();
    EVP_MD_CTX_free(ctx);
    
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

    printf("-> Will run SHA3-224 hashing.\n");
    printf("[*] OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
    printf("[*] Number of iterations: %lu\n", num_trials);

    unsigned char msg[] = "The quick brown fox jumps over the lazy dog";
    unsigned char digest[SHA256_DIGEST_LENGTH];

    // Begin encryption
    for (int n = 0; n < num_trials; n++) {
        // Randomize the message
        for (size_t j = 0; j < strlen((char *) msg); j++) msg[j] = rand() % 256;
        hash((const char *) msg, digest);
    }

    printf("\n");
    BIO_dump_fp(stdout, (const char *)digest, SHA224_DIGEST_LENGTH);
    printf("\n");

    // Clean up
    fflush(stdout);
    return EXIT_SUCCESS;
}