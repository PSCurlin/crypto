/**
 * @file sha256.c
 * @brief Demontration of SHA256 hashing.
 */

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

// ============================================================================
// Defines
// ============================================================================
/**
 * @brief The number of iterations.
 */
#define NUM_ITERATIONS (20*1000)

// ============================================================================
// Prototypes
// ============================================================================
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext);

// ============================================================================
// Functions
// ============================================================================
/**
 * @brief Error handler for EVP functions.
 */
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * @brief Main encryption function.
 */
void hash(const char *msg, unsigned char digest[SHA256_DIGEST_LENGTH]) {
    EVP_MD_CTX *ctx;

    if((ctx = EVP_MD_CTX_new()) == NULL) handleErrors();

    if(1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) handleErrors();
    if(1 != EVP_DigestUpdate(ctx, msg, strlen(msg))) handleErrors();
    if(1 != EVP_DigestFinal_ex(ctx, digest, NULL)) handleErrors();
    EVP_MD_CTX_free(ctx);
    
}
 
/**!
 * @brief Main function.
 */
int main(void) {

    printf("-> Will run SHA256 hashing.\n");
    printf("[*] OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
    printf("[*] Number of iterations: %u\n", NUM_ITERATIONS);

    unsigned char msg[] = "The quick brown fox jumps over the lazy dog";
    unsigned char digest[SHA256_DIGEST_LENGTH];

    // Begin encryption
    for (int n = 0; n < NUM_ITERATIONS; n++) {
        // Randomize the message
        for (size_t j = 0; j < strlen((char *) msg); j++) msg[j] = rand() % 256;
        hash((const char *) msg, digest);
    }

    printf("\n");
    BIO_dump_fp(stdout, (const char *)digest, SHA256_DIGEST_LENGTH);
    printf("\n");

    // Clean up
    fflush(stdout);
    return EXIT_SUCCESS;
}