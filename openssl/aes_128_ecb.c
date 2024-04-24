/**
 * @file aes_128_ecb.c
 * @brief Demontration of AES128 ECB encryption.
 */

// ============================================================================
// Includes
// ============================================================================
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <string.h>

// ============================================================================
// Defines
// ============================================================================
/**
 * @brief The number of iterations.
 */
#define NUM_ITERATIONS (20*1000) // !! CHANGEME !!

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
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) handleErrors();
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
int main(void) {

    printf("-> Will run AES-128 ECB encryption.\n");
    printf("[*] OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
    printf("[*] Number of iterations: %u\n", NUM_ITERATIONS);

    unsigned char key[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    unsigned char ciphertext[AES_BLOCK_SIZE];

    int ciphertext_len;

    // Begin encryption
    for (int n = 0; n < NUM_ITERATIONS; n++) {
        // Randomize the plaintext
        for (size_t j = 0; j < strlen((char *) plaintext); ++j) plaintext[j] = rand() % 256;
        ciphertext_len = encrypt(plaintext, strlen((char *) plaintext), key, ciphertext);
    }

    printf("\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
    printf("\n");

    // Clean up
    fflush(stdout);
    return EXIT_SUCCESS;
}