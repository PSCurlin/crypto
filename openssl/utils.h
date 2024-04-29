/**
 * @file utils.h
 * @brief Miscellaneous utility functions for the OpenSSL examples.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/**
 * @brief Usage message.
 */
void usage(char* argv[]) {
    printf("Usage: %s <num_trials>\n", argv[0]);
    exit(EXIT_FAILURE);
}

/**
 * @brief Error handler for EVP functions.
 */
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

#endif // UTILS_H