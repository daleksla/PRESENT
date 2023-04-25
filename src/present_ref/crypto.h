#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <stdint.h>
#include <string.h>

// Define basic parameters
#define CRYPTO_IN_SIZE  8 	// Present has 64-bit blocks
#define CRYPTO_KEY_SIZE 10  // Present has 80-bit key
#define CRYPTO_OUT_SIZE 8   // Present has 64-bit blocks

// The function to test
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE], uint8_t key[CRYPTO_KEY_SIZE]);

#endif
