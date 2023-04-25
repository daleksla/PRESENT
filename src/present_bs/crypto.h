#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <stdint.h>
#include <string.h>

// Define basic parameters
#define CRYPTO_IN_SIZE  8 // Present has 64-bit blocks
#define CRYPTO_KEY_SIZE 10 // Present has 80-bit key
#define CRYPTO_OUT_SIZE 8 // Present has 64-bit blocks

// Block size in bits
#define CRYPTO_IN_SIZE_BIT (CRYPTO_IN_SIZE * 8) // 64 entries

// Do 32-bit bitslicing
#define BITSLICE_WIDTH 32

// Bitslicing register typedef
typedef uint32_t bs_reg_t;

// The function to test
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE]);

// CRYPTO_IN_SIZE * BITSLICE_WIDTH = 8 * 32 = 256 entries
// our blocksize is 32 and our bitslice register is 32 bits wide
// our plaintext array is made up for uint8ts
// we therefore take 4 uint8s and bit slice them
// per 4 uint8ts, we need 32 * 32-bit vectors, with each bit vector holding a byte
// therefore, if for 4 uint8ts we need (plaintext size / 4) * 32 * 32-bits, ...
// then, for 256-bit plaintext we need 64 * 32 = 2048 32-bitvectors???

#endif
