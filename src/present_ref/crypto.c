#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "crypto.h"

/**
 * @brief Basic-optimised standard implementation of PRESENT cryptographic algorithm
 * @authors Doaa A., Dnyaneshwar S., Salih MSA
 * @note Optimisations performed:
  * #1 Common calculations created into offset variables
    * Less CPU time spent on needless calculations
    * e.g. (i / 4) + (1 * 16) -> off + (1 * 16), (i / 4) + (2 * 16) -> off + (2 * 16)
 */

static const uint8_t sbox[16] = { /* Lookup table for the s-box substitution layer */
	0x0C, 0x05, 0x06, 0x0B, 0x09, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
};

/**
 * @brief get_bit - inlined method to return the i-th bit of the byte s
 * @param const uint8_t s - byte to get bit from
 * @param const uint8_t i - bit position
 * @return uint8_t - sliced bit in an isolated byte
 */
static inline uint8_t get_bit(const uint8_t s, const uint8_t i)
{
	return (s >> (i)) & 0x1; // right-shift and mask
}

/**
 * @brief cpy_bit - inlined method to copy the bit value val into the bit position pos of the byte out
 * @param uint8_t out - pointer to byte to modify
 * @param const uint8_t pos - bit position of `out` to modify
 * @param const uint8_t val - bit values to set
 * @return uint8_t - modified byte
 */
static inline uint8_t cpy_bit(uint8_t out, const uint8_t pos, const uint8_t val)
{
	out &= ~(1 << (pos)); // Clear bit pos in out
	out |= ((val) << (pos)); // Set bit pos in out to val
	return out;
}

/**
 * @brief sbox_layer - applies substitution of each byte of the plaintext (s) using the s-box substitution table
 * @param uint8_t s[CRYPTO_IN_SIZE] - data to use SBOX to each element
 */
static void sbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	for (uint8_t i = 0; i < CRYPTO_IN_SIZE; ++i) {
		const uint8_t ln = s[i] & 0xF; // Lower nibble of s[i]
		const uint8_t un = (s[i] >> 4) & 0xF; // Upper nibble of s[i]
		s[i] = sbox[ln] | (sbox[un] << 4); // combine lower and upper nibbles into sbyte
	}
}

/**
 * @brief pbox_layer - rearranges the bytes of the plaintext (s) according to a predefined, fixed permutation
 * @param uint8_t s[CRYPTO_IN_SIZE] - data to use permute
 */
static void pbox_layer(uint8_t s[CRYPTO_IN_SIZE])
{
	uint8_t out[CRYPTO_IN_SIZE];
	for (uint8_t i = 0; i < CRYPTO_IN_SIZE; ++i) { // loop over each byte
		for (uint8_t j = 0; j < 8; ++j) { // loop over each bit of the byte
			const uint8_t tmp = get_bit(s[i], j); // bit at position j is permuted to position, store in state
			const uint8_t com = (i * 8 + j);
			const uint8_t new = (com / 4) + (com % 4) * 16; // compute the permuted position
			out[new / 8] = cpy_bit(out[new / 8], new % 8, tmp); // writeout
		}
	}

	memcpy(s, out, CRYPTO_IN_SIZE); // Copy rearranged bytes back to plaintext s
}

/**
 * @brief add_round_key - performs the XOR operation between the plaintext (pt) and round key (roundkey) byte-by-byte
 * @param uint8_t pt[CRYPTO_IN_SIZE] - data to apply roundkey TO
 * @param uint8_t roundkey[CRYPTO_IN_SIZE] - roundkey to apply
 */
static void add_round_key(uint8_t pt[CRYPTO_IN_SIZE], uint8_t roundkey[CRYPTO_IN_SIZE])
{
	for (uint8_t i = 0; i < CRYPTO_IN_SIZE; ++i) {
		pt[i] ^= roundkey[i]; // apply roundkey to each element using XOR
	}
}

/**
 * @brief update_round_key - updates the round key (key) for the next round by rotating it right by 19 bits, performing an s-box substitution on the MSbits, and XORing it with the round counter r
 * @param uint8_t key{CRYPTO_KEY_SIZE] - key to update
 * @param const uint8_t r - round counter
 */
static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	//
	// There is no need to edit this code
	//
	uint8_t tmp = 0;
	const uint8_t tmp2 = key[2];
	const uint8_t tmp1 = key[1];
	const uint8_t tmp0 = key[0];

	// rotate right by 19 bit
	key[0] = key[2] >> 3 | key[3] << 5;
	key[1] = key[3] >> 3 | key[4] << 5;
	key[2] = key[4] >> 3 | key[5] << 5;
	key[3] = key[5] >> 3 | key[6] << 5;
	key[4] = key[6] >> 3 | key[7] << 5;
	key[5] = key[7] >> 3 | key[8] << 5;
	key[6] = key[8] >> 3 | key[9] << 5;
	key[7] = key[9] >> 3 | tmp0 << 5;
	key[8] = tmp0 >> 3 | tmp1 << 5;
	key[9] = tmp1 >> 3 | tmp2 << 5;

	// perform sbox lookup on MSbits
	tmp = sbox[key[9] >> 4];
	key[9] &= 0x0F;
	key[9] |= tmp << 4;

	// XOR round counter k19 ... k15
	key[1] ^= r << 7;
	key[2] ^= r >> 1;
}

/**
 * @brief crypto_func - function to actually perform cryptography
 * @note Serves as API for those including "crypto.h". All other methods are bound to this file only
 * @param uint8_t pt[CRYPTO_IN_SIZE] - data to encrypt
 * @param uint8_t key[CRYPTO_KEY_SIZE] - key to apply
 */
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE], uint8_t key[CRYPTO_KEY_SIZE])
{
	for (uint8_t i = 1; i <= 31; ++i) {
		add_round_key(pt, key + 2);
		sbox_layer(pt);
		pbox_layer(pt);
		update_round_key(key, i);
	}
	add_round_key(pt, key + 2);
}
