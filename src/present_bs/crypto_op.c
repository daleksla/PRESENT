#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"

/**
 * @brief Optimised bitsliced implementation of PRESENT cryptographic algorithm
 *
 * @authors Doaa A., Dnyaneshwar S., Salih MSA
 *
 * @note Optimisations performed:
  * #1 x ^ 0xffffffff -> ~(x)
    * `eor` requires use of 3 sources - dest reg, val1 reg, val2 flexible
    * `mvn` (bitwise not) just needs two - dest reg, val1 reg
    * both theoretically and on a machine-code basis, it should be quicker
  * #2 Common calculations created into offset variables
    * Less CPU time spent on needless calculations
    * e.g. (i / 4) + (1 * 16) -> off + (1 * 16), (i / 4) + (2 * 16) -> off + (2 * 16)
  * #3 Minimising RAM interaction
    * Not using tmp variables allows compiler to better optimise keeping values in registers and not RAM, even if it makes the code look untidy / unnclean
    * const [] -> static const T[], when declarted within functions, where static variables means it's globalised (i.e. all instances of the function have access to it) - cost is persistent memory use (in .data) but improves performance by reducing initialisation time to only once (when function is first called)
  * #4 Manual reduction of constant integer expression
    * Compiler might not reduce an expression when it's too complex to it - do it yourself to improve performance
    * e.g. 16 * 0 -> n/a, 16 * 1 -> 16, ...
  * #5 Unrolling loops
    * Takes more memory in the form of instructions but no jumping, condition evaluating, calculating offset values per loop, etc.
    * Did this completely for pbox & sbox layers
    * The enslice and unslice functions would be far too large for both of their loops though (attempted to and I was reaching 5000+ lines of code) - instead I unrolled the inner loop which goes over each bit of each byte of data and writes it to a new element
 */

/**
 * @brief get_reg_bit - inlined method to return the i-th bit of the byte s
 * @note Very similar to get_bs_bit but it's inlined so won't be function wasting memory
 * @param const uint8_t s - byte to get bit from
 * @param const uint8_t i - bit position
 * @return uint8_t - bit in an isolated byte
 */
static inline uint8_t get_reg_bit(const uint8_t s, const uint8_t i)
{
	return (s >> (i)) & 0x1; // right-shift and mask
}

/**
 * @brief get_bs_bit - inlined method to return the i-th bit of the byte s
 * @note Very similar to get_bs_bit but it's inlined so won't be function wasting memory
 * @param const bs_reg_t s - slice to get bit from
 * @param const uint8_t i - bit position
 * @return uint8_t - bit in isolated slice
 */
static inline uint8_t get_bs_bit(const bs_reg_t s, const uint8_t i)
{
	return (s >> (i)) & 0x1; // right-shift and mask
}

///**
// * @brief cpy_reg_bit - inlined method to copy the bit value val into the bit position pos of the byte out
// * @param const uint8_t out - pointer to byte to modify
// * @param const uint8_t pos - bit position of `out` to modify
// * @param const uint8_t val - bit values to set
// * @return uint8_t - modified byte
// */
//static inline uint8_t cpy_reg_bit(const uint8_t out, const uint8_t pos, const uint8_t val)
//{
//	return (out & ~(1 << (pos))) | ((val) << (pos)); // Clear bit pos in out and set bit pos in out to val
//}
//
///**
// * @brief cpy_bs_bit - inlined method to copy the bit value val into the bit position pos of the uint32_t out
// * @param const bs_reg_t out - pointer to value to modify
// * @param const uint8_t pos - bit position of `out` to modify
// * @param const bs_reg_t val - bit values to set
// * @return bs_reg_t - modified value
// */
//static inline bs_reg_t cpy_bs_bit(const bs_reg_t out, const uint8_t pos, const bs_reg_t val)
//{
//	return (out & ~(1 << (pos))) | ((val) << (pos)); // Clear bit pos in out and set bit pos in out to val
//}

/**
 * @brief cpy_reg_bit - inlined method to copy the bit value val into the bit position pos of the byte out
 * @param uint8_t out - pointer to byte to modify
 * @param const uint8_t pos - bit position of `out` to modify
 * @param const uint8_t val - bit values to set
 * @return uint8_t - modified byte
 */
static inline uint8_t cpy_reg_bit(uint8_t out, const uint8_t pos, const uint8_t val)
{
	out &= ~(1 << (pos)); // Clear bit pos in out
	out |= ((val) << (pos)); // Set bit pos in out to val
	return out;
}

/**
 * @brief cpy_bs_bit - inlined method to copy the bit value val into the bit position pos of the uint32_t out
 * @param uint8_t out - pointer to byte to modify
 * @param const uint8_t pos - bit position of `out` to modify
 * @param const bs_reg_t val - bit values to set
 * @return bs_reg_t - modified value
 */
static inline bs_reg_t cpy_bs_bit(bs_reg_t out, const uint8_t pos, const bs_reg_t val)
{
	out &= ~(1 << (pos)); // Clear bit pos in out
	out |= ((val) << (pos)); // Set bit pos in out to val
	return out;
}

/**
 * @brief enslice - brings normal byte uint8_t form into into bitsliced uint32_t buffer representation
 * @param const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH] - input normal state
 * @param bs_reg_t pt[CRYPTO_IN_SIZE_BIT] state_bs - output bitsliced state
 */
static void enslice(const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	const uint8_t *ptr = pt; // initialise read only ptr for pt array

	for (uint32_t i = 0; i < BITSLICE_WIDTH; ++i) {
		// j = 0
		state_bs[0] = cpy_bs_bit(state_bs[0], i, (bs_reg_t)get_reg_bit(*ptr, 0)); // get bit from byte indicated by ptr (our plaintext) and set bit of bitsliced array, as specified by 2nd arg, which serves as our bitoffset

		// j = 1
		state_bs[1] = cpy_bs_bit(state_bs[1], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 2
		state_bs[2] = cpy_bs_bit(state_bs[2], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 3
		state_bs[3] = cpy_bs_bit(state_bs[3], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 4
		state_bs[4] = cpy_bs_bit(state_bs[4], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 5
		state_bs[5] = cpy_bs_bit(state_bs[5], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 6
		state_bs[6] = cpy_bs_bit(state_bs[6], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 7
		state_bs[7] = cpy_bs_bit(state_bs[7], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;

		// j = 8
		state_bs[8] = cpy_bs_bit(state_bs[8], i, (bs_reg_t)get_reg_bit(*ptr, 0));

		// j = 9
		state_bs[9] = cpy_bs_bit(state_bs[9], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 10
		state_bs[10] = cpy_bs_bit(state_bs[10], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 11
		state_bs[11] = cpy_bs_bit(state_bs[11], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 12
		state_bs[12] = cpy_bs_bit(state_bs[12], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 13
		state_bs[13] = cpy_bs_bit(state_bs[13], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 14
		state_bs[14] = cpy_bs_bit(state_bs[14], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 15
		state_bs[15] = cpy_bs_bit(state_bs[15], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;

		// j = 16
		state_bs[16] = cpy_bs_bit(state_bs[16], i, (bs_reg_t)get_reg_bit(*ptr, 0));

		// j = 17
		state_bs[17] = cpy_bs_bit(state_bs[17], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 18
		state_bs[18] = cpy_bs_bit(state_bs[18], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 19
		state_bs[19] = cpy_bs_bit(state_bs[19], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 20
		state_bs[20] = cpy_bs_bit(state_bs[20], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 21
		state_bs[21] = cpy_bs_bit(state_bs[21], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 22
		state_bs[22] = cpy_bs_bit(state_bs[22], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 23
		state_bs[23] = cpy_bs_bit(state_bs[23], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;

		// j = 24
		state_bs[24] = cpy_bs_bit(state_bs[24], i, (bs_reg_t)get_reg_bit(*ptr, 0));

		// j = 25
		state_bs[25] = cpy_bs_bit(state_bs[25], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 26
		state_bs[26] = cpy_bs_bit(state_bs[26], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 27
		state_bs[27] = cpy_bs_bit(state_bs[27], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 28
		state_bs[28] = cpy_bs_bit(state_bs[28], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 29
		state_bs[29] = cpy_bs_bit(state_bs[29], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 30
		state_bs[30] = cpy_bs_bit(state_bs[30], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 31
		state_bs[31] = cpy_bs_bit(state_bs[31], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;

		// j = 32
		state_bs[32] = cpy_bs_bit(state_bs[32], i, (bs_reg_t)get_reg_bit(*ptr, 0));

		// j = 33
		state_bs[33] = cpy_bs_bit(state_bs[33], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 34
		state_bs[34] = cpy_bs_bit(state_bs[34], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 35
		state_bs[35] = cpy_bs_bit(state_bs[35], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 36
		state_bs[36] = cpy_bs_bit(state_bs[36], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 37
		state_bs[37] = cpy_bs_bit(state_bs[37], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 38
		state_bs[38] = cpy_bs_bit(state_bs[38], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 39
		state_bs[39] = cpy_bs_bit(state_bs[39], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;

		// j = 40
		state_bs[40] = cpy_bs_bit(state_bs[40], i, (bs_reg_t)get_reg_bit(*ptr, 0));

		// j = 41
		state_bs[41] = cpy_bs_bit(state_bs[41], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 42
		state_bs[42] = cpy_bs_bit(state_bs[42], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 43
		state_bs[43] = cpy_bs_bit(state_bs[43], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 44
		state_bs[44] = cpy_bs_bit(state_bs[44], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 45
		state_bs[45] = cpy_bs_bit(state_bs[45], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 46
		state_bs[46] = cpy_bs_bit(state_bs[46], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 47
		state_bs[47] = cpy_bs_bit(state_bs[47], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;

		// j = 48
		state_bs[48] = cpy_bs_bit(state_bs[48], i, (bs_reg_t)get_reg_bit(*ptr, 0));

		// j = 49
		state_bs[49] = cpy_bs_bit(state_bs[49], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 50
		state_bs[50] = cpy_bs_bit(state_bs[50], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 51
		state_bs[51] = cpy_bs_bit(state_bs[51], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 52
		state_bs[52] = cpy_bs_bit(state_bs[52], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 53
		state_bs[53] = cpy_bs_bit(state_bs[53], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 54
		state_bs[54] = cpy_bs_bit(state_bs[54], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 55
		state_bs[55] = cpy_bs_bit(state_bs[55], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;

		// j = 56
		state_bs[56] = cpy_bs_bit(state_bs[56], i, (bs_reg_t)get_reg_bit(*ptr, 0));

		// j = 57
		state_bs[57] = cpy_bs_bit(state_bs[57], i, (bs_reg_t)get_reg_bit(*ptr, 1));

		// j = 58
		state_bs[58] = cpy_bs_bit(state_bs[58], i, (bs_reg_t)get_reg_bit(*ptr, 2));

		// j = 59
		state_bs[59] = cpy_bs_bit(state_bs[59], i, (bs_reg_t)get_reg_bit(*ptr, 3));

		// j = 60
		state_bs[60] = cpy_bs_bit(state_bs[60], i, (bs_reg_t)get_reg_bit(*ptr, 4));

		// j = 61
		state_bs[61] = cpy_bs_bit(state_bs[61], i, (bs_reg_t)get_reg_bit(*ptr, 5));

		// j = 62
		state_bs[62] = cpy_bs_bit(state_bs[62], i, (bs_reg_t)get_reg_bit(*ptr, 6));

		// j = 63
		state_bs[63] = cpy_bs_bit(state_bs[63], i, (bs_reg_t)get_reg_bit(*ptr, 7));
		++ptr;
	}
}

/**
 * @brief unslice - brings bitsliced uint32_t buffer into normal byte uint8_t form
 * @param const bs_reg_t pt[CRYPTO_IN_SIZE_BIT] state_bs - input bitsliced state
 * @param uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH] - output normal state
 */
static void unslice(const bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH])
{
	uint8_t *ptr = pt; // initialise write only ptr for pt array

	for (uint32_t i = 0; i < BITSLICE_WIDTH; ++i) {
		// j = 0
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[0], i));  // get bit from byte indicated by bitsliced array & set bit from byte indicated by ptr array

		// j = 1
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[1], i));

		// j = 2
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[2], i));

		// j = 3
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[3], i));

		// j = 4
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[4], i));

		// j = 5
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[5], i));

		// j = 6
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[6], i));

		// j = 7
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[7], i));
		++ptr;

		// j = 8
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[8], i));

		// j = 9
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[9], i));

		// j = 10
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[10], i));

		// j = 11
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[11], i));

		// j = 12
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[12], i));

		// j = 13
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[13], i));

		// j = 14
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[14], i));

		// j = 15
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[15], i));
		++ptr;

		// j = 16
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[16], i));

		// j = 17
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[17], i));

		// j = 18
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[18], i));

		// j = 19
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[19], i));

		// j = 20
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[20], i));

		// j = 21
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[21], i));

		// j = 22
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[22], i));

		// j = 23
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[23], i));
		++ptr;

		// j = 24
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[24], i));

		// j = 25
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[25], i));

		// j = 26
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[26], i));

		// j = 27
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[27], i));

		// j = 28
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[28], i));

		// j = 29
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[29], i));

		// j = 30
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[30], i));

		// j = 31
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[31], i));
		++ptr;

		// j = 32
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[32], i));

		// j = 33
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[33], i));

		// j = 34
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[34], i));

		// j = 35
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[35], i));

		// j = 36
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[36], i));

		// j = 37
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[37], i));

		// j = 38
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[38], i));

		// j = 39
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[39], i));
		++ptr;

		// j = 40
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[40], i));

		// j = 41
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[41], i));

		// j = 42
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[42], i));

		// j = 43
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[43], i));

		// j = 44
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[44], i));

		// j = 45
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[45], i));

		// j = 46
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[46], i));

		// j = 47
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[47], i));
		++ptr;

		// j = 48
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[48], i));

		// j = 49
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[49], i));

		// j = 50
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[50], i));

		// j = 51
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[51], i));

		// j = 52
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[52], i));

		// j = 53
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[53], i));

		// j = 54
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[54], i));

		// j = 55
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[55], i));
		++ptr;

		// j = 56
		*ptr = cpy_reg_bit(*ptr, 0, (uint8_t)get_bs_bit(state_bs[56], i));

		// j = 57
		*ptr = cpy_reg_bit(*ptr, 1, (uint8_t)get_bs_bit(state_bs[57], i));

		// j = 58
		*ptr = cpy_reg_bit(*ptr, 2, (uint8_t)get_bs_bit(state_bs[58], i));

		// j = 59
		*ptr = cpy_reg_bit(*ptr, 3, (uint8_t)get_bs_bit(state_bs[59], i));

		// j = 60
		*ptr = cpy_reg_bit(*ptr, 4, (uint8_t)get_bs_bit(state_bs[60], i));

		// j = 61
		*ptr = cpy_reg_bit(*ptr, 5, (uint8_t)get_bs_bit(state_bs[61], i));

		// j = 62
		*ptr = cpy_reg_bit(*ptr, 6, (uint8_t)get_bs_bit(state_bs[62], i));

		// j = 63
		*ptr = cpy_reg_bit(*ptr, 7, (uint8_t)get_bs_bit(state_bs[63], i));
		++ptr;
	}
}


/**
 * @brief add_round_key - performs the XOR operation between the plaintext (pt) and round key (roundkey) byte-by-byte
 * @param uint8_t pt[CRYPTO_IN_SIZE] - data to apply roundkey TO
 * @param uint8_t roundkey[CRYPTO_IN_SIZE] - roundkey to apply
 */
static void add_round_key(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t roundkey[CRYPTO_IN_SIZE])
{
	static const bs_reg_t bit_array[2] = {0x00000000, 0xFFFFFFFF};

	state_bs[0] ^= bit_array[get_reg_bit(roundkey[0], 0)]; // get current bit of current byte from roundkey, since bit is either 0 or 1, index `bit_array`
	state_bs[1] ^= bit_array[get_reg_bit(roundkey[0], 1)];
	state_bs[2] ^= bit_array[get_reg_bit(roundkey[0], 2)];
	state_bs[3] ^= bit_array[get_reg_bit(roundkey[0], 3)];
	state_bs[4] ^= bit_array[get_reg_bit(roundkey[0], 4)];
	state_bs[5] ^= bit_array[get_reg_bit(roundkey[0], 5)];
	state_bs[6] ^= bit_array[get_reg_bit(roundkey[0], 6)];
	state_bs[7] ^= bit_array[get_reg_bit(roundkey[0], 7)];

	state_bs[8] ^= bit_array[get_reg_bit(roundkey[1], 0)];
	state_bs[9] ^= bit_array[get_reg_bit(roundkey[1], 1)];
	state_bs[10] ^= bit_array[get_reg_bit(roundkey[1], 2)];
	state_bs[11] ^= bit_array[get_reg_bit(roundkey[1], 3)];
	state_bs[12] ^= bit_array[get_reg_bit(roundkey[1], 4)];
	state_bs[13] ^= bit_array[get_reg_bit(roundkey[1], 5)];
	state_bs[14] ^= bit_array[get_reg_bit(roundkey[1], 6)];
	state_bs[15] ^= bit_array[get_reg_bit(roundkey[1], 7)];

	state_bs[16] ^= bit_array[get_reg_bit(roundkey[2], 0)];
	state_bs[17] ^= bit_array[get_reg_bit(roundkey[2], 1)];
	state_bs[18] ^= bit_array[get_reg_bit(roundkey[2], 2)];
	state_bs[19] ^= bit_array[get_reg_bit(roundkey[2], 3)];
	state_bs[20] ^= bit_array[get_reg_bit(roundkey[2], 4)];
	state_bs[21] ^= bit_array[get_reg_bit(roundkey[2], 5)];
	state_bs[22] ^= bit_array[get_reg_bit(roundkey[2], 6)];
	state_bs[23] ^= bit_array[get_reg_bit(roundkey[2], 7)];

	state_bs[24] ^= bit_array[get_reg_bit(roundkey[3], 0)];
	state_bs[25] ^= bit_array[get_reg_bit(roundkey[3], 1)];
	state_bs[26] ^= bit_array[get_reg_bit(roundkey[3], 2)];
	state_bs[27] ^= bit_array[get_reg_bit(roundkey[3], 3)];
	state_bs[28] ^= bit_array[get_reg_bit(roundkey[3], 4)];
	state_bs[29] ^= bit_array[get_reg_bit(roundkey[3], 5)];
	state_bs[30] ^= bit_array[get_reg_bit(roundkey[3], 6)];
	state_bs[31] ^= bit_array[get_reg_bit(roundkey[3], 7)];

	state_bs[32] ^= bit_array[get_reg_bit(roundkey[4], 0)];
	state_bs[33] ^= bit_array[get_reg_bit(roundkey[4], 1)];
	state_bs[34] ^= bit_array[get_reg_bit(roundkey[4], 2)];
	state_bs[35] ^= bit_array[get_reg_bit(roundkey[4], 3)];
	state_bs[36] ^= bit_array[get_reg_bit(roundkey[4], 4)];
	state_bs[37] ^= bit_array[get_reg_bit(roundkey[4], 5)];
	state_bs[38] ^= bit_array[get_reg_bit(roundkey[4], 6)];
	state_bs[39] ^= bit_array[get_reg_bit(roundkey[4], 7)];

	state_bs[40] ^= bit_array[get_reg_bit(roundkey[5], 0)];
	state_bs[41] ^= bit_array[get_reg_bit(roundkey[5], 1)];
	state_bs[42] ^= bit_array[get_reg_bit(roundkey[5], 2)];
	state_bs[43] ^= bit_array[get_reg_bit(roundkey[5], 3)];
	state_bs[44] ^= bit_array[get_reg_bit(roundkey[5], 4)];
	state_bs[45] ^= bit_array[get_reg_bit(roundkey[5], 5)];
	state_bs[46] ^= bit_array[get_reg_bit(roundkey[5], 6)];
	state_bs[47] ^= bit_array[get_reg_bit(roundkey[5], 7)];

	state_bs[48] ^= bit_array[get_reg_bit(roundkey[6], 0)];
	state_bs[49] ^= bit_array[get_reg_bit(roundkey[6], 1)];
	state_bs[50] ^= bit_array[get_reg_bit(roundkey[6], 2)];
	state_bs[51] ^= bit_array[get_reg_bit(roundkey[6], 3)];
	state_bs[52] ^= bit_array[get_reg_bit(roundkey[6], 4)];
	state_bs[53] ^= bit_array[get_reg_bit(roundkey[6], 5)];
	state_bs[54] ^= bit_array[get_reg_bit(roundkey[6], 6)];
	state_bs[55] ^= bit_array[get_reg_bit(roundkey[6], 7)];

	state_bs[56] ^= bit_array[get_reg_bit(roundkey[7], 0)];
	state_bs[57] ^= bit_array[get_reg_bit(roundkey[7], 1)];
	state_bs[58] ^= bit_array[get_reg_bit(roundkey[7], 2)];
	state_bs[59] ^= bit_array[get_reg_bit(roundkey[7], 3)];
	state_bs[60] ^= bit_array[get_reg_bit(roundkey[7], 4)];
	state_bs[61] ^= bit_array[get_reg_bit(roundkey[7], 5)];
	state_bs[62] ^= bit_array[get_reg_bit(roundkey[7], 6)];
	state_bs[63] ^= bit_array[get_reg_bit(roundkey[7], 7)];
}

/**
 * @brief update_round_key - perform next key schedule step
 * @param uint8_t key[CRYPTO_KEY_SIZE] - key register to be updated
 * @param const uint8_t r - round counter
 * @warning For correct function, has to be called with incremented r each time
 * @note You are free to change or optimize this function
 */
static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	//
	// There is no need to edit this code - but you can do so if you want to
	// optimise further
	//
	static const uint8_t sbox[16] = { /* Lookup table for the s-box substitution layer */
		0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
	};

	uint8_t tmp = 0;
	const uint8_t tmp0 = key[0];
	const uint8_t tmp1 = key[1];
	const uint8_t tmp2 = key[2];

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
 * @brief sbox0 - first Boolean substitution box
 * @note ^ is XOR, & is AND
 * @param const bs_reg_t x0 - byte 1
 * @param const bs_reg_t x1 - byte 2
 * @param const bs_reg_t x2 - byte 3
 * @param const bs_reg_t x3 - byte 4
 * @return bs_reg_t - result of substitution
 */
static inline bs_reg_t sbox0(const bs_reg_t in0, const bs_reg_t in1, const bs_reg_t in2, const bs_reg_t in3)
{
	return in0 ^ (in1 & in2) ^ in2 ^ in3;
}

/**
 * @brief sbox1 - second Boolean substitution box
 * @note ^ is XOR, & is AND
 * @param const bs_reg_t x0 - byte 1
 * @param const bs_reg_t x1 - byte 2
 * @param const bs_reg_t x2 - byte 3
 * @param const bs_reg_t x3 - byte 4
 * @return bs_reg_t - result of substitution
 */
static inline bs_reg_t sbox1(const bs_reg_t in0, const bs_reg_t in1, const bs_reg_t in2, const bs_reg_t in3)
{
	const bs_reg_t in0in1 = in0 & in1;
	const bs_reg_t in1in3 = in1 & in3;
	const bs_reg_t in2in3 = in2 & in3;

	return (in0in1 & in2) ^ (in0in1 & in3) ^ in1in3 ^ in1 ^ (in0 & in2in3) ^ in2in3 ^ in3;
}

/**
 * @brief sbox2 - third Boolean substitution box
 * @note ^ is XOR, & is AND
 * @param const bs_reg_t x0 - byte 1
 * @param const bs_reg_t x1 - byte 2
 * @param const bs_reg_t x2 - byte 3
 * @param const bs_reg_t x3 - byte 4
 * @return bs_reg_t - result of substitution
 */
static inline bs_reg_t sbox2(const bs_reg_t in0, const bs_reg_t in1, const bs_reg_t in2, const bs_reg_t in3)
{
	const bs_reg_t in0in1 = in0 & in1;
	const bs_reg_t in0in3 = in0 & in3;
	const bs_reg_t in3in1 = in3 & in1;

	return ~((in0in1) ^ (in0in3 & in1) ^ in3in1 ^ in2 ^ in0in3 ^ (in0 & in2 & in3) ^ in3);
}

/**
 * @brief sbox3 - fourth Boolean substitution box
 * @note ^ is XOR, & is AND
 * @param const bs_reg_t x0 - byte 1
 * @param const bs_reg_t x1 - byte 2
 * @param const bs_reg_t x2 - byte 3
 * @param const bs_reg_t x3 - byte 4
 * @return bs_reg_t - result of substitution
 */
static inline bs_reg_t sbox3(const bs_reg_t in0, const bs_reg_t in1, const bs_reg_t in2, const bs_reg_t in3)
{
	const bs_reg_t in1in2 = in1 & in2;
	const bs_reg_t in1in3 = in1 & in3;
	const bs_reg_t in2in3 = in2 & in3;

	return ~(((in1in2 & in0) ^ (in1in3 & in0) ^ (in2in3 & in0) ^ in0 ^ in1 ^ in1in2 ^ in3));
}

/**
 * @brief sbox_layer - applies substitution of contents using the s-box substitution table
 * @param bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT] - data to use SBOX to contents
 */
static void sbox_layer(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	bs_reg_t in0, in1, in2, in3;

	// i = 0
	in0 = state_bs[0];
	in1 = state_bs[1];
	in2 = state_bs[2];
	in3 = state_bs[3];
	state_bs[0] = sbox0(in0, in1, in2, in3);
	state_bs[1] = sbox1(in0, in1, in2, in3);
	state_bs[2] = sbox2(in0, in1, in2, in3);
	state_bs[3] = sbox3(in0, in1, in2, in3);

	// i = 1
	in0 = state_bs[4];
	in1 = state_bs[5];
	in2 = state_bs[6];
	in3 = state_bs[7];
	state_bs[4] = sbox0(in0, in1, in2, in3);
	state_bs[5] = sbox1(in0, in1, in2, in3);
	state_bs[6] = sbox2(in0, in1, in2, in3);
	state_bs[7] = sbox3(in0, in1, in2, in3);

	// i = 2
	in0 = state_bs[8];
	in1 = state_bs[9];
	in2 = state_bs[10];
	in3 = state_bs[11];
	state_bs[8] = sbox0(in0, in1, in2, in3);
	state_bs[9] = sbox1(in0, in1, in2, in3);
	state_bs[10] = sbox2(in0, in1, in2, in3);
	state_bs[11] = sbox3(in0, in1, in2, in3);

	// i = 3
	in0 = state_bs[12];
	in1 = state_bs[13];
	in2 = state_bs[14];
	in3 = state_bs[15];
	state_bs[12] = sbox0(in0, in1, in2, in3);
	state_bs[13] = sbox1(in0, in1, in2, in3);
	state_bs[14] = sbox2(in0, in1, in2, in3);
	state_bs[15] = sbox3(in0, in1, in2, in3);

	// i = 4
	in0 = state_bs[16];
	in1 = state_bs[17];
	in2 = state_bs[18];
	in3 = state_bs[19];
	state_bs[16] = sbox0(in0, in1, in2, in3);
	state_bs[17] = sbox1(in0, in1, in2, in3);
	state_bs[18] = sbox2(in0, in1, in2, in3);
	state_bs[19] = sbox3(in0, in1, in2, in3);

	// i = 5
	in0 = state_bs[20];
	in1 = state_bs[21];
	in2 = state_bs[22];
	in3 = state_bs[23];
	state_bs[20] = sbox0(in0, in1, in2, in3);
	state_bs[21] = sbox1(in0, in1, in2, in3);
	state_bs[22] = sbox2(in0, in1, in2, in3);
	state_bs[23] = sbox3(in0, in1, in2, in3);

	// i = 6
	in0 = state_bs[24];
	in1 = state_bs[25];
	in2 = state_bs[26];
	in3 = state_bs[27];
	state_bs[24] = sbox0(in0, in1, in2, in3);
	state_bs[25] = sbox1(in0, in1, in2, in3);
	state_bs[26] = sbox2(in0, in1, in2, in3);
	state_bs[27] = sbox3(in0, in1, in2, in3);

	// i = 7
	in0 = state_bs[28];
	in1 = state_bs[29];
	in2 = state_bs[30];
	in3 = state_bs[31];
	state_bs[28] = sbox0(in0, in1, in2, in3);
	state_bs[29] = sbox1(in0, in1, in2, in3);
	state_bs[30] = sbox2(in0, in1, in2, in3);
	state_bs[31] = sbox3(in0, in1, in2, in3);

	// i = 8
	in0 = state_bs[32];
	in1 = state_bs[33];
	in2 = state_bs[34];
	in3 = state_bs[35];
	state_bs[32] = sbox0(in0, in1, in2, in3);
	state_bs[33] = sbox1(in0, in1, in2, in3);
	state_bs[34] = sbox2(in0, in1, in2, in3);
	state_bs[35] = sbox3(in0, in1, in2, in3);

	// i = 9
	in0 = state_bs[36];
	in1 = state_bs[37];
	in2 = state_bs[38];
	in3 = state_bs[39];
	state_bs[36] = sbox0(in0, in1, in2, in3);
	state_bs[37] = sbox1(in0, in1, in2, in3);
	state_bs[38] = sbox2(in0, in1, in2, in3);
	state_bs[39] = sbox3(in0, in1, in2, in3);

	// i = 10
	in0 = state_bs[40];
	in1 = state_bs[41];
	in2 = state_bs[42];
	in3 = state_bs[43];
	state_bs[40] = sbox0(in0, in1, in2, in3);
	state_bs[41] = sbox1(in0, in1, in2, in3);
	state_bs[42] = sbox2(in0, in1, in2, in3);
	state_bs[43] = sbox3(in0, in1, in2, in3);

	// i = 11
	in0 = state_bs[44];
	in1 = state_bs[45];
	in2 = state_bs[46];
	in3 = state_bs[47];
	state_bs[44] = sbox0(in0, in1, in2, in3);
	state_bs[45] = sbox1(in0, in1, in2, in3);
	state_bs[46] = sbox2(in0, in1, in2, in3);
	state_bs[47] = sbox3(in0, in1, in2, in3);

	// i = 12
	in0 = state_bs[48];
	in1 = state_bs[49];
	in2 = state_bs[50];
	in3 = state_bs[51];
	state_bs[48] = sbox0(in0, in1, in2, in3);
	state_bs[49] = sbox1(in0, in1, in2, in3);
	state_bs[50] = sbox2(in0, in1, in2, in3);
	state_bs[51] = sbox3(in0, in1, in2, in3);

	// i = 13
	in0 = state_bs[52];
	in1 = state_bs[53];
	in2 = state_bs[54];
	in3 = state_bs[55];
	state_bs[52] = sbox0(in0, in1, in2, in3);
	state_bs[53] = sbox1(in0, in1, in2, in3);
	state_bs[54] = sbox2(in0, in1, in2, in3);
	state_bs[55] = sbox3(in0, in1, in2, in3);

	// i = 14
	in0 = state_bs[56];
	in1 = state_bs[57];
	in2 = state_bs[58];
	in3 = state_bs[59];
	state_bs[56] = sbox0(in0, in1, in2, in3);
	state_bs[57] = sbox1(in0, in1, in2, in3);
	state_bs[58] = sbox2(in0, in1, in2, in3);
	state_bs[59] = sbox3(in0, in1, in2, in3);

	// i = 15
	in0 = state_bs[60];
	in1 = state_bs[61];
	in2 = state_bs[62];
	in3 = state_bs[63];
	state_bs[60] = sbox0(in0, in1, in2, in3);
	state_bs[61] = sbox1(in0, in1, in2, in3);
	state_bs[62] = sbox2(in0, in1, in2, in3);
	state_bs[63] = sbox3(in0, in1, in2, in3);
}

/**
 * @brief pbox_layer - rearranges contents according to a predefined, fixed permutation
 * @param bs_reg_t s[CRYPTO_IN_SIZE_BIT] - data to use permute
 */
static void pbox_layer(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	bs_reg_t state_out[CRYPTO_IN_SIZE_BIT]; // don't initialise arrays as the contents are filled up and them being zero'd isn't needed

	// i = 0, off = 0
//	state_out[0] = state_bs[0]; // not needed
	state_out[16] = state_bs[1];
	state_out[32] = state_bs[2];
	state_out[48] = state_bs[3];

	// i = 4, off = 1
	state_out[1] = state_bs[4];
	state_out[17] = state_bs[5];
	state_out[33] = state_bs[6];
	state_out[49] = state_bs[7];

	// i = 8, off = 2
	state_out[2] = state_bs[8];
	state_out[18] = state_bs[9];
	state_out[34] = state_bs[10];
	state_out[50] = state_bs[11];

	// i = 12, off = 3
	state_out[3] = state_bs[12];
	state_out[19] = state_bs[13];
	state_out[35] = state_bs[14];
	state_out[51] = state_bs[15];

	// i = 16, off = 4
	state_out[4] = state_bs[16];
	state_out[20] = state_bs[17];
	state_out[36] = state_bs[18];
	state_out[52] = state_bs[19];

	// i = 20, off = 5
	state_out[5] = state_bs[20];
	state_out[21] = state_bs[21];
	state_out[37] = state_bs[22];
	state_out[53] = state_bs[23];

	// i = 24, off = 6
	state_out[6] = state_bs[24];
	state_out[22] = state_bs[25];
	state_out[38] = state_bs[26];
	state_out[54] = state_bs[27];

	// i = 28, off = 7
	state_out[7] = state_bs[28];
	state_out[23] = state_bs[29];
	state_out[39] = state_bs[30];
	state_out[55] = state_bs[31];

	// i = 32, off = 8
	state_out[8] = state_bs[32];
	state_out[24] = state_bs[33];
	state_out[40] = state_bs[34];
	state_out[56] = state_bs[35];

	// i = 36, off = 9
	state_out[9] = state_bs[36];
	state_out[25] = state_bs[37];
	state_out[41] = state_bs[38];
	state_out[57] = state_bs[39];

	// i = 40, off = 10
	state_out[10] = state_bs[40];
	state_out[26] = state_bs[41];
	state_out[42] = state_bs[42];
	state_out[58] = state_bs[43];

	// i = 44, off = 11
	state_out[11] = state_bs[44];
	state_out[27] = state_bs[45];
	state_out[43] = state_bs[46];
	state_out[59] = state_bs[47];

	// i = 48, off = 12
	state_out[12] = state_bs[48];
	state_out[28] = state_bs[49];
	state_out[44] = state_bs[50];
	state_out[60] = state_bs[51];

	// i = 52, off = 13
	state_out[13] = state_bs[52];
	state_out[29] = state_bs[53];
	state_out[45] = state_bs[54];
	state_out[61] = state_bs[55];

	// i = 56, off = 14
	state_out[14] = state_bs[56];
	state_out[30] = state_bs[57];
	state_out[46] = state_bs[58];
	state_out[62] = state_bs[59];

	// i = 60, off = 15
	state_out[15] = state_bs[60];
	state_out[31] = state_bs[61];
	state_out[47] = state_bs[62];
//	state_out[63] = state_bs[63]; // not needed

	memcpy(state_bs, state_out, 256);
}

/**
 * @brief crypto_func - function to actually perform cryptography, serves as API for those including "crypto.h"
 * @param uint8_t pt[CRYPTO_IN_SIZE] - data to encrypt
 * @param uint8_t key[CRYPTO_KEY_SIZE] - key to apply
 */
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE])
{
	bs_reg_t state[CRYPTO_IN_SIZE_BIT] = {0}; // State buffer

	enslice(pt, state); // Bring into bitslicing form

	uint8_t *const key2 = key + 2; // why waste time calculating key + 2 repeatedly

	// i = 1
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 1);

	// i = 2
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 2);

	// i = 3
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 3);

	// i = 4
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 4);

	// i = 5
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 5);

	// i = 6
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 6);

	// i = 7
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 7);

	// i = 8
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 8);

	// i = 9
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 9);

	// i = 10
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 10);

	// i = 11
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 11);

	// i = 12
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 12);

	// i = 13
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 13);

	// i = 14
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 14);

	// i = 15
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 15);

	// i = 16
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 16);

	// i = 17
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 17);

	// i = 18
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 18);

	// i = 19
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 19);

	// i = 20
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 20);

	// i = 21
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 21);

	// i = 22
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 22);

	// i = 23
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 23);

	// i = 24
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 24);

	// i = 25
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 25);

	// i = 26
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 26);

	// i = 27
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 27);

	// i = 28
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 28);

	// i = 29
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 29);

	// i = 30
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 30);

	// i = 31
	add_round_key(state, key2);
	sbox_layer(state);
	pbox_layer(state);
	update_round_key(key, 31);

	add_round_key(state, key2);

	unslice(state, pt); // Convert back to normal form
}
