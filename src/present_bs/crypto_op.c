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
  * #3 One-off calculations not stored in temporary variables
    * Allows compiler to better optimise keeping values in registers and not RAM, even if it makes the code look untidy
  * #4 Manual reduction of constant integer expression
    * Compiler might not reduce an expression when it's too complex to it - do it yourself to improve performance
    * e.g. 16 * 0 -> n/a, 16 * 1 -> 16, ...
  * #5 const [] -> static const T[]
    * ...when declarted within functions, where static variables means it's globalised (i.e. all instances of the function have access to it)
    * Cost is persistent memory use (in .data) but improves performance by reducing initialisation time to only once (when function is first called)
  * #6 TODO #1 SBOX reduction
  * #7 TODO #2 Unrolling smaller loops
  *
  * Some of the optimisations are already done by the compiler
   * This includes machine / architecture-dependant instructions - I'm fine not bothering with these (such as whether it should use xor x, x as opposed to x = 0, whether it's more optimal to shift or to divide (by a power of 2))
   * Some optimisations may involve basic integer expressions (such as pre-calculating expressions involving constant) - these have been implemented even though the compiler may have gone and done it had I left it be
   * Some are structural, such as whether to completely reform an expression, using common variables, etc. - these have to be implemented because the compiler isn't smart enough to do it alone
   * Either way, this code should be faster than it's non-optimised counterpart
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

	for (uint32_t i = 0; i < BITSLICE_WIDTH; ++i) { // TODO what are we iterating over?
		for (uint32_t j = 0; j < CRYPTO_IN_SIZE_BIT; ++j) { // TODO what are we iterating over?
			const bs_reg_t bit_value = (bs_reg_t)get_reg_bit(*ptr, j % 8); // get bit from byte indicated by ptr (our plaintext)
			state_bs[j] = cpy_bs_bit(state_bs[j], i, bit_value); // set bit of bitsliced array, as specified by i which serves as our bitoffset
									  // note that bit_value will be promoted to uint32_t to allow for potential max bit shift

			if ((j + 1) % 8 == 0) { // ++x returns value anyway so make use of access here
				++ptr; // move pointer to next byte
			}
		}
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

	for (uint32_t i = 0; i < BITSLICE_WIDTH; ++i) { // TODO what are we iterating over?
		for (uint32_t j = 0; j < CRYPTO_IN_SIZE_BIT; ++j) { // TODO what are we iterating over?
			const uint8_t bit_value = (uint8_t)get_bs_bit(state_bs[j], i); // get bit from byte from bitsliced array
			*ptr = cpy_reg_bit(*ptr, j % 8, bit_value); // set bit from byte indicated by ptr, where j % 8 is our bit offset

			if ((j + 1) % 8 == 0) { // if we've iterate over a whole byte
				++ptr; // move pointer to next byte
			}
		}
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

	for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; ++i) {
		const uint8_t current_bit = get_reg_bit(roundkey[i / 8], (i % 8)); // get current bit of current byte from roundkey
		state_bs[i] ^= bit_array[current_bit]; // app_bit is either 0 or 1 so index `bit_array`
	}
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
	// y0 = x0 + x1 · x2 + x2 + x3
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
	// y1 = x0 · x2 · x1 + x0 · x3 · x1 + x3 · x1 + x1 + x0 · x2 · x3 + x2 · x3 + x3
	return (in0 & in2 & in1) ^ (in0 & in3 & in1) ^ (in3 & in1) ^ in1 ^ (in0 & in2 & in3) ^ (in2 & in3) ^ in3;

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
	// y2 = x0 · x1 + x0 · x3 · x1 + x3 · x1 + x2 + x0 · x3 + x0 · x2 · x3 + x3 + 1
	return ~((in0 & in1) ^ (in0 & in3 & in1) ^ (in3 & in1) ^ in2 ^ (in0 & in3) ^ (in0 & in2 & in3) ^ in3); // NOT statement instead of XOR'ing by 0xffffffff
													       // compiler will typically convert the XOR 0xffffffff into a MVN instruction anyway but its good to specify
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
	// y3 = x1 · x2 · x0 + x1 · x3 · x0 + x2 · x3 · x0 + x0 + x1 + x1 · x2 + x3 + 1
	return ~((in1 & in2 & in0) ^ (in1 & in3 & in0) ^ (in2 & in3 & in0) ^ in0 ^ in1 ^ (in1 & in2) ^ in3); // NOT statement instead of XOR'ing by 0xffffffff
}

/**
 * @brief sbox_layer - applies substitution of contents using the s-box substitution table
 * @param bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT] - data to use SBOX to contents
 */
static void sbox_layer(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	bs_reg_t state_out[CRYPTO_IN_SIZE_BIT]; // don't initialise arrays as the contents are filled up and them being zero'd isn't needed

	for (uint8_t i = 0; i < 16; ++i) { // 16 = CRYPTO_IN_SIZE_BIT / 4
		const uint8_t off = i * 4;

		const bs_reg_t in0 = state_bs[off];
		const bs_reg_t in1 = state_bs[off + 1];
		const bs_reg_t in2 = state_bs[off + 2];
		const bs_reg_t in3 = state_bs[off + 3];

		state_out[off] = sbox0(in0, in1, in2, in3);
		state_out[off + 1] = sbox1(in0, in1, in2, in3);
		state_out[off + 2] = sbox2(in0, in1, in2, in3);
		state_out[off + 3] = sbox3(in0, in1, in2, in3);
	}

	for (uint32_t i = 0; i < CRYPTO_IN_SIZE_BIT; ++i) {
		state_bs[i] = state_out[i];
	}

}

/**
 * @brief pbox_layer - rearranges contents according to a predefined, fixed permutation
 * @param bs_reg_t s[CRYPTO_IN_SIZE_BIT] - data to use permute
 */
static void pbox_layer(bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
	bs_reg_t state_out[CRYPTO_IN_SIZE_BIT]; // don't initialise arrays as the contents are filled up and them being zero'd isn't needed

	for (uint32_t i = 0; i < CRYPTO_IN_SIZE_BIT; i += 4) {
		const uint8_t off = i / 4;

		state_out[off] = state_bs[i];
		state_out[off + 16] = state_bs[i + 1];
		state_out[off + 32] = state_bs[i + 2];
		state_out[off + 48] = state_bs[i + 3];
	}

	for (uint32_t i = 0; i < CRYPTO_IN_SIZE_BIT; ++i) {
		state_bs[i] = state_out[i];
	}
}

/**
 * @brief crypto_func - function to actually perform cryptography, serves as API for those including "crypto.h"
 * @param uint8_t pt[CRYPTO_IN_SIZE] - data to encrypt
 * @param uint8_t key[CRYPTO_KEY_SIZE] - key to apply
 */
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE])
{
	// State buffer and additional backbuffer of same size (you can remove the backbuffer if you do not need it)
	bs_reg_t state[CRYPTO_IN_SIZE_BIT];

	enslice(pt, state); // Bring into bitslicing form
	for(uint8_t i = 1; i <= 31; ++i) {
		add_round_key(state, key + 2);
		sbox_layer(state);
		pbox_layer(state);
		update_round_key(key, i);
	}
	add_round_key(state, key + 2);
	unslice(state, pt); // Convert back to normal form
}
