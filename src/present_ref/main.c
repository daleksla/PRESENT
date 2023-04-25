/**
 * Based on https://gist.github.com/nezza/27835ad5e5d5482e2b81445c5ab8df9c by Thomas Roth <code@stacksmashing.net>
 * Modified by David Oswald <d.f.oswald@bham.ac.uk>
 **/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/timer.h"
#include "hardware/clocks.h"
#include "hardware/structs/pll.h"
#include "hardware/structs/clocks.h"
#include "hardware/structs/systick.h"

#include "crypto.h"

#define TRIGGER_ACTIVE() {}
#define TRIGGER_RELEASE() {}

const uint LED_PIN = 25;

// based on https://forums.raspberrypi.com/viewtopic.php?f=145&t=304201&p=1820770&hilit=Hermannsw+systick#p1822677
static void systick_init()
{
	systick_hw->csr = 0x5;
	systick_hw->rvr = 0x00FFFFFF;
}

static uint64_t cpucycles()
{
	return systick_hw->cvr;
}

static uint8_t pt[CRYPTO_IN_SIZE] = { 0 };
static uint8_t key[CRYPTO_KEY_SIZE] = { 0 };

int main(void)
{
	uint8_t b = 0;
	uint64_t begin = 0, end = 0, duration;
	int c = -1;

	stdio_init_all();
	systick_init();

	sleep_ms(2000);
	printf("Welcome to the PRESENT test program v0.1...\n");

	gpio_init(LED_PIN);
	gpio_set_dir(LED_PIN, GPIO_OUT);
	gpio_put(LED_PIN, 1);

	while (1) {
		c = getchar_timeout_us(100000);

		if (c == (int)'e') {
			gpio_put(LED_PIN, 0);

			// Get key
			b = 0;
			while (b < CRYPTO_KEY_SIZE) {
				int x = getchar_timeout_us(100000);
				
				if (x != PICO_ERROR_TIMEOUT) {
					key[b] = x & 0xff;
					b++;
				}
			}

			// Get input
			b = 0;
			while (b < CRYPTO_IN_SIZE) {
				int x = getchar_timeout_us(100000);
				
				if (x != PICO_ERROR_TIMEOUT) {
					pt[b] = x & 0xff;
					b++;
				}
			}

			// Execute crypto code
			TRIGGER_ACTIVE();
			begin = cpucycles();
			crypto_func(pt, key);
			end = cpucycles();
			TRIGGER_RELEASE();

			// Return output
			for (b = 0; b < CRYPTO_OUT_SIZE; b++) {
				putchar_raw(pt[b]);
			}

			// Systick *decreases*
			duration = begin - end;

			for (b = 0; b < 8; b++) {
				putchar_raw(duration & (uint64_t)0xff);
				duration >>= 8;
			}

			gpio_put(LED_PIN, 1);
		}
	}

	return 0;
}

