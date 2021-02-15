#define DT_DRV_COMPAT litex_trng

#include <device.h>
#include <drivers/entropy.h>
#include <errno.h>
#include <init.h>
#include <soc.h>
#include <string.h>
#include <zephyr.h>

#include <tinycrypt/sha256.h>

static struct tc_sha256_state_struct sha256_struct;
static uint8_t sha256_block[TC_SHA256_BLOCK_SIZE];
static uint8_t sha256_digest[TC_SHA256_DIGEST_SIZE];
static size_t sha256_offset;

#define TRNG_STATUS     ((volatile uint32_t *)DT_INST_REG_ADDR(0) + 1)
#define TRNG_WIDTH      4
#define SUBREG_SIZE_BIT 8

static void fill_digest(void)
{
	size_t i, j;

	for (i = 0; i < TC_SHA256_BLOCK_SIZE/4; i++) {
		for (j = 0; j < TRNG_WIDTH; ++j) {
			sha256_block[4*i+j] = (uint8_t)*(TRNG_STATUS + j);
		}
	}
	tc_sha256_update(&sha256_struct, sha256_block, TC_SHA256_BLOCK_SIZE);
	tc_sha256_final(sha256_digest, &sha256_struct);
	sha256_offset = 0;
}

static int entropy_trng_get_entropy(const struct device *dev, uint8_t *buffer,
					 uint16_t length)
{
	while (length > 0) {
		size_t to_copy;

		to_copy = MIN(length, (TC_SHA256_DIGEST_SIZE - sha256_offset));
		memcpy(buffer, &sha256_digest[sha256_offset], to_copy);
		buffer += to_copy;
		length -= to_copy;
		if (to_copy + sha256_offset == TC_SHA256_DIGEST_SIZE) {
			fill_digest();
		} else
			sha256_offset += to_copy;
	}
	return 0;
}

static int entropy_trng_init(const struct device *dev)
{
	tc_sha256_init(&sha256_struct);
	fill_digest();
	return 0;
}

static const struct entropy_driver_api entropy_trng_api = {
	.get_entropy = entropy_trng_get_entropy
};

DEVICE_DT_INST_DEFINE(0,
		    entropy_trng_init, device_pm_control_nop, NULL, NULL,
		    PRE_KERNEL_1, CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &entropy_trng_api);
