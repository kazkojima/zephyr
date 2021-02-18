#define DT_DRV_COMPAT litex_trng

#include <device.h>
#include <drivers/entropy.h>
#include <errno.h>
#include <init.h>
#include <soc.h>
#include <string.h>
#include <zephyr.h>

#if defined(CONFIG_WOLFSSL)
typedef struct wc_Sha256 {
        uint8_t digest[32];
        uint8_t buffer[64];
        uint32_t buffLen;   /* in bytes          */
        uint32_t loLen;     /* length in bytes   */
        uint32_t hiLen;     /* length in bytes   */
        void* heap;
} wc_Sha256_t;
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define sha256_init wc_InitSha256
#define sha256_update wc_Sha256Update
static inline void sha256_final(uint8_t *digest, wc_Sha256_t *str)
{
	wc_Sha256Final(str, digest);
}
static wc_Sha256_t sha256_struct;
#elif defined(CONFIG_MBEDTLS)
#include <mbedtls/sha256.h>
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
static inline void sha256_init(mbedtls_sha256_context *str)
{
	mbedtls_sha256_init(str);
	mbedtls_sha256_starts_ret(str, 0);
}
#define sha256_update mbedtls_sha256_update_ret
#define sha256_final mbedtls_sha256_finish_ret
static mbedtls_sha256_context sha256_struct;
#elif defined(CONFIG_TINYCRYPT)
#include <tinycrypt/sha256.h>
#define SHA256_BLOCK_SIZE TC_SHA256_BLOCK_SIZE
#define SHA256_DIGEST_SIZE TC_SHA256_DIGEST_SIZE
#define sha256_init tc_sha256_init
#define sha256_update tc_sha256_update
#define sha256_final tc_sha256_final
static struct tc_sha256_state_struct sha256_struct;
#else
// No software conditioning
typedef struct sha256_context {
	uint8_t buffer[32];
} sha256_context_t;
#define SHA256_BLOCK_SIZE 32
#define SHA256_DIGEST_SIZE 32
static inline void sha256_init(sha256_context *str) {}
static inline void sha256_update(sha256_context_t *str, uint8_t *s, size_t len)
{
	memcpy(srt->buffer, s, len);
}
static inline void sha256_final(uint8_t *digest, sha256_context_t *str)
{
	memcpy(digest, srt->buffer, SHA256_DIGEST_SIZE);
}
static sha256_context_t sha256_struct;
#endif

static uint8_t sha256_block[SHA256_BLOCK_SIZE];
static uint8_t sha256_digest[SHA256_DIGEST_SIZE];
static size_t sha256_offset;

#define TRNG_STATUS     ((volatile uint32_t *)DT_INST_REG_ADDR(0) + 1)
#define TRNG_WIDTH      4
#define SUBREG_SIZE_BIT 8

static void fill_digest(void)
{
	size_t i, j;

	for (i = 0; i < SHA256_BLOCK_SIZE/4; i++) {
		for (j = 0; j < TRNG_WIDTH; ++j) {
			sha256_block[4*i+j] = (uint8_t)*(TRNG_STATUS + j);
		}
	}
	sha256_update(&sha256_struct, sha256_block, SHA256_BLOCK_SIZE);
	sha256_final(sha256_digest, &sha256_struct);
	sha256_offset = 0;
}

static int entropy_trng_get_entropy(const struct device *dev, uint8_t *buffer,
					 uint16_t length)
{
	while (length > 0) {
		size_t to_copy;

		to_copy = MIN(length, (SHA256_DIGEST_SIZE - sha256_offset));
		memcpy(buffer, &sha256_digest[sha256_offset], to_copy);
		buffer += to_copy;
		length -= to_copy;
		if (to_copy + sha256_offset == SHA256_DIGEST_SIZE) {
			fill_digest();
		} else
			sha256_offset += to_copy;
	}
	return 0;
}

static int entropy_trng_init(const struct device *dev)
{
	sha256_init(&sha256_struct);
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
