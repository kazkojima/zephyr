#define DT_DRV_COMPAT litex_trng

#include <device.h>
#include <drivers/entropy.h>
#include <errno.h>
#include <init.h>
#include <soc.h>
#include <string.h>
#include <zephyr.h>
#include <sys/printk.h>

#define TRNG_DATA       ((volatile uint32_t *)DT_INST_REG_ADDR(0))
#define TRNG_READY      ((volatile uint8_t *)DT_INST_REG_ADDR(0)+16)
#define TRNG_WIDTH      4
#define SUBREG_SIZE_BIT 8

static inline unsigned int trng_read(volatile uint32_t *reg_data,
					 volatile uint32_t reg_width)
{
	uint32_t shifted_data, shift, i;
	uint32_t result = 0;

	for (i = 0; i < reg_width; ++i) {
		shifted_data = *(reg_data + i);
		shift = (reg_width - i - 1) * SUBREG_SIZE_BIT;
		result |= (shifted_data << shift);
	}

	return result;
}

static int entropy_trng_get_entropy(const struct device *dev, uint8_t *buffer,
					 uint16_t length)
{
	while (length > 0) {
		size_t to_copy;
		uint32_t value;
		volatile uint32_t busy;

		busy = 0;
		while (*TRNG_READY == 0) {
			if (++busy > 100) {
				//printk("TRNG: ready timeout\n");
				return -1;
			}
		}
		value = trng_read(TRNG_DATA, TRNG_WIDTH);
		//printk("TRNG: Got %08x\n", value);
		to_copy = MIN(length, sizeof(value));

		memcpy(buffer, &value, to_copy);
		buffer += to_copy;
		length -= to_copy;
	}
	return 0;
}

static int entropy_trng_init(const struct device *dev)
{
	return 0;
}

static const struct entropy_driver_api entropy_trng_api = {
	.get_entropy = entropy_trng_get_entropy
};

DEVICE_DT_INST_DEFINE(0,
		    entropy_trng_init, device_pm_control_nop, NULL, NULL,
		    PRE_KERNEL_1, CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &entropy_trng_api);
