// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Adappt Limited. All rights reserved.
 *
 * RK3576 platform support for OP-TEE.
 *
 * DDR firewall: managed by TF-A via SYS_SGRF_FW at 0x26005000.
 *
 * TRNG: uses the RKRNG IP at RKRNG_S_BASE (0x2A440000).  The RKRNG
 * has a simpler interface than the RK3588's TRNG_V1: no explicit
 * seed step, just request TRNG and poll for ready.
 *
 * HUK: 128-bit key stored in secure OTP at word index 0x80.
 * On first boot (empty OTP), generated from TRNG and persisted.
 */

#include <assert.h>
#include <common.h>
#include <drivers/rockchip_otp.h>
#include <io.h>
#include <kernel/mutex.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <platform.h>
#include <platform_config.h>
#include <rng_support.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <utee_defines.h>

/*
 * RKRNG register offsets — same IP as used in RK3576/RK3562/RK3528.
 * Register layout from the Linux rockchip-rng driver and verified
 * against the RK3576 TRM V1.2.
 */
#define RKRNG_CTRL		0x0010
#define RKRNG_CTRL_REQ_TRNG	BIT32(4)
#define RKRNG_STATE		0x0014
#define RKRNG_STATE_TRNG_RDY	BIT32(4)
#define RKRNG_TRNG_DATA0	0x0050

#define RKRNG_POLL_PERIOD_US	0
#define RKRNG_POLL_TIMEOUT_US	10000
#define RKRNG_READ_LEN		32	/* 8 x 32-bit = 256 bits per request */

register_phys_mem_pgdir(MEM_AREA_IO_SEC, RKRNG_S_BASE, RKRNG_S_SIZE);

static struct mutex rng_mutex = MUTEX_INITIALIZER;
static struct mutex huk_mutex = MUTEX_INITIALIZER;

static struct tee_hw_unique_key *huk;

int platform_secure_ddr_region(int rgn, paddr_t st, size_t sz)
{
	DMSG("DDR firewall region %d: 0x%"PRIxPA"-0x%"PRIxPA
	     " (managed by TF-A, not OP-TEE)", rgn, st, st + sz);

	return 0;
}

TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
	vaddr_t base = (vaddr_t)phys_to_virt_io(RKRNG_S_BASE, RKRNG_S_SIZE);
	uint8_t *dst = buf;
	size_t remaining = blen;
	uint32_t val = 0;

	if (!base)
		panic("RKRNG_S base not mapped");

	mutex_lock(&rng_mutex);

	while (remaining > 0) {
		size_t chunk = MIN(remaining, (size_t)RKRNG_READ_LEN);
		size_t i = 0;

		/* Request TRNG output (write-enable mask in upper 16 bits) */
		io_write32(base + RKRNG_CTRL,
			   RKRNG_CTRL_REQ_TRNG |
			   (RKRNG_CTRL_REQ_TRNG << 16));

		/* Poll for TRNG_RDY */
		if (IO_READ32_POLL_TIMEOUT(base + RKRNG_STATE, val,
					   val & RKRNG_STATE_TRNG_RDY,
					   RKRNG_POLL_PERIOD_US,
					   RKRNG_POLL_TIMEOUT_US)) {
			EMSG("RKRNG timeout");
			mutex_unlock(&rng_mutex);
			return TEE_ERROR_BUSY;
		}

		/* Clear TRNG_RDY */
		io_write32(base + RKRNG_STATE, RKRNG_STATE_TRNG_RDY);

		/* Read out random words */
		for (i = 0; i < chunk; i += sizeof(uint32_t)) {
			uint32_t rnd = io_read32(base + RKRNG_TRNG_DATA0 + i);
			size_t copy_len = MIN(chunk - i, sizeof(uint32_t));

			memcpy(dst, &rnd, copy_len);
			dst += copy_len;
		}

		remaining -= chunk;
	}

	mutex_unlock(&rng_mutex);

	return TEE_SUCCESS;
}

static TEE_Result generate_huk(struct tee_hw_unique_key *hwkey)
{
	uint8_t buffer[HW_UNIQUE_KEY_LENGTH] = { };
	TEE_Result res = TEE_SUCCESS;
	bool key_is_zero = true;
	size_t i = 0;

	res = hw_get_random_bytes(buffer, sizeof(buffer));
	if (res)
		return res;

	for (i = 0; i < ARRAY_SIZE(buffer); i++) {
		if (buffer[i] != 0)
			key_is_zero = false;
	}
	if (key_is_zero)
		return TEE_ERROR_NO_DATA;

	memcpy(hwkey->data, buffer, HW_UNIQUE_KEY_LENGTH);

	return res;
}

static TEE_Result persist_huk(struct tee_hw_unique_key *hwkey)
{
	uint32_t buffer[ROCKCHIP_OTP_HUK_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;

	static_assert(sizeof(buffer) == sizeof(hwkey->data));

	memcpy(buffer, hwkey->data, HW_UNIQUE_KEY_LENGTH);

	res = rockchip_otp_write_secure(buffer, ROCKCHIP_OTP_HUK_INDEX,
					ROCKCHIP_OTP_HUK_SIZE);

	memzero_explicit(buffer, sizeof(buffer));

	return res;
}

static TEE_Result read_huk(struct tee_hw_unique_key *hwkey)
{
	uint32_t buffer[ROCKCHIP_OTP_HUK_SIZE] = { };
	TEE_Result res = TEE_SUCCESS;
	bool key_is_empty = true;
	size_t i = 0;

	static_assert(sizeof(buffer) == sizeof(hwkey->data));

	res = rockchip_otp_read_secure(buffer,
				       ROCKCHIP_OTP_HUK_INDEX,
				       ROCKCHIP_OTP_HUK_SIZE);
	if (res)
		goto out;

	for (i = 0; i < ARRAY_SIZE(buffer); i++) {
		if (buffer[i] != 0)
			key_is_empty = false;
	}
	if (key_is_empty)
		return TEE_ERROR_NO_DATA;

	memcpy(hwkey->data, buffer, HW_UNIQUE_KEY_LENGTH);

out:
	memzero_explicit(buffer, sizeof(buffer));

	return res;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result res = TEE_SUCCESS;

	if (!hwkey)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&huk_mutex);

	if (huk)
		goto out;

	huk = malloc(sizeof(*huk));
	if (!huk) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = read_huk(huk);
	if (res != TEE_ERROR_NO_DATA)
		goto out;

	res = generate_huk(huk);
	if (res != TEE_SUCCESS)
		goto out;
	res = persist_huk(huk);

out:
	if (res == TEE_SUCCESS) {
		memcpy(hwkey->data, huk->data, HW_UNIQUE_KEY_LENGTH);
	} else if (huk) {
		free_wipe(huk);
		huk = NULL;
	}

	mutex_unlock(&huk_mutex);

	return res;
}
