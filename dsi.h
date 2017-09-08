
#pragma once

#include "common.h"

typedef enum {
	NORMAL = 1,
	BCD = 2,
	CTR = 3
} brute_mode_t;

void dsi_aes_ctr_crypt_block(const u8 *console_id, const u8 *emmc_cid,
	const u8 *offset, const u8 *src, int is3DS);

void dsi_decrypt_mbr(const u8 *console_id, const u8 *emmc_cid,
	const char *in_file, const char *out_file);

void dsi_brute_emmc_cid(const u8 *console_id, const u8 *emmc_cid_template,
	const u8 *offset, const u8 *src, const u8 *verify);

void dsi_brute_console_id(const u8 *console_id_template, const u8 *emmc_cid,
	const u8 *offset, const u8 *src, const u8 *verify, brute_mode_t mode);
