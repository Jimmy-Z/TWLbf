
#pragma once

#include "common.h"

void dsi_aes_ctr_crypt_block(const u8 *console_id, const u8 *emmc_cid,
	const u8 *offset, const u8 *src);

void dsi_brute_emmc_cid(const u8 *console_id, const u8 *emmc_cid_template,
	const u8 *offset, const u8 *src, const u8 *verify);

void dsi_brute_console_id(const u8 *console_id_template, const u8 *emmc_cid,
	const u8 *offset, const u8 *src, const u8 *verify, int bcd);

