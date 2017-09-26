
#pragma once

#include "common.h"

static inline u64 u64be(const void *in){
	u64 out;
	u8 *out8 = (u8*)&out;
	out8[0] = ((u8*)in)[7];
	out8[1] = ((u8*)in)[6];
	out8[2] = ((u8*)in)[5];
	out8[3] = ((u8*)in)[4];
	out8[4] = ((u8*)in)[3];
	out8[5] = ((u8*)in)[2];
	out8[6] = ((u8*)in)[1];
	out8[7] = ((u8*)in)[0];
	return out;
}

static inline u32 u32be(const void *in){
	u32 out;
	u8 *out8 = (u8*)&out;
	out8[0] = ((u8*)in)[3];
	out8[1] = ((u8*)in)[2];
	out8[2] = ((u8*)in)[1];
	out8[3] = ((u8*)in)[0];
	return out;
}

static inline u16 u16be(const void *in){
	u16 out;
	u8 *out8 = (u8*)&out;
	out8[0] = ((u8*)in)[1];
	out8[1] = ((u8*)in)[0];
	return out;
}

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
