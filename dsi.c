
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "dsi.h"
#include "utils.h"
#include "crypto.h"

// references:
// http://problemkaputt.de/gbatek.htm
// https://github.com/WinterMute/twltool

const u32 DSi_KEY_Y[4] =
	{0x0ab9dc76, 0xbd4dc4d3, 0x202ddd1d, 0xe1a00005};

const u32 DSi_KEY_MAGIC[4] =
	{0x1a4f3e79, 0x2a680f5f, 0x29590258, 0xfffefb4e};

static inline void xor_128(u64 *x, const u64 *a, const u64 *b){
	x[0] = a[0] ^ b[0];
	x[1] = a[1] ^ b[1];
}

static inline void add_128(u64 *a, const u64 *b){
	a[0] += b[0];
	if(a[0] < b[0]){
		a[1] += b[1] + 1;
	}else{
		a[1] += b[1];
	}
}

static inline void add_128_64(u64 *a, u64 b){
	a[0] += b;
	if(a[0] < b){
		a[1] += 1;
	}
}

// Answer to life, universe and everything.
static inline void rol42_128(u64 *a){
	u64 t = a[1];
	a[1] = (t << 42 ) | (a[0] >> 22);
	a[0] = (a[0] << 42 ) | (t >> 22);
}

// Key = ((Key_X XOR Key_Y) + FFFEFB4E295902582A680F5F1A4F3E79h) ROL 42
// equivalent to F_XY in twltool/f_xy.c
static inline void dsi_make_key(u64 *key, u64 *key_x){
	xor_128(key, key_x, (u64*)DSi_KEY_Y);
	add_128(key, (u64*)DSi_KEY_MAGIC);
	rol42_128(key);
}

// eMMC Encryption for MBR/Partitions (AES-CTR, with console-specific key)
static inline void dsi_make_key_from_console_id(u64 *key, u64 console_id){
	u32 h = console_id >> 32, l = (u32)console_id;
	u32 key_x[4] = {l, l ^ 0x24ee6906, h ^ 0xe65b601d, h};
	dsi_make_key(key, (u64*)key_x);
}

void dsi_aes_ctr_crypt_block(const u8 *console_id, const u8 *emmc_cid, const u8 *src, u16 offset){
	u64 key[2];
	dsi_make_key_from_console_id(key, u64be(console_id));
	printf("AES-CTR KEY: ");
	hexdump(key, 16, 1);

	u8 emmc_cid_sha1[20];
	sha1(emmc_cid_sha1, emmc_cid, 16);
	printf("AES-CTR IV:  ");
	hexdump(emmc_cid_sha1, 16, 1);

	printf("Source:      ");
	hexdump(src, 16, 1);

	aes_128_ecb_init();
	// twltool/dsi.c
	// in dsi_set_ctx, ctx/iv is reversed
	// then dsi_add_ctr is a big endian add
	//     first it was (semi) byte reversed to u32[4], to do add with carry, then reverse back
	// the first reverse in dsi_add_ctr cancelled the reverse in dsi_set_ctx
	u8 ctr[16];
	add_128_64((u64*)emmc_cid_sha1, offset);
	byte_reverse_16(ctr, emmc_cid_sha1);

	u8 key_reversed[16];
	byte_reverse_16(key_reversed, (u8*)key);

	aes_128_ecb_set_key(key_reversed);

	u8 xor_stream[16], xor_stream_reversed[16];
	aes_128_ecb_crypt(xor_stream, ctr);
	byte_reverse_16(xor_stream_reversed, xor_stream);

	u8 out[16];
	xor_128((u64*)out, (u64*)src, (u64*)xor_stream_reversed);

	printf("Decrypted:   ");
	hexdump(out, 16, 1);
}

void dsi_brute_emmc_cid(const u8 *console_id, const u8 *emmc_cid_template, const u8 *src, const u8 *ver, u16 offset){
	u8 emmc_cid[16];
	memcpy(emmc_cid, emmc_cid_template, sizeof(emmc_cid));

	time_t start = time(0);

	printf("brute EMMC CID from ");
	*(u32*)(emmc_cid + 1) = 0;
	hexdump(emmc_cid, 16, 0);
	printf("\tto ");
	*(u32*)(emmc_cid + 1) = 0xffffffffu;
	hexdump(emmc_cid, 16, 0);

	aes_128_ecb_init();

	u64 key[2];
	dsi_make_key_from_console_id(key, u64be(console_id));
	u8 key_reversed[16];
	byte_reverse_16(key_reversed, (u8*)key);

	aes_128_ecb_set_key(key_reversed);

	for (u32 i = 0; i <= 0xffffffffu; ++i){
		*(u32*)(emmc_cid + 1) = i;
		if(!(i & 0x00ffffff)){
			printf("testing ");
			hexdump(emmc_cid, 16, 0);
		}
		u8 emmc_cid_sha1[20];
		sha1(emmc_cid_sha1, emmc_cid, 16);
		u8 ctr[16];
		add_128_64((u64*)emmc_cid_sha1, offset);
		byte_reverse_16(ctr, emmc_cid_sha1);

		u8 xor_stream[16], xor_stream_reversed[16];
		aes_128_ecb_crypt(xor_stream, ctr);
		byte_reverse_16(xor_stream_reversed, xor_stream);

		u8 out[16];
		xor_128((u64*)out, (u64*)src, (u64*)xor_stream_reversed);

		if(!memcmp(out, ver, 16)){
			printf("got a hit: ");
			hexdump(emmc_cid, 16, 0);
			break;
		}
	}
	printf("%.2f seconds\n", difftime(time(0), start));
}
