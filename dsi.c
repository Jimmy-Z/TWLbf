
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <malloc.h>
#include <assert.h>
#include "dsi.h"
#include "utils.h"
#include "crypto.h"

#define DSI_PROFILE 0
#if DSI_PROFILE
#include <sys/time.h>
long long time_diff(const struct timeval *t1, const struct timeval *t0){
	return (t1->tv_sec - t0->tv_sec) * 1000000ll + (t1->tv_usec - t0->tv_usec);
}
#endif

// references:
// http://problemkaputt.de/gbatek.htm
// https://github.com/WinterMute/twltool

const u64 DSi_KEY_Y[2] =
	{0xbd4dc4d30ab9dc76ull, 0xe1a00005202ddd1dull};

const u64 DSi_KEY_MAGIC[2] =
	{0x2a680f5f1a4f3e79ull, 0xfffefb4e29590258ull};

static inline u64 u64be(const u8 *in){
	u64 out;
	u8 *out8 = (u8*)&out;
	out8[0] = in[7];
	out8[1] = in[6];
	out8[2] = in[5];
	out8[3] = in[4];
	out8[4] = in[3];
	out8[5] = in[2];
	out8[6] = in[1];
	out8[7] = in[0];
	return out;
}

static inline u32 u32be(const u8 *in){
	u32 out;
	u8 *out8 = (u8*)&out;
	out8[0] = in[3];
	out8[1] = in[2];
	out8[2] = in[1];
	out8[3] = in[0];
	return out;
}

static inline u16 u16be(const u8 *in){
	u16 out;
	u8 *out8 = (u8*)&out;
	out8[0] = in[1];
	out8[1] = in[0];
	return out;
}

// CAUTION this one doesn't work in-place
static inline void byte_reverse_16(u8 *out, const u8 *in){
	out[0] = in[15];
	out[1] = in[14];
	out[2] = in[13];
	out[3] = in[12];
	out[4] = in[11];
	out[5] = in[10];
	out[6] = in[9];
	out[7] = in[8];
	out[8] = in[7];
	out[9] = in[6];
	out[10] = in[5];
	out[11] = in[4];
	out[12] = in[3];
	out[13] = in[2];
	out[14] = in[1];
	out[15] = in[0];
}

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

// eMMC Encryption for MBR/Partitions (AES-CTR, with console-specific key)
static inline void dsi_make_key(u64 *key, u64 console_id){
	u32 h = console_id >> 32, l = (u32)console_id;
	u32 key_x[4] = {l, l ^ 0x24ee6906, h ^ 0xe65b601d, h};
	// Key = ((Key_X XOR Key_Y) + FFFEFB4E295902582A680F5F1A4F3E79h) ROL 42
	// equivalent to F_XY in twltool/f_xy.c
	xor_128(key, (u64*)key_x, DSi_KEY_Y);
	add_128(key, DSi_KEY_MAGIC);
	rol42_128(key);
}

void dsi_aes_ctr_crypt_block(const u8 *console_id, const u8 *emmc_cid,
	const u8 *offset, const u8 *src){
	crypto_init();
	u64 key[2];
	dsi_make_key(key, u64be(console_id));
	u8 key_reversed[16];
	byte_reverse_16(key_reversed, (u8*)key);
	printf("AES-CTR KEY: %s\n", hexdump(key_reversed, 16, 1));

	u8 emmc_cid_sha1[20];
	sha1_16(emmc_cid_sha1, emmc_cid);

	// twltool/dsi.c
	// in dsi_set_ctx, ctx/iv is reversed
	// then dsi_add_ctr is a big endian add
	//     first it was (semi) byte reversed to u32[4], to do add with carry, then reverse back
	// the first reverse in dsi_add_ctr cancelled the reverse in dsi_set_ctx
	add_128_64((u64*)emmc_cid_sha1, u16be(offset));
	u8 ctr[16];
	byte_reverse_16(ctr, emmc_cid_sha1);
	printf("AES-CTR IV:  %s\n", hexdump(ctr, 16, 1));

	aes_128_ecb_set_key(key_reversed);

	u8 xor_stream[16], xor_stream_reversed[16];
	aes_128_ecb_crypt_1(xor_stream, ctr);
	byte_reverse_16(xor_stream_reversed, xor_stream);

	printf("Source:      %s\n", hexdump(src, 16, 1));

	u8 out[16];
	xor_128((u64*)out, (u64*)src, (u64*)xor_stream_reversed);

	printf("Decrypted:   %s\n", hexdump(out, 16, 1));
}

#define BLOCK_SIZE 16
#if DSI_PROFILE
#define CHUNK_BITS 22
#else
#define CHUNK_BITS 12
#endif
#define CHUNK_LEN (1 << CHUNK_BITS)
#define CHUNK_COUNT (1 << (32 - CHUNK_BITS))

void dsi_brute_emmc_cid(const u8 *console_id, const u8 *emmc_cid_template,
	const u8 *offset, const u8 *src, const u8 *ver){
	u8 emmc_cid[16];
	memcpy(emmc_cid, emmc_cid_template, sizeof(emmc_cid));

	time_t start = time(0);
	u64 tested = 0;

	crypto_init();

	*(u32*)(emmc_cid + 1) = 0;
	printf("brute EMMC CID from %s", hexdump(emmc_cid, 16, 0));
	*(u32*)(emmc_cid + 1) = 0xffffffffu;
	printf(" to %s\n", hexdump(emmc_cid, 16, 0));

	printf("chunk size: %d bytes\n", BLOCK_SIZE * CHUNK_LEN);

	u8 target_xor[16];
   	xor_128((u64*)target_xor, (u64*)src, (u64*)ver);
	u64 target_xor_l64 = u64be(target_xor + 8);
	u64 target_xor_h64 = u64be(target_xor);

	u64 key[2];
	dsi_make_key(key, u64be(console_id));
	u8 key_reversed[16];
	byte_reverse_16(key_reversed, (u8*)key);

	aes_128_ecb_set_key(key_reversed);

	u64 offset64 = u16be(offset);

#if DSI_PROFILE
	struct timeval t0, t1, t2, t3;
#endif

	int succeed = 0;
	u8 *ctr_chunk = malloc(BLOCK_SIZE * CHUNK_LEN);
	u8 *xor_chunk = malloc(BLOCK_SIZE * CHUNK_LEN);
	assert(ctr_chunk != NULL && xor_chunk != NULL);
	for (u32 i = 0; i < CHUNK_COUNT; ++i){

		*(u32*)(emmc_cid + 1) = i << CHUNK_BITS;
		if(!(i << (CHUNK_BITS + 4))){
			printf("testing %02x??????%1x?%s\n", *emmc_cid,
				i >> (32 - CHUNK_BITS - 4), hexdump(emmc_cid + 5, 11, 0));
		}
#if DSI_PROFILE
		gettimeofday(&t0, NULL);
#endif
		for(unsigned j = 0; j < CHUNK_LEN; ++j){
			u8 emmc_cid_sha1[20];
			sha1_16(emmc_cid_sha1, emmc_cid);
			add_128_64((u64*)emmc_cid_sha1, offset64);
			byte_reverse_16(ctr_chunk + BLOCK_SIZE * j, emmc_cid_sha1);
			*(u32*)(emmc_cid + 1) += 1;
		}
#if DSI_PROFILE
		gettimeofday(&t1, NULL);
#endif
		aes_128_ecb_crypt(xor_chunk, ctr_chunk, BLOCK_SIZE * CHUNK_LEN);
#if DSI_PROFILE
		gettimeofday(&t2, NULL);
#endif
		tested = i * CHUNK_LEN;
		u64 *p_l = (u64*)xor_chunk, *p_h = (u64*)(xor_chunk + 8);
		for(unsigned j = 0; j < CHUNK_LEN; ++j){
			if(*p_l == target_xor_l64 && *p_h == target_xor_h64){
				*(u32*)(emmc_cid + 1) = (i << CHUNK_BITS) + j;
				printf("got a hit: %s\n", hexdump(emmc_cid, 16, 0));
				succeed = 1;
				break;
			}
			p_l += 2;
			p_h += 2;
		}
#if DSI_PROFILE
		gettimeofday(&t3, NULL);
		printf("SHA1: %lld\nAES: %lld\nmemcmp: %lld\n",
				time_diff(&t1, &t0), time_diff(&t2, &t1), time_diff(&t3, &t2));
		return;
#endif
		if(succeed){
			break;
		}
	}
	free(ctr_chunk);
	free(xor_chunk);
	double td = difftime(time(0), start);
	printf("%.2f seconds, %.2f M/s\n", td, tested / 1000000.0 / td);
}

void dsi_brute_console_id(const u8 *console_id_template, const u8 *emmc_cid,
	const u8 *offset, const u8 *src, const u8 *ver, int bcd)
{
	u64 tested = 0;
	time_t start = time(0);

	crypto_init();

	u8 target_xor[16];
	xor_128((u64*)target_xor, (u64*)src, (u64*)ver);
	u64 target_xor_l64 = u64be(target_xor + 8);
	u64 target_xor_h64 = u64be(target_xor);

	u8 emmc_cid_sha1[20];
	sha1_16(emmc_cid_sha1, emmc_cid);
	add_128_64((u64*)emmc_cid_sha1, u16be(offset));
	u8 ctr[16];
	byte_reverse_16(ctr, emmc_cid_sha1);

	if(bcd){
		int succeed = 0;
		u64 start64 = (u64be(console_id_template) & 0xfffff00000000000ull) + 0x100;
		for (u64 i = 0; (i <= 9ull << 40) && !succeed; i += 1ull << 40) {
			printf("testing %06x???????1??\n", (u32)((start64 + i) >> 40));
			for (u64 j = 0; (j <= 9ull << 36) && !succeed; j += 1ull << 36) {
				for (u64 k = 0; (k <= 9ull << 32) && !succeed; k += 1ull << 32) {
					for (u64 l = 0; (l <= 9ull << 28) && !succeed; l += 1ull << 28) {
						for (u64 m = 0; (m <= 9ull << 24) && !succeed; m += 1ull << 24) {
							for (u64 n = 0; (n <= 9ull << 20) && !succeed; n += 1ull << 20) {
								for (u64 o = 0; (o <= 9ull << 16) && !succeed; o += 1ull << 16) {
									for (u64 p = 0; (p <= 9ull << 12) && !succeed; p += 1ull << 12) {
										for (u64 q = 0; (q <= 9ull << 4) && !succeed; q += 1ull << 4) {
											for (u64 r = 0; (r <= 9ull) && !succeed; r += 1ull) {
												u64 console_id = start64 + i + j + k + l + m + n + o + p + q + r;

												u64 key[2];
												dsi_make_key(key, console_id);
												u8 key_reversed[16];
												byte_reverse_16(key_reversed, (u8*)key);

												aes_128_ecb_set_key(key_reversed);

												u64 xor[2];
												aes_128_ecb_crypt_1((u8*)xor, ctr);

												++tested;

												if(xor[0] == target_xor_l64 && xor[1] == target_xor_h64){
													printf("got a hit: %08x%08x\n", (u32)(console_id >> 32), (u32)console_id);
													succeed = 1;
													break;
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}else{
		u64 start64 = u64be(console_id_template) & 0xffffffff00000000ull;
		for (u64 i = 0; i <= 1ull << 32; ++i){
			tested = i;
			// brute through the lower 32 bits
			u64 console_id = start64 | i;
			if(!(i & 0xfffffff)){
				printf("testing %08x%1x???????\n", (u32)(console_id >> 32), ((u32)console_id) >> 28);
			}
			u64 key[2];
			dsi_make_key(key, console_id);
			u8 key_reversed[16];
			byte_reverse_16(key_reversed, (u8*)key);

			aes_128_ecb_set_key(key_reversed);

			u64 xor[2];
			aes_128_ecb_crypt_1((u8*)xor, ctr);

			if(xor[0] == target_xor_l64 && xor[1] == target_xor_h64){
				printf("got a hit: %08x%08x\n", (u32)(console_id >> 32), (u32)console_id);
				break;
			}
		}
	}
	double td = difftime(time(0), start);
	printf("%.2f seconds, %.2f M/s\n", td, tested / 1000000.0 / td);
}

