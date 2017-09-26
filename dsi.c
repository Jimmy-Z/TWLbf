
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <malloc.h>
#include <assert.h>
#include "dsi.h"
#include "utils.h"
#include "sector0.h"
#include "ticket0.h"
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

const u64 DSi_ES_KEY_Y[2] =
	{0x72c9d0568b5acce5ull, 0xa9361239dce8179cull};

// CAUTION this one doesn't work in-place
static inline void byte_reverse_16(u8 *out, const u8 *in){
	out[0] = in[15]; out[1] = in[14]; out[2] = in[13]; out[3] = in[12];
	out[4] = in[11]; out[5] = in[10]; out[6] = in[9]; out[7] = in[8];
	out[8] = in[7]; out[9] = in[6]; out[10] = in[5]; out[11] = in[4];
	out[12] = in[3]; out[13] = in[2]; out[14] = in[1]; out[15] = in[0];
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

// Answer to life, universe and everything?
static inline void rol42_128(u64 *a){
	u64 t = a[1];
	a[1] = (t << 42 ) | (a[0] >> 22);
	a[0] = (a[0] << 42 ) | (t >> 22);
}

// "eMMC Encryption for MBR/Partitions (AES-CTR, with console-specific key)"
static inline void dsi_make_key(u64 *key, u64 console_id, int is3DS){
	u32 h = console_id >> 32, l = (u32)console_id;
	u32 key_x[4];
	if(!is3DS){
		key_x[0] = l;
		key_x[1] = l ^ 0x24ee6906;
		key_x[2] = h ^ 0xe65b601d;
		key_x[3] = h;
	}else{
		key_x[0] = (l ^ 0xb358a6af) | 0x80000000;
		key_x[1] = 0x544e494e;
		key_x[2] = 0x4f444e45;
		key_x[3] = h ^ 0x08c267b7;
	}
	// printf("AES-CTR KEY_X:\n%s\n", hexdump(key_x, 16, 0));
	// Key = ((Key_X XOR Key_Y) + FFFEFB4E295902582A680F5F1A4F3E79h) ROL 42
	// equivalent to F_XY in twltool/f_xy.c
	xor_128(key, (u64*)key_x, DSi_KEY_Y);
	// printf("AES-CTR KEY: XOR KEY_Y:\n%s\n", hexdump(key, 16, 0));
	add_128(key, DSi_KEY_MAGIC);
	// printf("AES-CTR KEY: + MAGIC:\n%s\n", hexdump(key, 16, 0));
	rol42_128(key);
	// printf("AES-CTR KEY: ROL 42:\n%s\n", hexdump(key, 16, 0));
}

void dsi_aes_ctr_crypt_block(const u8 *console_id, const u8 *emmc_cid,
	const u8 *offset, const u8 *src, int is3DS)
{
	crypto_init();
	u64 key[2];
	dsi_make_key(key, u64be(console_id), is3DS);
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

#define MBR_SIZE 0x200

void dsi_decrypt_mbr(const u8 *console_id, const u8 *emmc_cid,
	const char *in_file, const char *out_file)
{
	u8 mbr[MBR_SIZE];
	read_block_from_file(mbr, in_file, 0, MBR_SIZE);

	int is3DS = parse_ncsd(mbr);

	crypto_init();
	u64 key[2];
	dsi_make_key(key, u64be(console_id), is3DS);
	u8 key_reversed[16];
	byte_reverse_16(key_reversed, (u8*)key);

	aes_128_ecb_set_key(key_reversed);

	u8 emmc_cid_sha1[20];
	sha1_16(emmc_cid_sha1, emmc_cid);

	for (unsigned offset = 0; offset < MBR_SIZE; offset += 16) {
		u8 ctr[16];
		byte_reverse_16(ctr, emmc_cid_sha1);

		u8 xor[16];
		aes_128_ecb_crypt_1(ctr, ctr);
		byte_reverse_16(xor, ctr);

		xor_128((u64*)(mbr + offset), (u64*)(mbr + offset), (u64*) xor );

		add_128_64((u64*)emmc_cid_sha1, 1);
	}

	if (parse_mbr(mbr, is3DS, 1)) {
		dump_to_file(out_file, mbr, MBR_SIZE);
	}
	else {
		printf("invalid MBR, decryption failed\n");
	}
}

static void aes_ecb_rev(u8 *o, const u8 *i) {
	u8 rev[16];
	byte_reverse_16(rev, i);
	aes_128_ecb_crypt_1(rev, rev);
	byte_reverse_16(o, rev);
}

static void aes_ctr_1(u8 *d, const u8 *ctr) {
	u8 xor[16];
	aes_ecb_rev(xor, ctr);
	xor_128((u64*)d, (u64*)d, (u64*)xor);
}

// http://problemkaputt.de/gbatek.htm#dsiesblockencryption
// "DSi SD/MMC DSiware Files on Internal eMMC Storage"
void dsi_es_block_crypt(const u8 *console_id,
	const char *in_file, const char *out_file)
{
	crypto_init();
	u32 key[4] = {
		0x4e00004a,
		0x4a00004e,
		u32be(console_id) ^ 0xc80c4b72,
		u32be(console_id + 4)
	};
	xor_128((u64*)key, (u64*)key, DSi_ES_KEY_Y);
	add_128((u64*)key, DSi_KEY_MAGIC);
	rol42_128((u64*)key);
	u8 key_rev[16];
	byte_reverse_16(key_rev, (u8*)key);
	aes_128_ecb_set_key(key_rev);

	long input_size;
	u8 *input_buf = read_file(in_file, &input_size);
	printf("file size %u, block size would be %06x\n",
		(unsigned)input_size, (unsigned)(input_size - sizeof(es_block_footer_t)));
	
	// AES-CTR crypt later half of footer
	es_block_footer_t footer;
	u8 nonce[sizeof(footer.nonce)];
	// save footer since it might be overwritten by padding
	memcpy(&footer, input_buf + input_size - sizeof(es_block_footer_t), sizeof(es_block_footer_t));
	// save nonce since the one in ther footer becomes gargage after footer verification
	memcpy(nonce, footer.nonce, sizeof(nonce));
	u8 ctr[16] = { 0 };
	memcpy(ctr + 1, nonce, sizeof(nonce));
	aes_ctr_1(((u8*)&footer) + 0x10, ctr);
	// check decrypted footer
	if (footer.fixed_3a != 0x3a) {
		printf("footer decryption failed, offset 0x10 should be 0x3a, got 0x%02x\n", footer.fixed_3a);
		return;
	}
	unsigned block_size = (((((unsigned)footer.len2) << 8) | footer.len1) << 8) | footer.len0;
	if (block_size + sizeof(es_block_footer_t) != input_size) {
		printf("block size in footer doesn't match, %06x != %06x\n",
			block_size, (unsigned)(input_size - sizeof(es_block_footer_t)));
		return;
	}
	// apply padding if not 16 bytes aligned
	unsigned remainder = block_size & 0xf;
	if (remainder > 0) {
		u8 padding[16] = { 0 };
		u8 ctr[16] = { 0 };
		*(u32*)ctr = (block_size >> 4) + 1;
		memcpy(ctr + 3, nonce, sizeof(nonce));
		ctr[0xf] = 2;
		aes_ctr_1(padding, ctr);
		memcpy(input_buf + block_size, padding + remainder, sizeof(padding) - remainder);
		block_size += sizeof(padding) - remainder;
	}
	// AES-CCM MAC
	u8 mac[16];
	*(u32*)mac = block_size;
	memcpy(mac + 3, nonce, sizeof(nonce));
	mac[15] = 0x3a;
	aes_ecb_rev(mac, mac);
	// printf("AES-CCM MAC: %s\n", hexdump(mac, 16, 1));
	// AES-CCM CTR
	ctr[0] = 0; ctr[1] = 0; ctr[2] = 0;
	memcpy(ctr + 3, nonce, sizeof(nonce));
	ctr[15] = 2;
	// printf("AES-CCM CTR: %s\n", hexdump(ctr, 16, 1));
	// what?
	u8 S0[16] = { 0 };
	aes_ctr_1(S0, ctr);
	add_128_64((u64*)ctr, 1);
	// printf("AES-CCM S0 : %s\n", hexdump(S0, 16, 1));
	// CCM loop
	for (unsigned i = 0; i < block_size; i += 16) {
		aes_ctr_1(input_buf + i, ctr);
		// printf("AES-CCM DUMP %s\n", hexdump(input_buf + i, 16, 1));
		add_128_64((u64*)ctr, 1);
		xor_128((u64*)mac, (u64*)mac, (u64*)(input_buf + i));
		aes_ecb_rev(mac, mac);
		// printf("AES-CCM MAC: %s\n", hexdump(mac_rev, 16, 1));
	}
	xor_128((u64*)mac, (u64*)mac, (u64*)S0);

	printf("MAC in footer  : %s\n", hexdump(&footer, 16, 1));
	printf("MAC calculated : %s\n", hexdump(mac, 16, 1));

	free(input_buf);
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
	const u8 *offset, const u8 *src, const u8 *ver)
{
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
	dsi_make_key(key, u64be(console_id), 0);
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
	const u8 *offset, const u8 *src, const u8 *ver, brute_mode_t mode)
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

	if(mode == BCD){
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
												dsi_make_key(key, console_id, 0);
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
		u64 total = mode != CTR ? 1ull << 32 : 1ull << 31;
		for (u64 i = 0; i <= total; ++i){
			tested = i;
			// brute through the lower 32 bits
			u64 console_id = start64 | i;
			if(!(i & 0xfffffff)){
				printf("testing %08x%1x???????\n", (u32)(console_id >> 32), ((u32)console_id) >> 28);
			}
			u64 key[2];
			dsi_make_key(key, console_id, mode == CTR);
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

