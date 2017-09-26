
#pragma once

#include "common.h"

#define AES_BLOCK_LEN 16

// definition in sha1_16.c
void sha1_16(u8 out[16], const u8 in[16]);

// definition in crypto_*.c
void crypto_init();

void aes_128_ecb_set_key(const u8 *key);
void aes_128_ecb_crypt_1(u8 *out, const u8 *in);
void aes_128_ecb_crypt(u8 *out, const u8 *in, unsigned len);

