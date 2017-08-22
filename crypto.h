
#pragma once

#include "common.h"

void sha1(u8 *out, const u8 *in, unsigned len);

void crypto_init();
void aes_128_ecb_set_key(const u8 *key);
void aes_128_ecb_crypt_1(u8 *out, const u8 *in);
void aes_128_ecb_crypt(u8 *out, const u8 *in, unsigned len);
