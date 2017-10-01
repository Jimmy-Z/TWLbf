
#include <stdio.h>
#include <mbedtls/config.h>
#include <mbedtls/version.h>
#include <mbedtls/aes.h>
#include <mbedtls/aesni.h>
#include "crypto.h"

static mbedtls_aes_context ctx_aes;

static int (*p_aes_crypt_ecb)(mbedtls_aes_context*, int, const unsigned char *, unsigned char *) = NULL;

static void (*p_aes_128_ecb_set_key)(const u8 *key) = NULL;

static void aes_128_ecb_set_key_aesni(const u8 *key){
	// mbedtls_aes_setkey_enc(&ctx_aes, key, 128);
	ctx_aes.nr = 10;
	ctx_aes.rk = ctx_aes.buf;
	mbedtls_aesni_setkey_enc((unsigned char *)ctx_aes.rk, key, 128);
}

static void aes_128_ecb_set_key_c(const u8 *key) {
	mbedtls_aes_setkey_enc(&ctx_aes, key, 128);
}

void crypto_init(){
	fputs(MBEDTLS_VERSION_STRING_FULL, stdout);
	mbedtls_aes_init(&ctx_aes);
	// prevent runtime checks
	if(mbedtls_aesni_has_support(MBEDTLS_AESNI_AES)){
		puts(", AES-NI supported");
		p_aes_crypt_ecb = mbedtls_aesni_crypt_ecb;
		p_aes_128_ecb_set_key = aes_128_ecb_set_key_aesni;
	}else {
		puts(", AES-NI not supported");
		p_aes_crypt_ecb = mbedtls_aes_crypt_ecb;
		p_aes_128_ecb_set_key = aes_128_ecb_set_key_c;
	}
	// it will error out but also get aes_gen_tables done
	mbedtls_aes_setkey_enc(&ctx_aes, NULL, 0);
}

void aes_128_ecb_set_key(const u8 *key) {
	p_aes_128_ecb_set_key(key);
}

void aes_128_ecb_crypt_1(u8 *out, const u8 *in){
	p_aes_crypt_ecb(&ctx_aes, MBEDTLS_AES_ENCRYPT, in, out);
}

void aes_128_ecb_crypt(u8 *out, const u8 *in, unsigned len){
	len >>= 4;
	for(unsigned i = 0; i < len; ++i){
		p_aes_crypt_ecb(&ctx_aes, MBEDTLS_AES_ENCRYPT, in, out);
		in += 16;
		out += 16;
	}
}

