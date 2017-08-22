
#include <stdio.h>
#include "mbedtls/config.h"
#include "mbedtls/version.h"
#include "mbedtls/sha1.h"
#include "mbedtls/aes.h"
#include "mbedtls/aesni.h"
#include "crypto.h"

void sha1(u8 *out, const u8 *in, unsigned len){
	mbedtls_sha1(in, len, out);
}

static mbedtls_aes_context ctx;

int (*p_aes_crypt_ecb)(mbedtls_aes_context*, int, const unsigned char *, unsigned char *) = NULL;

void crypto_init(){
	fputs(MBEDTLS_VERSION_STRING_FULL, stdout);
	if(mbedtls_aesni_has_support(MBEDTLS_AESNI_AES) && mbedtls_aesni_has_support(MBEDTLS_AESNI_CLMUL)){
		puts(", AES-NI supported");
		p_aes_crypt_ecb = mbedtls_aesni_crypt_ecb;
	}else{
		puts(", AES-NI not supported");
		p_aes_crypt_ecb = mbedtls_aes_crypt_ecb;
	}
	mbedtls_aes_init(&ctx);
}

void aes_128_ecb_set_key(const u8 *key){
	mbedtls_aes_setkey_enc(&ctx, key, 128);
}

void aes_128_ecb_crypt_1(u8 *out, const u8 *in){
	p_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
}

void aes_128_ecb_crypt(u8 *out, const u8 *in, unsigned len){
	len >>= 4;
	for(unsigned i = 0; i < len; ++i){
		p_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
		in += 16;
		out += 16;
	}
}
