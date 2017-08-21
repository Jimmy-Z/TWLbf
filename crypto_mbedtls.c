
#include <stdio.h>
#include "mbedtls/config.h"
#include "mbedtls/sha1.h"
#include "mbedtls/aes.h"
#include "mbedtls/aesni.h"
#include "crypto.h"

void sha1(u8 *out, const u8 *in, size_t len){
	mbedtls_sha1(in, len, out);
}

static mbedtls_aes_context ctx;

void aes_128_ecb_init(){
	if(mbedtls_aesni_has_support(MBEDTLS_AESNI_AES) && mbedtls_aesni_has_support(MBEDTLS_AESNI_CLMUL)){
		printf("AES-NI supported\n");
	}else{
		printf("AES-NI not supported\n");
		exit(0);
	}
	mbedtls_aes_init(&ctx);
}

void aes_128_ecb_set_key(const u8 *key){
	mbedtls_aes_setkey_enc(&ctx, key, 128);
}

void aes_128_ecb_crypt(u8 *out, const u8 *in){
	mbedtls_aesni_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
}
