
#include <stdio.h>
#include <assert.h>
// #include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include "crypto.h"

static EVP_CIPHER_CTX ctx;

// https://www.openssl.org/docs/man1.0.2/crypto/OPENSSL_VERSION_NUMBER.html
static void print_openssl_version(unsigned ver){
	printf("%01u.%u.%u", ver >> 28, (ver >> 20) & 0xff, (ver >> 12) & 0xff);
	unsigned patch = (ver >> 4) & 0xff;
	if(patch){
		putchar('a' + patch - 1);
	}
	unsigned status = ver & 0xf;
	if(status == 0){
		fputs(" dev", stdout);
	}else if(status == 0xf){
		fputs(" release", stdout);
	}else{
		printf(" beta %u", status);
	}
}

void crypto_init(){
	// look  like they're struggling with the names
	// https://github.com/openssl/openssl/blob/OpenSSL_1_0_2-stable/apps/version.c#L175-L182
	fputs(SSLeay_version(SSLEAY_VERSION), stdout);
	if(SSLeay() != OPENSSL_VERSION_NUMBER){
		fputs(", was linked to ", stdout);
		print_openssl_version(OPENSSL_VERSION_NUMBER);
	}
	putchar('\n');
	puts(SSLeay_version(SSLEAY_CFLAGS));
	EVP_CIPHER_CTX_init(&ctx);
}

/*
void sha1(u8 *out, const u8 *in, unsigned len){
	SHA1(in, len, out);
}
*/

void aes_128_ecb_set_key(const u8 *key){
	assert(EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1);
}

void aes_128_ecb_crypt_1(u8 *out, const u8 *in){
	int len_out;
	assert(EVP_EncryptUpdate(&ctx, out, &len_out, in, 16) == 1);
	assert(len_out == 16);
}

void aes_128_ecb_crypt(u8 *out, const u8 *in, unsigned len){
	int len_out;
	assert(EVP_EncryptUpdate(&ctx, out, &len_out, in, len) == 1);
	assert(len_out == len);
}

