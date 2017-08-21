
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "crypto.h"
#include "utils.h"

void sha1(u8 *out, const u8 *in, size_t len){
	SHA1(in, len, out);
}

static EVP_CIPHER_CTX *ctx;

void aes_128_ecb_init(){
	ctx = EVP_CIPHER_CTX_new();
	if(!ctx){
		fprintf(stderr, "%s: EVP_CIPHER_CTX_new() failed\n", __FUNCTION__);
		exit(-1);
	}
}

void aes_128_ecb_set_key(const u8 *key){
	if(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1){
		fprintf(stderr, "%s: EVP_EncryptInit_ex() failed\n", __FUNCTION__);
		exit(-1);
	}
}

void aes_128_ecb_crypt(u8 *out, const u8 *in){
	int len_out;
	if(EVP_EncryptUpdate(ctx, out, &len_out, in, 16) != 1){
		fprintf(stderr, "%s: EVP_EncryptUpdate() failed\n", __FUNCTION__);
		exit(-1);
	}
	if(EVP_EncryptFinal_ex(ctx, out + len_out, &len_out) != 1){
		fprintf(stderr, "%s: EVP_EncryptFinal_ex() failed\n", __FUNCTION__);
		exit(-1);
	}
}
