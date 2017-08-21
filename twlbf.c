
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "utils.h"
#include "dsi.h"
#include "crypto.h"

int main(int argc, const char *argv[]){
	if(argc == 6 && !(strcmp(argv[1], "dec"))){
		// twlbf dec [SRC_BLOCK] [OFFSET] [Console ID] [EMMC CID]
		u8 src[16], offset[2], console_id[8], emmc_cid[16];
		hex2bytes(src, 16, argv[2], 1, 1);
		hex2bytes(offset, 2, argv[3], 1, 1);
		hex2bytes(console_id, 8, argv[4], 1, 1);
		hex2bytes(emmc_cid, 16, argv[5], 1, 1);

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
		u8 out[16];
		aes_128_ecb_init();
		dsi_aes_ctr_crypt_block(out, src, (u8*)key, emmc_cid_sha1, u16be(offset));
		printf("Decrypted:   ");
		hexdump(out, 16, 1);
	}else{
		fprintf(stderr, "invalid parameters\n");
		// aes_128_ecb test
		u8 test_src[16] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
		u8 test_key[16] = {8, 7, 6, 5, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1};
		u8 out[16];

		aes_128_ecb_init();
		aes_128_ecb_set_key(test_key);

		// so as expected this is reusable
		aes_128_ecb_crypt(out, test_src);
		printf("aes_128_ecb test 0: ");
		hexdump(out, 16, 1);
		aes_128_ecb_crypt(out, test_key);
		printf("aes_128_ecb test 1: ");
		hexdump(out, 16, 1);
	}
}
