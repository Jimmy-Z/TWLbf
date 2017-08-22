
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "utils.h"
#include "dsi.h"
#include "crypto.h"

int main(int argc, const char *argv[]){
	if(argc == 6 && !strcmp(argv[1], "crypt")){
		// twlbf crypt [Console ID] [EMMC CID] [src] [offset]
		u8 console_id[8], emmc_cid[16], src[16], offset[2];
		hex2bytes(console_id, 8, argv[2], 1);
		hex2bytes(emmc_cid, 16, argv[3], 1);
		hex2bytes(src, 16, argv[4], 1);
		hex2bytes(offset, 2, argv[5], 1);

		dsi_aes_ctr_crypt_block(console_id, emmc_cid, src, offset);
	}else if(argc == 7 && !strcmp(argv[1], "emmc_cid")){
		// twlbf emmc_cid [Console ID] [EMMC CID template] [src] [verify] [offset]
		u8 console_id[8], emmc_cid[16], src[16], ver[16], offset[2];
		hex2bytes(console_id, 8, argv[2], 1);
		hex2bytes(emmc_cid, 16, argv[3], 1);
		hex2bytes(src, 16, argv[4], 1);
		hex2bytes(ver, 16, argv[5], 1);
		hex2bytes(offset, 2, argv[6], 1);

		dsi_brute_emmc_cid(console_id, emmc_cid, src, ver, offset);
	}else{
		// aes_128_ecb test
		u8 test_src[16] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
		u8 test_key[16] = {8, 7, 6, 5, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1};
		u8 out[16];

		aes_128_ecb_init();

		aes_128_ecb_set_key(test_key);

		aes_128_ecb_crypt(out, test_src);
		fputs("aes_128_ecb test 0: ", stdout);
		hexdump(out, 16, 1);

		/*
		aes_128_ecb_set_key(test_key);
		// so as expected this is reusable
		aes_128_ecb_crypt(out, test_key);
		fputs("aes_128_ecb test 1: ", stdout);
		hexdump(out, 16, 1);
		*/
	}
}
