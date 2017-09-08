
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "utils.h"
#include "dsi.h"
#include "crypto.h"

const char * const CRYPT = "crypt";
const char * const CRYPT_3DS = "crypt_3ds";
const char * const DECRYPT_MBR = "decrypt_mbr";

const char * const EMMC_CID = "emmc_cid";
const char * const CONSOLE_ID = "console_id";
const char * const CONSOLE_ID_BCD = "console_id_bcd";
const char * const CONSOLE_ID_3DS = "console_id_3ds";

int main(int argc, const char *argv[]){
	if(argc == 6){
		// twlbf crypt(_3ds) [Console ID] [EMMC CID] [offset] [src]
		// twlbf decrypt_mbr [Console ID] [EMMC CID] [in_file] [out_file]
		u8 console_id[8], emmc_cid[16], src[16], offset[2];
		hex2bytes(console_id, 8, argv[2], 1);
		hex2bytes(emmc_cid, 16, argv[3], 1);
		if (!strcmp(argv[1], CRYPT) || !strcmp(argv[1], CRYPT_3DS)) {
			hex2bytes(offset, 2, argv[4], 1);
			hex2bytes(src, 16, argv[5], 1);
		}

		if(!strcmp(argv[1], CRYPT)){
			dsi_aes_ctr_crypt_block(console_id, emmc_cid, offset, src, 0);
		}else if(!strcmp(argv[1], CRYPT_3DS)){
			dsi_aes_ctr_crypt_block(console_id, emmc_cid, offset, src, 1);
		}else if(!strcmp(argv[1], DECRYPT_MBR)){
			dsi_decrypt_mbr(console_id, emmc_cid, argv[4], argv[5]);
		}else{
			puts("invalid parameters");
		}
	}else if(argc == 7){
		// twlbf emmc_cid/console_id(_bcd) [Console ID] [EMMC CID] [offset] [src] [verify]
		u8 console_id[8], emmc_cid[16], src[16], verify[16], offset[2];
		hex2bytes(console_id, 8, argv[2], 1);
		hex2bytes(emmc_cid, 16, argv[3], 1);
		hex2bytes(offset, 2, argv[4], 1);
		hex2bytes(src, 16, argv[5], 1);
		hex2bytes(verify, 16, argv[6], 1);

		if(!strcmp(argv[1], "emmc_cid")){
			dsi_brute_emmc_cid(console_id, emmc_cid, offset, src, verify);
		}else if(!strcmp(argv[1], "console_id")){
			dsi_brute_console_id(console_id, emmc_cid, offset, src, verify, NORMAL);
		}else if(!strcmp(argv[1], "console_id_bcd")){
			dsi_brute_console_id(console_id, emmc_cid, offset, src, verify, BCD);
		}else if(!strcmp(argv[1], "console_id_3ds")){
			dsi_brute_console_id(console_id, emmc_cid, offset, src, verify, CTR);
		}else{
			puts("invalid parameters");
		}
	}else if(argc >= 2 && !strcmp(argv[1], "crypto_test")){
		u8 key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
		u8 src[32] = {8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8,
			1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1};
		u8 out[32];

		crypto_init();

		aes_128_ecb_set_key(key);

		aes_128_ecb_crypt(out, src, 16);
		aes_128_ecb_crypt(out + 16, src + 16, 16);
		puts(hexdump(out, 32, 1));

		aes_128_ecb_crypt(out, src, 32);
		puts(hexdump(out, 32, 1));
	}else{
		puts("invalid parameters");
	}
#ifdef _WIN32
	system("pause");
#endif
	return 0;
}

