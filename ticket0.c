#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "ticket0.h"
#include "utils.h"
#include "dsi.h"

tmd_header_v0_t tmd;
tmd_content_v0_t tmd_content[0x10000];
ticket_v0_t ticket;

int main(int argc, const char *argv[]) {
	if (argc == 3 && !strcmp(argv[1], "tmd")) {
		read_block_from_file(&tmd, argv[2], 0, sizeof(tmd_header_v0_t));
		printf("Title ID: %016" PRIx64 "\n", u64be(&tmd.title_id));
		printf("Issuer: %s\n", tmd.issuer);
		int num_content = u16be(&tmd.num_content);
		printf("Number of content: %d\n", num_content);
		read_block_from_file(tmd_content, argv[2], sizeof(tmd_header_v0_t), sizeof(tmd_content_v0_t) * num_content);
		for (int i = 0; i < num_content; ++i) {
			printf("Content ID: %08x\n", u32be(&tmd_content[i].content_id));
			printf("index: %d\n", u16be(&tmd_content[i].index));
			printf("type: %d\n", u16be(&tmd_content[i].type));
			printf("size: %" PRIu64 "\n", u64be(&tmd_content[i].size));
		}
	} else if (argc == 3 && !strcmp(argv[1], "tik")) {
		read_block_from_file(&ticket, argv[2], 0, sizeof(ticket_v0_t));
		printf("Title ID: %016" PRIx64 "\n", u64be(&ticket.title_id));
		printf("Issuer: %s\n", ticket.issuer);
	} else {
		printf("invalid arguments\n");
	}
	return 0;
}
