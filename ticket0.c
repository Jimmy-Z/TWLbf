#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <mbedtls/sha1.h>
#include "ticket0.h"
#include "utils.h"
#include "dsi.h"

int main(int argc, const char *argv[]) {
	if (argc == 3 && !strcmp(argv[1], "tmd")) {
		tmd_header_v0_t *tmd;
		tmd_content_v0_t *tmd_content;
		tmd = malloc(sizeof(tmd_header_v0_t));
		read_block_from_file(tmd, argv[2], 0, sizeof(tmd_header_v0_t));
		printf("Title ID: %016" PRIx64 "(%c%c%c%c)\n", u64be(tmd->title_id),
			tmd->title_id[4], tmd->title_id[5], tmd->title_id[6], tmd->title_id[7]);
		printf("Issuer: %s\n", tmd->issuer);
		printf("public save: %u\n", u32be(tmd->public_save_size));
		printf("private save: %u\n", u32be(tmd->private_save_size));
		int num_content = u16be(tmd->num_content);
		printf("Number of content: %d\n", num_content);
		assert(num_content > 0);
		tmd_content = malloc(sizeof(tmd_content_v0_t) * num_content);
		read_block_from_file(tmd_content, argv[2], sizeof(tmd_header_v0_t), sizeof(tmd_content_v0_t) * num_content);
		for (int i = 0; i < num_content; ++i) {
			uint32_t content_id = u32be(tmd_content[i].content_id);
			uint64_t size = u64be(tmd_content[i].size);
			printf("=== Content ID: %08x ===\n", content_id);
			printf("index: %d\n", u16be(tmd_content[i].index));
			printf("type: %d\n", u16be(tmd_content[i].type));
			printf("size: %u\n", (unsigned)size);
			// read content
			unsigned actual_size;
			char name[16];
			sprintf(name, "%08x.app", content_id);
			void *c = read_file(name, &actual_size);
			if (actual_size != size) {
				printf("size mismatch, expecting %u, got %u\n", (unsigned)size, actual_size);
			} else {
				printf("size match\n");
			}
			// check content sha1
			unsigned char sha1[20];
			mbedtls_sha1(c, actual_size, sha1);
			if (memcmp(sha1, tmd_content[i].sha1, 20) != 0) {
				printf("sha1 mismatch, expecting:\n");
				print_hex(tmd_content[i].sha1, 20);
				printf("got:\n");
				print_hex(sha1, 20);
			} else {
				printf("sha1 verified\n");
			}
			free(c);
		}
		free(tmd);
		free(tmd_content);
	} else if (argc == 3 && !strcmp(argv[1], "tik")) {
		ticket_v0_t *ticket = malloc(sizeof(ticket_v0_t));
		read_block_from_file(ticket, argv[2], 0, sizeof(ticket_v0_t));
		printf("Title ID: %016" PRIx64 "\n", u64be(ticket->title_id));
		printf("Issuer: %s\n", ticket->issuer);
		free(ticket);
	} else {
		printf("invalid arguments\n");
	}
	return 0;
}
