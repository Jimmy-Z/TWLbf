
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include "utils.h"

int htoi(char a){
	if(a >= '0' && a <= '9'){
		return a - '0';
	}else if(a >= 'a' && a <= 'f'){
		return a - ('a' - 0xa);
	}else if(a >= 'A' && a <= 'F'){
		return a - ('A' - 0xa);
	}else{
		return -1;
	}
}

int hex2bytes(u8 *out, unsigned byte_len, const char *in, int critical){
	if (strlen(in) != byte_len << 1){
		fprintf(stderr, "%s: invalid input length, expecting %u, got %u.\n",
			__FUNCTION__, (unsigned)byte_len << 1, (unsigned)strlen(in));
		assert(!critical);
		return -1;
	}
	for(unsigned i = 0; i < byte_len; ++i){
		int h = htoi(*in++), l = htoi(*in++);
		if(h == -1 || l == -1){
			fprintf(stderr, "%s: invalid input \"%c%c\"\n",
				__FUNCTION__, *(in - 2), *(in - 1));
			assert(!critical);
			return -2;
		}
		*out++ = (h << 4) + l;
	}
	return 0;
}

static char hexdump_buf[HEXDUMP_BUF_SIZE];
// CAUTION, this always assume the buffer is big enough
// it uses a static buffer so the value is only valid until next call
// and of course this is not thread safe
const char *hexdump(const void *b, unsigned l, int space){
	const u8 *p = (u8*)b;
	char *out = hexdump_buf;
	for(unsigned i = 0; i < l; ++i){
		out += sprintf(out, "%02x", *p);
		++p;
		if(space && i < l - 1){
			*out++ = ' ';
		}
	}
	return hexdump_buf;
}

void read_block_from_file(void *out, const char *file_name, size_t offset, size_t size) {
	FILE * f = fopen(file_name, "rb");
	if (f == NULL) {
		fprintf(stderr, "can't read file: %s\n", file_name);
		exit(-1);
	}
	fseek(f, offset, SEEK_SET);
	size_t read = fread(out, 1, size, f);
	if (read != size) {
		fprintf(stderr, "failed to read %u bytes at offset %u from file: %s",
			(unsigned)size, (unsigned)offset, file_name);
		exit(-1);
	}
	fclose(f);
}

// read entire file to memory, don't use it on large files
// the caller is resposible to free the memory
void* read_file(const char *file_name, long *psize) {
	FILE *f = fopen(file_name, "rb");
	if (f == NULL) {
		fprintf(stderr, "can't read file: %s\n", file_name);
		exit(-1);
	}
	fseek(f, 0, SEEK_END);
	*psize = ftell(f);
	// printf("size: %u\n", (unsigned)*psize);
	void *p = malloc(*psize);
	if (p == NULL) {
		fprintf(stderr, "failed to alloc buffer to read %s\n", file_name);
		exit(-2);
	}
	fseek(f, 0, SEEK_SET);
	size_t read = fread(p, 1, *psize, f);
	if (read != *psize) {
		fprintf(stderr, "failed to read entire file %s\n", file_name);
		free(p);
		exit(-1);
	}
	fclose(f);
	return p;
}

void dump_to_file(const char *file_name, const void *buf, size_t len) {
	FILE *f = fopen(file_name, "r");
	if (f != NULL) {
		fclose(f);
		fprintf(stderr, "%s exists, won't overwrite\n", file_name);
		return;
	}
	f = fopen(file_name, "wb");
	if (f == NULL) {
		fprintf(stderr, "can't open file to write: %s\n", file_name);
		return;
	}
	size_t written = fwrite(buf, 1, len, f);
	if (written != len) {
		fprintf(stderr, "failed to write %u bytes to %s\n",
			(unsigned)len, file_name);
	}
	fclose(f);
}

// this stupid thing shares the hexdump_buf with hexdump
const char *to_Mebi(size_t size) {
	if (size % (1024 * 1024)) {
		sprintf(hexdump_buf, "%.2f", (float)(((double)size) / 1024 / 1024));
	} else {
		sprintf(hexdump_buf, "%u", (unsigned)(size >> 20));
	}
	return hexdump_buf;
}

