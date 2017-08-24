
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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

#ifndef HEXDUMP_BUF_SIZE
#define HEXDUMP_BUF_SIZE 0x100
#endif

static char hexdump_buf[HEXDUMP_BUF_SIZE];
// CAUTION, this always assume you have a buffer big enough
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
