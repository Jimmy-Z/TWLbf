
#pragma once

#include "common.h"

#ifndef HEXDUMP_BUF_SIZE
#define HEXDUMP_BUF_SIZE 0x100
#endif

int hex2bytes(u8 *out, unsigned byte_len, const char *in, int critical);

const char * hexdump(const void *a, unsigned l, int space);

void read_block_from_file(void *out, const char *file_name, size_t offset, size_t size);

void dump_to_file(const char *file_name, const void *buf, size_t len);

const char * to_Mebi(size_t size);
