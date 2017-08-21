
#pragma once

#include "common.h"

u64 u64be(u8 *in);
u32 u32be(u8 *in);
u16 u16be(u8 *in);
void byte_reverse_16(u8 *out, const u8 *in);

int hex2bytes(u8 *out, size_t byte_len, const char *in, int verbose, int critical);

void hexdump(const void *a, size_t l, int space);
