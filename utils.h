
#pragma once

#include "common.h"

int hex2bytes(u8 *out, unsigned byte_len, const char *in, int critical);

const char * hexdump(const void *a, unsigned l, int space);
