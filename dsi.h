
#pragma once

#include "common.h"

void dsi_make_key_from_console_id(u64 *key, u64 console_id);

void dsi_aes_ctr_crypt_block(u8 *out, const u8 *in, const u8 *key, const u8 *iv, size_t offset);
