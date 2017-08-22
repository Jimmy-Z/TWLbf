
#pragma once

/* if you want to use mbedtls, copy these files over:
 * mbedtls/aes.h mbedtls/aesni.h mbedtls/sha1.h mbedtls/version.h
 * aes.c aesni.c sha1.c
 * and make twlbf_mbedtls
 */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_AESNI_C
#define MBEDTLS_AES_C
#define MBEDTLS_SHA1_C

#include "check_config.h"
