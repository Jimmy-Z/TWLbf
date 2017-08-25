
#pragma once

/* if you want to use mbedtls, copy these files over:
 * mbedtls/aes.h mbedtls/aesni.h mbedtls/version.h
 * aes.c aesni.c
 * and make twlbf_mbedtls
 */
#define MBEDTLS_AES_C
#define MBEDTLS_AESNI_C
#define MBEDTLS_HAVE_X86_64
#define MBEDTLS_HAVE_ASM
