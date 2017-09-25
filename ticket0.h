#pragma once

#include <assert.h>
#include <stdint.h>

#ifdef _MSC_VER
#pragma pack(push, 1)
#define PACKED
#else
#define PACKED __attribute__ ((__packed__))
#endif

// most, if not all, are big endian

// http://dsibrew.org/wiki/Ticket
// http://wiibrew.org/wiki/Ticket
typedef struct {
	uint32_t sig_type;
	uint8_t sig[0x100];
	uint8_t padding0[0x3c];
	uint8_t issuer[0x40];
	uint8_t ecdh[0x3c];
	uint8_t padding1[3];
	uint8_t encrypted_title_key[0x10];
	uint8_t unknown0;
	uint64_t ticket_id;
	uint32_t console_id;
	uint64_t title_id;
	uint8_t unknown1[2];
	uint16_t version;
	uint32_t permitted_titles_mask;
	uint32_t permit_mask;
	uint8_t title_export_allowed;
	uint8_t common_key_index;
	uint8_t unknown[0x30];
	uint8_t content_access_permissions[0x40];
	uint8_t padding2[2];
	uint32_t time_limits[2 * 8];
} PACKED ticket_v0_t;

static_assert(sizeof(ticket_v0_t) == 0x2a4, "invalid sizeof(ticket_v0_t)");

// http://dsibrew.org/wiki/Tmd
// http://wiibrew.org/wiki/Title_metadata
typedef struct {
	uint32_t sig_type;
	uint8_t sig[256];
	uint8_t padding0[60];
	uint8_t issuer[64];
	uint8_t version;
	uint8_t ca_crl_version;
	uint8_t signer_crl_version;
	uint8_t padding1;
	uint64_t system_version;
	uint64_t title_id;
	uint32_t title_type;
	uint16_t group_id;
	uint8_t reserved[62];
	uint32_t access_rights;
	uint16_t title_version;
	uint16_t num_content;
	uint16_t boot_index;
	uint8_t padding2[2];
} PACKED tmd_header_v0_t;

static_assert(sizeof(tmd_header_v0_t) == 0x1e4, "invalid sizeof(tmd_header_v0_t)");

typedef struct {
	uint32_t content_id;
	uint16_t index;
	uint16_t type;
	uint64_t size;
	uint8_t sha1[20];
} PACKED tmd_content_v0_t;

static_assert(sizeof(tmd_content_v0_t) == 36, "invalid sizeof(tmd_contend_v0_t)");

#ifdef _MSC_VER
#pragma pack(pop)
#endif
#undef PACKED
