#pragma once

#include <assert.h>
#include "common.h"

// https://3dbrew.org/wiki/NCSD#NCSD_header

#define SECTOR_SIZE 0x200

#define NCSD_PARTITIONS 8

#ifdef _MSC_VER
#pragma pack(push, 1)
#define PACKED
#elif defined __GNUC__
#define PACKED __attribute__ ((__packed__))
#endif

typedef struct {
	u32 offset;
	u32 length;
} PACKED ncsd_partition_t;

typedef struct {
	u8 signature[0x100];
	u32 magic;
	u32 size;
	u64 media_id;
	u8 fs_types[NCSD_PARTITIONS];
	u8 crypt_types[NCSD_PARTITIONS];
	ncsd_partition_t partitions[NCSD_PARTITIONS];
} PACKED ncsd_header_t;

typedef struct {
	u8 head;
	u8 sector;
	u8 cylinder;
} PACKED chs_t;

typedef struct {
	u8 status;
	chs_t chs_first;
	u8 type;
	chs_t chs_last;
	u32 offset;
	u32 length;
} PACKED mbr_partition_t;

#define MBR_PARTITIONS 4
// or 446 in decimal, all zero on DSi in all my samples
#define MBR_BOOTSTRAP_SIZE 0x1be

typedef struct {
	u8 bootstrap[MBR_BOOTSTRAP_SIZE];
	mbr_partition_t partitions[MBR_PARTITIONS];
	u8 boot_signature_0;
	u8 boot_signature_1;
} PACKED mbr_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif
#undef PACKED


static_assert(sizeof(ncsd_header_t) == 0x160, "sizeof(ncsd_header_t) should equal 0x160");
static_assert(sizeof(mbr_t) == SECTOR_SIZE, "sizeof(mbr_t) should equal 0x200");

int parse_ncsd(const u8 sector0[SECTOR_SIZE]);

int parse_mbr(const u8 sector0[SECTOR_SIZE], int is3DS, int verbose);
