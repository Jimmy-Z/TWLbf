
#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "sector0.h"

// return 1 for valid NCSD header
int parse_ncsd(const u8 sector0[SECTOR_SIZE]) {
	const ncsd_header_t * h = (ncsd_header_t *)sector0;
	if (h->magic == 0x4453434e) {
		printf("NCSD magic found\n");
	} else {
		printf("NCSD magic not found\n");
		return 0;
	}
	printf("size: %d sectors, %s MB\n", h->size, to_Mebi(h->size * SECTOR_SIZE));
	printf("media ID: %s\n", hexdump(&h->media_id, 8, 0));

	for (unsigned i = 0; i < NCSD_PARTITIONS; ++i) {
		unsigned fs_type = h->fs_types[i];
		if (fs_type == 0) {
			break;
		}
		const char *s_fs_type;
		switch (fs_type) {
			case 1:
				s_fs_type = "Normal";
				break;
			case 3:
				s_fs_type = "FIRM";
				break;
			case 4:
				s_fs_type = "AGB_FIRM save";
				break;
			default:
				printf("invalid partition type %d\n", fs_type);
				return 0;
		}
		// yes I use MB for "MiB", bite me
		printf("partition %u, %s, crypt: %u, offset: 0x%08x, length: 0x%08x(%s MB)\n",
			i, s_fs_type, h->crypt_types[i],
			h->partitions[i].offset, h->partitions[i].length, to_Mebi(h->partitions[i].length * SECTOR_SIZE));
	}
	return 1;
}

static const mbr_partition_t ptable_DSi[MBR_PARTITIONS] = {
	{0, {3, 24, 4}, 6, {15, 224, 59}, 0x00000877, 0x00066f89},
	{0, {2, 206, 60}, 6, {15, 224, 190}, 0x0006784d, 0x000105b3},
	{0, {2, 222, 191}, 1, {15, 224, 191}, 0x00077e5d, 0x000001a3},
	{0, {0, 0, 0}, 0, {0, 0, 0}, 0, 0}
};

static const mbr_partition_t ptable_3DS[MBR_PARTITIONS] = {
	{0, {4, 24, 0}, 6, {1, 160, 63}, 0x00000097, 0x00047da9},
	{0, {4, 142, 64}, 6, {1, 160, 195}, 0x0004808d, 0x000105b3},
	{0, {0, 0, 0}, 0, {0, 0, 0}, 0, 0},
	{0, {0, 0, 0}, 0, {0, 0, 0}, 0, 0}
};

// return 1 for valid MBR
int parse_mbr(const u8 sector0[SECTOR_SIZE], int is3DS, int verbose) {
	const mbr_t *m = (mbr_t*)sector0;
	const mbr_partition_t *ref_ptable; // reference partition table
	int ret = 1;
	if (m->boot_signature_0 != 0x55 || m->boot_signature_1 != 0xaa) {
		printf("invalid boot signature(0x55, 0xaa)\n");
		ret = 0;
	}
	if (!is3DS) {
		for (unsigned i = 0; i < sizeof(m->bootstrap); ++i) {
			if (m->bootstrap[i]) {
				printf("bootstrap on DSi should be all zero\n");
				ret = 0;
				break;
			}
		}
		ref_ptable = ptable_DSi;
	} else {
		ref_ptable = ptable_3DS;
	}
	if (memcmp(ref_ptable, sector0 + MBR_BOOTSTRAP_SIZE,
		sizeof(mbr_partition_t) * MBR_PARTITIONS)) {
		printf("invalid partition table\n");
		ret = 0;
	}
	if (!verbose) {
		return ret;
	}
	for (unsigned i = 0; i < MBR_PARTITIONS; ++i) {
		const mbr_partition_t *rp = &ref_ptable[i]; // reference
		const mbr_partition_t *p = &m->partitions[i];
		if (p->status != rp->status) {
			printf("invalid partition %d status: %02x, should be %02x\n",
				i, p->status, rp->status);
		}
		if (p->type != rp->type) {
			printf("invalid partition %d type: %02x, should be %02x\n",
				i, p->type, rp->type);
		}
		if (memcmp(&p->chs_first, &rp->chs_first, sizeof(chs_t))) {
			printf("invalid partition %d first C/H/S: %d/%d/%d, should be %d/%d/%d\n",
				i, p->chs_first.cylinder, p->chs_first.head, p->chs_first.sector,
				rp->chs_first.cylinder, rp->chs_first.head, rp->chs_first.sector);
		}
		if (memcmp(&p->chs_last, &rp->chs_last, sizeof(chs_t))) {
			printf("invalid partition %d last C/H/S: %d/%d/%d, should be %d/%d/%d\n",
				i, p->chs_last.cylinder, p->chs_last.head, p->chs_last.sector,
				rp->chs_last.cylinder, rp->chs_last.head, rp->chs_last.sector);
		}
		if (p->offset != rp->offset) {
			printf("invalid partition %d LBA offset: 0x%08x, should be 0x%08x\n",
				i, p->offset, rp->offset);
		}
		if (p->length != rp->length) {
			printf("invalid partition %d LBA length: 0x%08x, should be 0x%08x\n",
				i, p->length, rp->length);
		}
		printf("status: %02x, type: %02x, offset: 0x%08x, length: 0x%08x(%s MB)\n"
			"\t C/H/S: %u/%u/%u - %u/%u/%u\n",
			p->status, p->type, p->offset, p->length, to_Mebi(p->length * SECTOR_SIZE),
			p->chs_first.cylinder, p->chs_first.head, p->chs_first.sector,
			p->chs_last.cylinder, p->chs_last.head, p->chs_last.sector);
	}
	return ret;
}
