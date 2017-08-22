# TWLbf
DSi Console ID or EMMC CID brute-force

### Usage
- (de/en)crypt a single block(as in AES block, not NAND block):

	`twlbf crypt [Console ID] [EMMC CID] [src] [offset]`

	- Console ID, 8 bytes, hex string, should be 16 characters long.
	- EMMC CID, 16 bytes, hex string.
	- src, 16 bytes, hex string.
	- offset, 2 bytes, hex string, beware this is block offset.

	AES-CTR is symmetric so encrypt and decrypt is the same thing.

	example: decrypt a block at 0x1f0 in byte offset:
	````
	twlbf crypt 08a1522617110121 ab6778e02d034d303046504100001500 \
		1ced45c75e810bb6b51a5318e0fc5eee 001f
	````
	the result should be `000000000000000000000000000055aa`

- brute force by providing a known block to verify against:

	`twlbf emmc_cid [Console ID] [EMMC CID] [src] [verify] [offset]`

	`twlbf console_id [Console ID] [EMMC CID] [src] [verify] [offset]`

	- verify, 16 bytes, hex string.

	when brute EMMC CID, the EMMC CID you provided was used as a template.

	when brute Console ID, the Console ID you provided was used as a template.

	usually you should read 16 bytes from EMMC dump at offset 0x1f0 as [src],
	use `000000000000000000000000000055aa` as [verify], and `001f` as [offset].

### Thanks:
- Martin Korth for [GBATEK](http://problemkaputt.de/gbatek.htm)
- Wulfystylz/WinterMute for [TWLTool](https://github.com/WinterMute/twltool)
