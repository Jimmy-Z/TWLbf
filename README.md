# TWLbf
DSi Console ID or EMMC CID brute-force

### Download
Build on Linux requires OpenSSL headers.

There're two build targets one of them linked with OpenSSL
and the other linked with mbed TLS.

Prebuilt Windows x86_64 binaries at [release page](https://github.com/Jimmy-Z/TWLbf/releases).

The Windows version linked with OpenSSL requires libeay32.dll to run,
I suggest you get it from [here](https://indy.fulgan.com/SSL/).

### Usage
- (de/en)crypt a single block(as in AES block, not NAND block):

	`twlbf crypt [Console ID] [EMMC CID] [src] [offset]`

	- Console ID, 8 bytes, hex string, should be 16 characters long.
	- EMMC CID, 16 bytes, hex string.
	- src, 16 bytes, hex string.
	- offset, 2 bytes, hex string, beware this is block offset.

	AES-CTR is symmetric so encrypt and decrypt is the same thing.

	example: decrypt a block at 0x1f0(in byte offset):
	````
	twlbf crypt 08a1522617110121 ab6778e02d034d303046504100001500 \
		1ced45c75e810bb6b51a5318e0fc5eee 001f
	````
	the result should be `000000000000000000000000000055aa`

- brute force by providing a known block to verify against:

	`twlbf emmc_cid [Console ID] [EMMC CID] [src] [verify] [offset]`

	`twlbf console_id [Console ID] [EMMC CID] [src] [verify] [offset]`

	`twlbf console_id_bcd [Console ID] [EMMC CID] [src] [verify] [offset]`

	- verify, 16 bytes, hex string.

	when bruting EMMC CID, the EMMC CID you provided was used as a template.

	when bruting Console ID, the Console ID you provided was used as a template.

	the [_bcd variant loops through 0\~9 instead of 0\~0xf](http://problemkaputt.de/gbatek.htm#dsiconsoleids).

	usually you should read 16 bytes from EMMC dump at offset 0x1f0 as [src],
	use `000000000000000000000000000055aa` as [verify], and `001f` as [offset].

### some notes
OpenSSL and mbed TLS can both benefit from AES-NI,
particularly OpenSSL AES can be 5 times faster with that.

EMMC CID brute forcing can be optimized to do AES on large blocks,
for that kind of work OpenSSL's AES-NI implementation is about 1.8x faster than mbed TLS,
overall speed improvement is about 1.4x due to SHA1 costing most of the CPU time.
OpenSSL SHA1 is also a bit faster than mbed TLS.

Console ID brute forcing unfortunately can't be optimized that way,
we're forced to do lots of 16 byte AES operations,
this time mbed TLS shines for having a very light interface.
overall it is about 2.5x faster than OpenSSL build.

### Thanks:
- Martin Korth for [GBATEK](http://problemkaputt.de/gbatek.htm)
- Wulfystylez/WinterMute for [TWLTool](https://github.com/WinterMute/twltool)
