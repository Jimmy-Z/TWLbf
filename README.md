# TWLbf
DSi Console ID or EMMC CID brute-force.
discussion thread on [GBAtemp.net](https://gbatemp.net/threads/481732/)

### Download
Build requires OpenSSL headers.

There're two build targets one of them linked with OpenSSL
and the other linked with mbed TLS.

Prebuilt Windows x86_64 binaries at [release page](https://github.com/Jimmy-Z/TWLbf/releases).

The Windows version linked with OpenSSL requires libeay32.dll to run,
I suggest you get it from [here](https://indy.fulgan.com/SSL/).

### Usage
brute force by providing a known block(as in AES block, not NAND block) to verify against:

````
twlbf emmc_cid [Console ID] [EMMC CID] [offset] [src] [verify]
twlbf console_id [Console ID] [EMMC CID] [offset] [src] [verify]
twlbf console_id_bcd [Console ID] [EMMC CID] [offset] [src] [verify]
````

- Console ID, 8 bytes, hex string, so 16 digits long.
- EMMC CID, 16 bytes, hex string.
- offset, 2 bytes, hex string, beware this is block offset.
- src, 16 bytes, hex string.
- verify, 16 bytes, hex string.

usually you should read 16 bytes from EMMC dump at offset 0x1f0 as [src],
use `000000000000000000000000000055aa` as [verify], and `001f` as [offset].

#### when brute force EMMC CID, the EMMC CID you provided was used as a template.

quote from GBATEK:

> eMMC CID Register
> The CID can be read via SD/MMC commands, and it's also stored at 2FFD7BCh in RAM; the RAM value is little-endian 120bit (ie. without the CRC7 byte), zeropadded to 16-bytes (with 00h in MSB); the value looks as so;

````
MY ss ss ss ss 03 4D 30 30 46 50 41 00 00 15 00  ;DSi CID KMAPF0000M-S998
MY ss ss ss ss 32 57 37 31 36 35 4D 00 01 15 00  ;DSi CID KLM5617EFW-B301
MY ss ss ss ss 03 47 31 30 43 4D 4D 00 01 11 00  ;3DS CID
````

> The value is used to initialize AES_IV register for eMMC encryption/decryption.
> The "MY" byte contains month/year; with Y=0Bh..0Dh for 2008..2010 (Y=0Eh..0Fh would be 2011..2012, but there aren't any known DSi/3DS consoles using that values) (unknown how 2013 and up would be assigned; JEDEC didn't seem to mind to define them yet). The "ss" digits are a 32bit serial number (or actually it looks more like a 32bit random number, not like a incrementing serial value).

TWLbf will brute the 4 random bytes(8 "ss" digits).

#### when bruting Console ID, the Console ID you provided was used as a template.

again quoting from GBATEK:

````
08A20nnnnnnnn1nnh  for DSi
08A19???????????h  for some other DSi
08A15???????????h  for some other DSi
08201nnnnnnnn1nnh  for DSi XL
6B27D20002000000h  for n3DS
````
> The "n" digits appear to be always in BCD range (0..9), the other digits appear to be fixed (on all known consoles; ie. on three DSi's and two DSi XL's and null 3DS's).

The _bcd variant brute the ten BCD digits while the other one brute the lower 4 bytes(later 8 digits).

### Notes
The program runs only one thread, to saturate multi-core processors,
you should start multiple instance on different templates.
more about this on the GBAtemp thread.

OpenSSL and mbed TLS can both benefit from AES-NI,
particularly OpenSSL AES can be 5 times faster with that.

EMMC CID brute forcing can be optimized to do AES on large blocks,
for that kind of work OpenSSL's AES-NI implementation is about 1.8x faster than mbed TLS,
overall speed improvement is not that impressive due to SHA1 costing most of the CPU time.

Console ID brute forcing unfortunately can't be optimized that way,
we're forced to do lots of 16 byte AES operations,
this time mbed TLS shines for having a very light interface.
overall it is about 2.5x faster than OpenSSL build.

### License:
Usually my code is licensed under [WTFPL](https://en.wikipedia.org/wiki/WTFPL),
but this project used code from mbed TLS which is Apache 2.0 license,
so I guess this project becomes Apache 2.0 licensed automatically?
or only the `crypto.c` file is Apache 2.0?
I'm not sure.

### Thanks:
- Martin Korth for [GBATEK](http://problemkaputt.de/gbatek.htm)
- Wulfystylez/WinterMute for [TWLTool](https://github.com/WinterMute/twltool)
