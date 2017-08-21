PNAME = twlbf
OBJS = $(PNAME).o utils.o dsi.o
MBEDTLS_OBJS = sha1.o aes.o aesni.o
CFLAGS = -std=c99 -Wall -O3 -D__USE_MINGW_ANSI_STDIO=1

$(PNAME)_openssl_evp: $(OBJS) crypto_openssl_evp.o
	$(CC) -o $@ $^ -lcrypto

$(PNAME)_mbedtls: $(OBJS) $(MBEDTLS_OBJS) crypto_mbedtls.o
	$(CC) -o $@ $^

clean:
	rm $(PNAME)_openssl_evp $(PNAME)_mbedtls $(OBJS)
