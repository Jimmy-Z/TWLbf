PNAME = twlbf
OBJS = $(PNAME).o utils.o dsi.o
MBEDTLS_OBJS = sha1.o aes.o aesni.o
CFLAGS = -std=c11 -Wall -O2 -D__USE_MINGW_ANSI_STDIO=1

all: $(PNAME)_openssl $(PNAME)_mbedtls

$(PNAME)_openssl: $(OBJS) crypto_openssl_evp.o
	$(CC) -o $@ $^ -lcrypto

$(PNAME)_mbedtls: $(OBJS) $(MBEDTLS_OBJS) crypto_mbedtls.o
	$(CC) -o $@ $^

clean:
	rm $(PNAME)_* *.o
