PNAME = twlbf
OBJS = $(PNAME).o utils.o dsi.o sha1_16.o sector0.o
MBEDTLS_OBJS = aes.o aesni.o
CFLAGS += -std=c11 -Wall -O2

all: $(PNAME)_openssl $(PNAME)_mbedtls

$(PNAME)_openssl: $(OBJS) crypto_openssl_evp.o
	$(CC) -o $@ $^ -lcrypto

$(PNAME)_mbedtls: $(OBJS) $(MBEDTLS_OBJS) crypto_mbedtls.o
	$(CC) -o $@ $^

clean:
	rm $(PNAME)_* *.o

