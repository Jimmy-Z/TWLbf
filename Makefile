# for fuck's sake this is still not fixed
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52991
CFLAGS += -mno-ms-bitfields

PNAME = twlbf
OBJS = $(PNAME).o utils.o dsi.o sha1_16.o sector0.o
MBEDTLS_OBJS = aes.o aesni.o
CFLAGS += -std=c11 -Wall -O2

all: $(PNAME)_openssl $(PNAME)_mbedtls

$(PNAME)_openssl: $(OBJS) crypto_openssl_evp.o
	$(CC) -o $@ $^ -lcrypto

$(PNAME)_mbedtls: $(OBJS) crypto_mbedtls.o
	$(CC) --static -o $@ $^ -lmbedcrypto

ticket0: ticket0.o utils.o
	$(CC) --static -o $@ $^ -lmbedcrypto

clean:
	rm $(PNAME)_* ticket0 *.o
