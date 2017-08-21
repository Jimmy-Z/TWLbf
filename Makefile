OBJS = twlbf.o utils.o dsi.o crypto.o
CFLAGS = -Wall -O3 -D__USE_MINGW_ANSI_STDIO=1
OUTPUT = twlbf

$(OUTPUT): $(OBJS)
	$(CC) -o $(OUTPUT) $(OBJS) -lcrypto

clean:
	rm $(OUTPUT) $(OBJS)
