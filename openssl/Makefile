CC = gcc
CCFLAGS = -Wall -O3
LDFLAGS = -lcrypto

SOURCES = $(wildcard *.c)
BINARIES = $(SOURCES:.c=)

all: $(SOURCES:.c=)

%: %.c
	$(CC) $(CCFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BINARIES)