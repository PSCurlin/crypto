CC = gcc
CCFLAGS = -Wall -O0 -g
LDFLAGS = -lcrypto

SOURCES = $(wildcard *.c)
BINARIES = $(SOURCES:.c=)

all: $(SOURCES:.c=)

%: %.c
	$(CC) $(CCFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BINARIES)