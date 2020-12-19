# CFLAGS=-O2 -std=c99 -Wall
CFLAGS=-O2 -std=c99
OPTFLAGS=-s -DUSE_SPLICE
LDFLAGS=
all: clean proxy

proxy:
	gcc $(CFLAGS) $(OPTFLAGS) -o proxy proxy.c $(LDFLAGS)
clean:
	rm -f proxy proxy.exe./proxy