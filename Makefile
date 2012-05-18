CC=CLANG
all:
	CC -lpcap -g send.c main.c -o arpping
