CC=CLANG
all:
	CC -std=c99 -lpcap -g send.c main.c -o arpping
