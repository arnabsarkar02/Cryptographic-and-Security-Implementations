CC      ?= gcc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Wpedantic
SRC     = keccak.c mlkem.c

all: test demo

test: test.c $(SRC) keccak.h mlkem.h
	$(CC) $(CFLAGS) -o $@ test.c $(SRC)

demo: demo.c $(SRC) keccak.h mlkem.h
	$(CC) $(CFLAGS) -o $@ demo.c $(SRC)

check: test
	./test

clean:
	rm -f test demo

.PHONY: all check clean
