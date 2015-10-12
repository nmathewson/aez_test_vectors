CC=gcc
CFLAGS=-Wall  -fno-strict-aliasing
SOURCE= \
blake2b.c \
encrypt.c \
rijndael-alg-fst.c \
tv.c

HEADERS=\
api.h \
blake2b.h \
rijndael-alg-fst.h

OBJ = blake2b.o encrypt.o rijndael-alg-fst.o tv.o

all: test_vectors tv

test_vectors: tv
	./tv > test_vectors

tv: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o tv

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) tv test_vectors
