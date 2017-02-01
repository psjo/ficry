CC = gcc
LIBS = `libgcrypt-config --libs` #-lgcrypt
CFLAGS = -g -std=c99 -pedantic -Wall #'libgcrypt-config --cflags'
LDFLAGS = -s ${LIBS}
SRC = aes-crypt.c
OBJ = ${SRC:.c=.o}

all: options fcry

options:
	@echo aes build:
	@echo "CC	= ${CC}"
	@echo "CFLAGS	= ${CFLAGS}"
	@echo "LIBS	= ${LIBS}"
	@echo "SRC	= ${SRC}"

.c.o:
	@echo "CC $<"
	@${CC} -c ${CFLAGS} $<

fcry: ${OBJ}
	@echo "CC -o $@"
	@${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	@echo Cleaning
	@rm -f fcry ${OBJ}

.PHONY: all options clean
