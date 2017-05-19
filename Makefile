CC = gcc
LIBS = `libgcrypt-config --libs` #-lgcrypt
CFLAGS = -std=c99 -pedantic -Wall #'libgcrypt-config --cflags'
LDFLAGS = -s ${LIBS}
SRC = aes-crypt.c
OBJ = ${SRC:.c=.o}
HEADER = ${SRC:.c=.h}

all: options ficry

options:
	@echo ficry build:
	@echo "CC	= ${CC}"
	@echo "CFLAGS	= ${CFLAGS}"
	@echo "LIBS	= ${LIBS}"
	@echo "SRC	= ${SRC}"

.c.o:
	@echo "CC $<"
	@${CC} -c ${CFLAGS} $<

ficry: ${OBJ} ${HEADER}
	@echo "CC -o $@"
	@${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	@echo Cleaning
	@rm -f ficry ${OBJ}

.PHONY: all options clean
