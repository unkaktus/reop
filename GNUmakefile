CPPFLAGS= -I/usr/local/include -I/opt/local/include -Iother -D_GNU_SOURCE
CFLAGS=   -std=c99 -Wall -Werror -Wno-pointer-sign -Wno-unused-result -O2
LDFLAGS=  -L/usr/local/lib -lsodium

ifeq ($(shell uname -s),Darwin)
	CPPFLAGS+= -D_NSIG=NSIG -DHAVE_STRLCAT
endif

OBJS= reop.o other/other.o main.o

PREFIX= /usr/local
BINDIR= ${PREFIX}/bin
MANDIR= ${PREFIX}/share/man

.PHONY: all clean install

all: reop

reop: ${OBJS}
	${CC} ${OBJS} -o reop ${LDFLAGS}

clean:
	rm -f ${OBJS} reop

install:
	install -m 755 reop ${BINDIR}
	install -m 644 reop.1 ${MANDIR}/man1
