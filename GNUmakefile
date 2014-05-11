CPPFLAGS= -I/usr/local/include -I/opt/local/include -Iother
CFLAGS=   -Wall -Werror -Wno-pointer-sign -Wno-unused-result -O2
LDFLAGS=  -L/usr/local/lib -L/opt/local/lib -lsodium

ifeq ($(shell uname -s),Darwin)
	CPPFLAGS+= -D_NSIG=NSIG -DHAVE_STRLCAT
endif

OBJS= reop.o other/other.o

PREFIX= /usr/local
BINDIR= ${PREFIX}/bin
MANDIR= ${PREFIX}/share/man

.PHONY: all clean install

all: reop

reop: ${OBJS}
	${CC} ${LDFLAGS} ${OBJS} -o reop

clean:
	rm -f ${OBJS} reop

install:
	install -m 755 reop ${BINDIR}
	install -m 644 reop.1 ${MANDIR}/man1
