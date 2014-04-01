
CC=cc
CFLAGS=-Wall -I/usr/local/include -O2
CFLAGS+=-Werror
LDFLAGS=-lutil -L/usr/local/lib -lsodium

SRCS=reop.c

OBJS=${SRCS:S/.c/.o/}

reop: pretest ${OBJS}
	${CC} ${OBJS} ${LDFLAGS} -o reop

clean:
	rm -f ${OBJS} reop

pretest:
	@[ `uname` = "OpenBSD" ] || { echo Use the other Makefile; false; }

.SUFFIXES: .c .o
.c.o:
	${CC} ${CFLAGS} -c $< -o $@

