/*
 * Copyright (c) 2014 Ted Unangst <tedu@tedunangst.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <sys/stat.h>

#include <netinet/in.h>
#include <resolv.h>

#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>

#include "reop.h"

static void
usage(const char *error)
{
	if (error)
		fprintf(stderr, "%s\n", error);
	fprintf(stderr, "Usage:\n"
"  reop -G [-n] [-i identity] [-p public-key-file -s secret-key-file]\n"
"  reop -D [-i identity] [-p public-key-file -s secret-key-file] -m message-file [-x ciphertext-file]\n"
"  reop -E [-1b] [-i identity] [-p public-key-file -s secret-key-file] -m message-file [-x ciphertext-file]\n"
"  reop -S [-e] [-x signature-file] -s secret-key-file -m message-file\n"
"  reop -V [-eq] [-x signature-file] -p public-key-file -m message-file\n"
	    );
	exit(1);
}

int
main(int argc, char **argv)
{
	const char *pubkeyfile = NULL, *seckeyfile = NULL, *msgfile = NULL,
	    *xfile = NULL;
	char xfilebuf[1024];
	const char *ident = NULL;
	int ch, rounds;
	int embedded = 0;
	int quiet = 0;
	int v1compat = 0;
	opt_binary binary = { 0 };
	enum {
		NONE,
		DECRYPT,
		ENCRYPT,
		GENERATE,
		SIGN,
		VERIFY
	} verb = NONE;

	rounds = 42;

	while ((ch = getopt(argc, argv, "1CDEGSVbei:m:np:qs:x:")) != -1) {
		switch (ch) {
		case '1':
			v1compat = 1;
			break;
		case 'D':
			if (verb)
				usage(NULL);
			verb = DECRYPT;
			break;
		case 'E':
			if (verb)
				usage(NULL);
			verb = ENCRYPT;
			break;
		case 'G':
			if (verb)
				usage(NULL);
			verb = GENERATE;
			break;
		case 'S':
			if (verb)
				usage(NULL);
			verb = SIGN;
			break;
		case 'V':
			if (verb)
				usage(NULL);
			verb = VERIFY;
			break;
		case 'b':
			binary.v = 1;
			break;
		case 'e':
			embedded = 1;
			break;
		case 'i':
			ident = optarg;
			break;
		case 'm':
			msgfile = optarg;
			break;
		case 'n':
			rounds = 0;
			break;
		case 'p':
			pubkeyfile = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 's':
			seckeyfile = optarg;
			break;
		case 'x':
			xfile = optarg;
			break;
		default:
			usage(NULL);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(NULL);

	switch (verb) {
	case ENCRYPT:
	case DECRYPT:
		if (!msgfile)
			usage("You must specify a message-file");
		if (!xfile) {
			if (strcmp(msgfile, "-") == 0)
				usage("must specify encfile with - message");
			if (snprintf(xfilebuf, sizeof(xfilebuf), "%s.enc",
			    msgfile) >= sizeof(xfilebuf))
				errx(1, "path too long");
			xfile = xfilebuf;
		}
		break;
	case SIGN:
	case VERIFY:
		if (!xfile && msgfile) {
			if (strcmp(msgfile, "-") == 0)
				usage("must specify sigfile with - message");
			if (snprintf(xfilebuf, sizeof(xfilebuf), "%s.sig",
			    msgfile) >= sizeof(xfilebuf))
				errx(1, "path too long");
			xfile = xfilebuf;
		}
		break;
	default:
		break;
	}

	switch (verb) {
	case DECRYPT:
		decrypt(pubkeyfile, seckeyfile, msgfile, xfile);
		break;
	case ENCRYPT:
		if (seckeyfile && (!pubkeyfile && !ident))
			usage("specify a pubkey or ident");
		if (pubkeyfile || ident) {
			if (v1compat)
				v1pubencrypt(pubkeyfile, ident, seckeyfile, msgfile, xfile, binary);
			else
				pubencrypt(pubkeyfile, ident, seckeyfile, msgfile, xfile, binary);
		} else
			symencrypt(msgfile, xfile, rounds, binary);
		break;
	case GENERATE:
		if (!ident && !(ident= getenv("USER")))
			ident = "unknown";

		/* can specify none, but not only one */
		if ((!pubkeyfile && seckeyfile) ||
		    (!seckeyfile && pubkeyfile))
			usage("must specify pubkey and seckey");
		/* if none, create ~/.reop */
		if (!pubkeyfile && !seckeyfile) {
			char buf[1024];
			const char *home;

			if (!(home = getenv("HOME")))
				errx(1, "can't find HOME");
			snprintf(buf, sizeof(buf), "%s/.reop", home);
			if (mkdir(buf, 0700) == -1 && errno != EEXIST)
				err(1, "Unable to create ~/.reop");
		}
		generate(pubkeyfile, seckeyfile, rounds, ident);
		break;
	case SIGN:
		if (!msgfile)
			usage("must specify message");
		signfile(seckeyfile, msgfile, xfile, embedded);
		break;
	case VERIFY:
		if (!msgfile && !xfile)
			usage("must specify message or sigfile");
		if (msgfile)
			verifysimple(pubkeyfile, msgfile, xfile, quiet);
		else
			verifyembedded(pubkeyfile, xfile, quiet);
		break;
	default:
		usage(NULL);
		break;
	}

	return 0;
}
