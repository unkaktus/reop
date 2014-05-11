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
#include <err.h>
#include <unistd.h>
#ifdef __OpenBSD__
#include <readpassphrase.h>
#include <util.h>
#else
#include "other.h"
#endif

#include <sodium.h>

/* shorter names */
#define SIGBYTES crypto_sign_ed25519_BYTES
#define SIGSECRETBYTES crypto_sign_ed25519_SECRETKEYBYTES
#define SIGPUBLICBYTES crypto_sign_ed25519_PUBLICKEYBYTES

#define ENCSECRETBYTES crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
#define ENCPUBLICBYTES crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#define ENCNONCEBYTES crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define ENCZEROBYTES crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
#define ENCBOXZEROBYTES crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
#define ENCBOXBYTES (ENCZEROBYTES - ENCBOXZEROBYTES)

#define SYMKEYBYTES crypto_secretbox_xsalsa20poly1305_KEYBYTES
#define SYMNONCEBYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
#define SYMZEROBYTES crypto_secretbox_xsalsa20poly1305_ZEROBYTES
#define SYMBOXZEROBYTES crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
#define SYMBOXBYTES (SYMZEROBYTES - SYMBOXZEROBYTES)

/* magic */
#define SIGALG "Ed"	/* Ed25519 */
#define ENCALG "CS"	/* Curve25519-Salsa20 */
#define EKCALG "eS"	/* ephemeral-curve25519-Salsa20 */
#define SYMALG "SP"	/* Salsa20-Poly1305 */
#define KDFALG "BK"	/* bcrypt kdf */
#define IDENTLEN 64
#define FPLEN 8

/* metadata */
struct seckey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint8_t fingerprint[FPLEN];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t box[SYMNONCEBYTES + SYMBOXBYTES];
	uint8_t sigkey[SIGSECRETBYTES];
	uint8_t enckey[ENCSECRETBYTES];
};

struct pubkey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t fingerprint[FPLEN];
	uint8_t sigkey[SIGPUBLICBYTES];
	uint8_t enckey[ENCPUBLICBYTES];
};

struct sig {
	uint8_t sigalg[2];
	uint8_t fingerprint[FPLEN];
	uint8_t sig[SIGBYTES];
};

struct symmsg {
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t box[SYMNONCEBYTES + SYMBOXBYTES];
};

struct encmsg {
	uint8_t encalg[2];
	uint8_t secfingerprint[FPLEN];
	uint8_t pubfingerprint[FPLEN];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

struct ekcmsg {
	uint8_t ekcalg[2];
	uint8_t pubfingerprint[FPLEN];
	uint8_t pubkey[ENCPUBLICBYTES];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

/* utility */
static void
usage(const char *error)
{
	if (error)
		fprintf(stderr, "%s\n", error);
	fprintf(stderr, "usage:"
	    "\treop -G [-n] [-i ident] [-p pubkey -s seckey]\n"
	    "\treop -A [-i ident] [-p pubkey -s seckey] -m message [-x encfile]\n"
	    "\treop -D [-i ident] [-p pubkey -s seckey] -m message [-x encfile]\n"
	    "\treop -E [-i ident] [-p pubkey -s seckey] -m message [-x encfile]\n"
	    "\treop -S [-e] [-x sigfile] -s seckey -m message\n"
	    "\treop -V [-eq] [-x sigfile] -p pubkey -m message\n"
	    );
	exit(1);
}

static int
xopen(const char *fname, int oflags, mode_t mode)
{
	struct stat sb;
	int fd;

	if (strcmp(fname, "-") == 0) {
		if ((oflags & O_WRONLY))
			fd = dup(STDOUT_FILENO);
		else
			fd = dup(STDIN_FILENO);
		if (fd == -1)
			err(1, "dup failed");
	} else {
		fd = open(fname, oflags, mode);
		if (fd == -1)
			err(1, "can't open %s for %s", fname,
			    (oflags & O_WRONLY) ? "writing" : "reading");
	}
	if (fstat(fd, &sb) == -1 || S_ISDIR(sb.st_mode))
		errx(1, "not a valid file: %s", fname);
	return fd;
}

static void *
xmalloc(size_t len)
{
	void *p;

	p = malloc(len);
	if (!p)
		err(1, "malloc %zu", len);
	return p;
}

static void
xfree(void *p, size_t len)
{
	explicit_bzero(p, len);
	free(p);
}

/*
 * nacl wrapper functions.
 * the nacl API isn't very friendly, requiring the caller to provide padding
 * strange places. these functions workaround that by copying data, which is
 * generally how the nacl included c++ wrappers do things. the message data
 * is operated on separately from any required padding or nonce bytes.
 * wasteful, but convenient.
 */

/*
 * wrapper around crypto_secretbox.
 * operates on buf "in place".
 * box will be used to hold the additional auth tag data.
 */
static void
symencryptmsg(uint8_t *buf, unsigned long long msglen, uint8_t *box, uint8_t *symkey)
{
	uint8_t *cmsg, *msg;

	randombytes(box, SYMNONCEBYTES);

	msg = xmalloc(msglen + SYMZEROBYTES);
	memset(msg, 0, SYMZEROBYTES);
	memcpy(msg + SYMZEROBYTES, buf, msglen);
	cmsg = xmalloc(msglen + SYMZEROBYTES);

	crypto_secretbox_xsalsa20poly1305(cmsg, msg, msglen + SYMZEROBYTES,
	    box, symkey);
	xfree(msg, msglen + SYMZEROBYTES);

	memcpy(box + SYMNONCEBYTES, cmsg + SYMBOXZEROBYTES, SYMBOXBYTES);
	memcpy(buf, cmsg + SYMZEROBYTES, msglen);
	xfree(cmsg, msglen + SYMZEROBYTES);
}

/*
 * wrapper around crypto_secretbox_open.
 * operates on buf "in place".
 * box contains the auth tag data.
 */
static void
symdecryptmsg(uint8_t *buf, unsigned long long msglen, const uint8_t *box,
    uint8_t *symkey)
{
	uint8_t *msg, *cmsg;

	cmsg = xmalloc(msglen + SYMZEROBYTES);
	memset(cmsg, 0, SYMBOXZEROBYTES);
	memcpy(cmsg + SYMBOXZEROBYTES, box + SYMNONCEBYTES, SYMBOXBYTES);
	memcpy(cmsg + SYMZEROBYTES, buf, msglen);
	msg = xmalloc(msglen + SYMZEROBYTES);

	if (crypto_secretbox_xsalsa20poly1305_open(msg, cmsg, msglen +
	    SYMZEROBYTES, box, symkey) == -1)
		errx(1, "decryption failed");
	xfree(cmsg, msglen + SYMZEROBYTES);

	memcpy(buf, msg + SYMZEROBYTES, msglen);
	xfree(msg, msglen + SYMZEROBYTES);
}

/*
 * wrapper around crypto_box.
 * operates on buf "in place".
 * box will be used to hold randomly generated nonce and auth tag data.
 */
static void
pubencryptmsg(uint8_t *buf, unsigned long long msglen, uint8_t *box,
    uint8_t *pubkey, uint8_t *seckey)
{
	uint8_t *cmsg, *msg;

	randombytes(box, ENCNONCEBYTES);

	msg = xmalloc(msglen + ENCZEROBYTES);
	memset(msg, 0, ENCZEROBYTES);
	memcpy(msg + ENCZEROBYTES, buf, msglen);
	cmsg = xmalloc(msglen + ENCZEROBYTES);

	crypto_box_curve25519xsalsa20poly1305(cmsg, msg, msglen + ENCZEROBYTES,
	    box, pubkey, seckey);
	xfree(msg, msglen + SYMZEROBYTES);

	memcpy(box + ENCNONCEBYTES, cmsg + ENCBOXZEROBYTES, ENCBOXBYTES);
	memcpy(buf, cmsg + ENCZEROBYTES, msglen);
	xfree(cmsg, msglen + ENCZEROBYTES);
}

/*
 * wrapper around crypto_box_open.
 * operates on buf "in place".
 * box contains nonce and auth tag data.
 */
static void
pubdecryptmsg(uint8_t *buf, unsigned long long msglen, uint8_t *box,
    uint8_t *pubkey, uint8_t *seckey)
{
	uint8_t *msg, *cmsg;

	cmsg = xmalloc(msglen + ENCZEROBYTES);
	memset(cmsg, 0, ENCBOXZEROBYTES);
	memcpy(cmsg + ENCBOXZEROBYTES, box + ENCNONCEBYTES, ENCBOXBYTES);
	memcpy(cmsg + ENCZEROBYTES, buf, msglen);
	msg = xmalloc(msglen + ENCZEROBYTES);

	if (crypto_box_curve25519xsalsa20poly1305_open(msg, cmsg,
	    msglen + ENCZEROBYTES, box, pubkey, seckey) == -1)
		errx(1, "decryption failed");
	xfree(cmsg, msglen + ENCZEROBYTES);

	memcpy(buf, msg + ENCZEROBYTES, msglen);
	xfree(msg, msglen + ENCZEROBYTES);
}

/*
 * wrapper around crypto_sign to generate detached signatures
 */
static void
signmsg(uint8_t *seckey, uint8_t *msg, unsigned long long msglen,
    uint8_t *sig)
{
	unsigned long long siglen;
	uint8_t *sigbuf;

	sigbuf = xmalloc(msglen + SIGBYTES);
	crypto_sign_ed25519(sigbuf, &siglen, msg, msglen, seckey);
	memcpy(sig, sigbuf, SIGBYTES);
	free(sigbuf);
}

/*
 * wrapper around crypto_sign_open supporting detached signatures
 */
static void
verifymsg(struct pubkey *pubkey, uint8_t *msg, unsigned long long msglen,
    struct sig *sig, int quiet)
{
	uint8_t *sigbuf, *dummybuf;
	unsigned long long siglen, dummylen;

	if (memcmp(pubkey->fingerprint, sig->fingerprint, FPLEN) != 0)
		errx(1, "verification failed: checked against wrong key");

	siglen = SIGBYTES + msglen;
	sigbuf = xmalloc(siglen);
	dummybuf = xmalloc(siglen);
	memcpy(sigbuf, sig->sig, SIGBYTES);
	memcpy(sigbuf + SIGBYTES, msg, msglen);
	if (crypto_sign_ed25519_open(dummybuf, &dummylen, sigbuf, siglen,
	    pubkey->sigkey) == -1)
		errx(1, "signature verification failed");
	if (!quiet)
		printf("Signature Verified\n");
	free(sigbuf);
	free(dummybuf);
}

#ifdef __OpenBSD__
/*
 * override randombytes. this version works in chroot.
 */
void
randombytes(unsigned char *x, unsigned long long xlen)
{
	arc4random_buf(x, xlen);
}
#endif

/* file utilities */
static uint8_t *
readall(const char *filename, unsigned long long *msglenp)
{
	unsigned long long msglen = 0;
	uint8_t *msg = NULL;
	struct stat sb;
	ssize_t x, space;
	int fd;
	const unsigned long long maxmsgsize = 1UL << 30;

	fd = xopen(filename, O_RDONLY | O_NOFOLLOW, 0);
	if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode)) {
		if (sb.st_size > maxmsgsize)
			errx(1, "msg too large in %s", filename);
		space = sb.st_size + 1;
	} else {
		space = 64 * 1024;
	}

	msg = xmalloc(space + 1);
	while (1) {
		if (space == 0) {
			if (msglen * 2 > maxmsgsize)
				errx(1, "msg too large in %s", filename);
			space = msglen;
			if (!(msg = realloc(msg, msglen + space + 1)))
				errx(1, "realloc");
		}
		if ((x = read(fd, msg + msglen, space)) == -1)
			err(1, "read from %s", filename);
		if (x == 0)
			break;
		space -= x;
		msglen += x;
	}

	msg[msglen] = 0;
	close(fd);

	*msglenp = msglen;
	return msg;
}

static void
writeall(int fd, const void *buf, size_t buflen, const char *filename)
{
	ssize_t x;

	while (buflen != 0) {
		x = write(fd, buf, buflen);
		if (x == -1)
			err(1, "write to %s", filename);
		buflen -= x;
		buf = (char *)buf + x;
	}
}

static void
writeb64data(int fd, const char *filename, char *b64)
{
	size_t amt, pos, rem;

	rem = strlen(b64);
	pos = 0;
	while (rem > 0) {
		amt = rem > 76 ? 76 : rem;
		writeall(fd, b64 + pos, amt, filename);
		writeall(fd, "\n", 1, filename);
		pos += amt;
		rem -= amt;
	}
}

static char *
gethomefile(const char *filename)
{
	static char buf[1024];
	struct stat sb;
	const char *home;

	if (!(home = getenv("HOME")))
		errx(1, "can't find HOME");
	snprintf(buf, sizeof(buf), "%s/.reop", home);
	if (stat(buf, &sb) == -1 || !S_ISDIR(sb.st_mode))
		usage("Can't use default files without ~/.reop");
	snprintf(buf, sizeof(buf), "%s/.reop/%s", home, filename);
	return buf;
}

/*
 * parse ident line, return pointer to next line
 */
static char *
readident(char *buf, char *ident)
{
#if IDENTLEN != 64
#error fix sscanf
#endif
	if (sscanf(buf, "ident:%63s", ident) != 1)
		errx(1, "no ident found: %s", buf);
	if (!(buf = strchr(buf + 1, '\n')))
		errx(1, "invalid header");
	return buf + 1;
}

/*
 * try to read a few different kinds of files 
 */
static void
readkeyfile(const char *filename, void *key, size_t keylen, char *ident)
{
	char *keydata;
	unsigned long long keydatalen;
	char *begin, *end;
	const char *beginreop = "-----BEGIN REOP";
	const char *endreop = "-----END REOP";

	keydata = readall(filename, &keydatalen);
	if (strncmp(keydata, beginreop, strlen(beginreop)) != 0 ||
	    !(end = strstr(keydata, endreop)))
		errx(1, "invalid key: %s", filename);
	*end = 0;
	if (!(begin = strchr(keydata, '\n')))
		errx(1, "invalid key: %s", filename);
	begin = readident(begin + 1, ident);
	*end = 0;
	if (b64_pton(begin, key, keylen) != keylen)
		errx(1, "invalid b64 encoding: %s", filename);

	xfree(keydata, keydatalen);
}
/*
 * generate a symmetric encryption key.
 * caller creates and provides salt.
 * if rounds is 0 (no password requested), generates a dummy zero key.
 */
typedef struct { int v; } kdf_allowstdin;
typedef struct { int v; } kdf_confirm;
static void
kdf(uint8_t *salt, size_t saltlen, int rounds, kdf_allowstdin allowstdin,
    kdf_confirm confirm, uint8_t *key, size_t keylen)
{
	char pass[1024];
	int rppflags = RPP_ECHO_OFF;

	if (rounds == 0) {
		memset(key, 0, keylen);
		return;
	}

	if (allowstdin.v && !isatty(STDIN_FILENO))
		rppflags |= RPP_STDIN;
	if (!readpassphrase("passphrase: ", pass, sizeof(pass), rppflags))
		errx(1, "unable to read passphrase");
	if (strlen(pass) == 0)
		errx(1, "please provide a password");
	if (confirm.v && !(rppflags & RPP_STDIN)) {
		char pass2[1024];
		if (!readpassphrase("confirm passphrase: ", pass2,
		    sizeof(pass2), rppflags))
			errx(1, "unable to read passphrase");
		if (strcmp(pass, pass2) != 0)
			errx(1, "passwords don't match");
		explicit_bzero(pass2, sizeof(pass2));
	}
	if (bcrypt_pbkdf(pass, strlen(pass), salt, saltlen, key,
	    keylen, rounds) == -1)
		errx(1, "bcrypt pbkdf");
	explicit_bzero(pass, sizeof(pass));
}

/*
 * read user's pubkeyring file to allow lookup by ident
 */
static const struct pubkey *
findpubkey(const char *ident)
{
	static struct {
		char ident[IDENTLEN];
		struct pubkey pubkey;
	} *keys;
	static int numkeys;
	static int done;
	int i;
	const char *beginreop = "-----BEGIN REOP PUBLIC KEY----\n";
	const char *endreop = "-----END REOP PUBLIC KEY-----\n";

	if (!done) {
		char line[1024];
		char buf[1024];
		int identline;
		FILE *fp;
		
		done = 1;
		fp = fopen(gethomefile("pubkeyring"), "r");
		if (!fp)
			return NULL;

		while (fgets(line, sizeof(line), fp)) {
			buf[0] = 0;
			identline = 1;
			if (line[0] == 0 || line[0] == '\n')
				continue;
			if (strncmp(line, beginreop, strlen(beginreop)) != 0)
				errx(1, "invalid keyring line: %s", line);
			if (!(keys = realloc(keys, sizeof(*keys) * (numkeys + 1))))
				err(1, "realloc keyring");
			while (1) {
				if (!fgets(line, sizeof(line), fp))
					errx(1, "premature pubkeyring EOF");
				if (identline) {
					readident(line, keys[numkeys].ident);
					identline = 0;
					continue;
				}
				if (strncmp(line, endreop, strlen(endreop)) == 0)
					break;
				strlcat(buf, line, sizeof(buf));
			}
			if (b64_pton(buf, (void *)&keys[numkeys].pubkey,
			    sizeof(keys[0].pubkey)) != sizeof(keys[0].pubkey))
				errx(1, "invalid keyring b64 encoding");
			if (numkeys++ > 1000000)
				errx(1, "too many keys");
		}
	}
	for (i = 0; i < numkeys; i++) {
		if (strcmp(ident, keys[i].ident) == 0)
			return &keys[i].pubkey;
	}
	return NULL;
}

/*
 * 1. specified file
 * 2. lookup ident
 * 3. default pubkey file
 */
static void
getpubkey(const char *pubkeyfile, const char *ident, struct pubkey *pubkey)
{
	const struct pubkey *identkey;
	char dummyident[IDENTLEN];

	if (!pubkeyfile && ident) {
		if ((identkey = findpubkey(ident))) {
			*pubkey = *identkey;
			return;
		}
		errx(1, "unable to find a pubkey for %s", ident);
	}
	if (!pubkeyfile)
		pubkeyfile = gethomefile("pubkey");
	readkeyfile(pubkeyfile, pubkey, sizeof(*pubkey), dummyident);
}

/*
 * 1. specified file
 * 2. default seckey file
 */
static void
getseckey(const char *seckeyfile, struct seckey *seckey, char *ident,
    kdf_allowstdin allowstdin)
{
	char dummyident[IDENTLEN];
	uint8_t symkey[SYMKEYBYTES];
	kdf_confirm confirm = { 0 };

	int rounds;

	if (!seckeyfile)
		seckeyfile = gethomefile("seckey");

	readkeyfile(seckeyfile, seckey, sizeof(*seckey), ident ? ident : dummyident);
	if (memcmp(seckey->kdfalg, KDFALG, 2) != 0)
		errx(1, "unsupported KDF");
	rounds = ntohl(seckey->kdfrounds);
	kdf(seckey->salt, sizeof(seckey->salt), rounds,
	    allowstdin, confirm, symkey, sizeof(symkey));
	symdecryptmsg(seckey->sigkey, sizeof(seckey->sigkey) + sizeof(seckey->enckey),
	    seckey->box, symkey);
	explicit_bzero(symkey, sizeof(symkey));
}

/*
 * can write a few different file types
 */
static void
writekeyfile(const char *filename, const char *info, const void *key,
    size_t keylen, const char *ident, int oflags, mode_t mode)
{
	char header[1024];
	char b64[1024];
	int fd;

	fd = xopen(filename, O_CREAT|oflags|O_NOFOLLOW|O_WRONLY, mode);
	snprintf(header, sizeof(header), "-----BEGIN REOP %s-----\nident:%s\n",
	    info, ident);
	writeall(fd, header, strlen(header), filename);
	if (b64_ntop(key, keylen, b64, sizeof(b64)) == -1)
		errx(1, "b64 encode failed");
	writeb64data(fd, filename, b64);
	explicit_bzero(b64, sizeof(b64));
	snprintf(header, sizeof(header), "-----END REOP %s-----\n", info);
	writeall(fd, header, strlen(header), filename);
	close(fd);
}

/*
 * generate two key pairs, one for signing and one for encryption.
 */
static void
generate(const char *pubkeyfile, const char *seckeyfile, int rounds,
    const char *ident)
{
	struct pubkey pubkey;
	struct seckey seckey;
	uint8_t symkey[SYMKEYBYTES];
	uint8_t fingerprint[FPLEN];
	kdf_allowstdin allowstdin = { 1 };
	kdf_confirm confirm = { 1 };

	if (!seckeyfile)
		seckeyfile = gethomefile("seckey");

	memset(&pubkey, 0, sizeof(pubkey));
	memset(&seckey, 0, sizeof(seckey));

	crypto_sign_ed25519_keypair(pubkey.sigkey, seckey.sigkey);
	crypto_box_keypair(pubkey.enckey, seckey.enckey);
	randombytes(fingerprint, sizeof(fingerprint));

	memcpy(seckey.fingerprint, fingerprint, FPLEN);
	memcpy(seckey.sigalg, SIGALG, 2);
	memcpy(seckey.encalg, ENCALG, 2);
	memcpy(seckey.symalg, SYMALG, 2);
	memcpy(seckey.kdfalg, KDFALG, 2);
	seckey.kdfrounds = htonl(rounds);
	randombytes(seckey.salt, sizeof(seckey.salt));

	kdf(seckey.salt, sizeof(seckey.salt), rounds, allowstdin, confirm,
	    symkey, sizeof(symkey));
	symencryptmsg(seckey.sigkey, sizeof(seckey.sigkey) + sizeof(seckey.enckey),
	    seckey.box, symkey);
	explicit_bzero(symkey, sizeof(symkey));

	writekeyfile(seckeyfile, "SECRET KEY", &seckey, sizeof(seckey),
	    ident, O_EXCL, 0600);
	explicit_bzero(&seckey, sizeof(seckey));

	memcpy(pubkey.fingerprint, fingerprint, FPLEN);
	memcpy(pubkey.sigalg, SIGALG, 2);
	memcpy(pubkey.encalg, ENCALG, 2);

	if (!pubkeyfile)
		pubkeyfile = gethomefile("pubkey");
	writekeyfile(pubkeyfile, "PUBLIC KEY", &pubkey, sizeof(pubkey),
	    ident, O_EXCL, 0666);
}

static void
writesignedmsg(const char *filename, struct sig *sig,
    const char *ident, uint8_t *msg, unsigned long long msglen)
{
	char header[1024];
	char b64[1024];
	int fd;

	fd = xopen(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
	snprintf(header, sizeof(header), "-----BEGIN REOP SIGNED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	writeall(fd, msg, msglen, filename);

	snprintf(header, sizeof(header), "-----BEGIN REOP SIGNATURE-----\n"
	    "ident:%s\n", ident);
	writeall(fd, header, strlen(header), filename);
	if (b64_ntop((void *)sig, sizeof(*sig), b64, sizeof(b64)) == -1)
		errx(1, "b64 encode failed");
	writeb64data(fd, filename, b64);
	explicit_bzero(b64, sizeof(b64));
	snprintf(header, sizeof(header), "-----END REOP SIGNED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	close(fd);
}

/*
 * main sign function
 */
static void
sign(const char *seckeyfile, const char *msgfile, const char *sigfile,
    int embedded)
{
	struct sig sig;
	struct seckey seckey;
	char ident[IDENTLEN];
	uint8_t *msg;
	unsigned long long msglen;
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };

	getseckey(seckeyfile, &seckey, ident, allowstdin);

	msg = readall(msgfile, &msglen);

	signmsg(seckey.sigkey, msg, msglen, sig.sig);

	memcpy(sig.fingerprint, seckey.fingerprint, FPLEN);
	memcpy(sig.sigalg, SIGALG, 2);

	explicit_bzero(&seckey, sizeof(seckey));

	if (embedded)
		writesignedmsg(sigfile, &sig, ident, msg, msglen);
	else
		writekeyfile(sigfile, "SIGNATURE", &sig, sizeof(sig), ident,
		    O_TRUNC, 0666);

	free(msg);
}

/*
 * simple case, detached signature
 */
static void
verifysimple(const char *pubkeyfile, const char *msgfile, const char *sigfile,
    int quiet)
{
	char ident[IDENTLEN];
	struct sig sig;
	struct pubkey pubkey;
	unsigned long long msglen;
	uint8_t *msg;

	msg = readall(msgfile, &msglen);

	readkeyfile(sigfile, &sig, sizeof(sig), ident);
	getpubkey(pubkeyfile, ident, &pubkey);

	verifymsg(&pubkey, msg, msglen, &sig, quiet);

	free(msg);
}

/*
 * message followed by signature in one file
 */
static void
verifyembedded(const char *pubkeyfile, const char *sigfile, int quiet)
{
	char ident[IDENTLEN];
	struct sig sig;
	struct pubkey pubkey;
	uint8_t *msg;
	unsigned long long msglen;
	uint8_t *msgdata;
	unsigned long long msgdatalen;
	char *begin, *end;
	const char *beginreopmsg = "-----BEGIN REOP SIGNED MESSAGE-----\n";
	const char *beginreopsig = "-----BEGIN REOP SIGNATURE-----\n";
	const char *endreopmsg = "-----END REOP SIGNED MESSAGE-----\n";

	msgdata = readall(sigfile, &msgdatalen);
	if (strncmp(msgdata, beginreopmsg, strlen(beginreopmsg)) != 0)
 		goto fail;
	begin = msgdata + 36;
	if (!(end = strstr(begin, beginreopsig)))
 		goto fail;
	*end = 0;

	msg = begin;
	msglen = end - begin;

	begin = end + 31;
	if (!(end = strstr(begin, endreopmsg)))
 		goto fail;
	*end = 0;

	begin = readident(begin, ident);
	if (b64_pton(begin, (void *)&sig, sizeof(sig)) != sizeof(sig))
 		goto fail;

	getpubkey(pubkeyfile, ident, &pubkey);

	verifymsg(&pubkey, msg, msglen, &sig, quiet);

	free(msgdata);

	return;
fail:
	errx(1, "invalid signature: %s", sigfile);
}

/*
 * write an reop encrypted message header, followed by base64 data
 */
static void
writeencfile(const char *filename, const void *hdr,
    size_t hdrlen, const char *ident, uint8_t *msg, unsigned long long msglen)
{
	char header[1024];
	char b64[1024];
	char *b64data;
	size_t b64len;
	int fd;
	
	b64len = (msglen + 2) / 3 * 4 + 1;
	b64data = xmalloc(b64len);
	if (b64_ntop(msg, msglen, b64data, b64len) == -1)
		errx(1, "b64 encode failed");

	fd = xopen(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
	snprintf(header, sizeof(header), "-----BEGIN REOP ENCRYPTED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	snprintf(header, sizeof(header), "ident:%s\n", ident);
	writeall(fd, header, strlen(header), filename);
	if (b64_ntop(hdr, hdrlen, b64, sizeof(b64)) == -1)
		errx(1, "b64 encode failed");
	writeb64data(fd, filename, b64);
	explicit_bzero(b64, sizeof(b64));

	snprintf(header, sizeof(header), "-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n");
	writeall(fd, header, strlen(header), filename);
	writeb64data(fd, filename, b64data);
	xfree(b64data, b64len);

	snprintf(header, sizeof(header), "-----END REOP ENCRYPTED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	close(fd);
}

/*
 * encrypt a file using public key cryptography
 * ephemeral key version that discards sender key pair
 */
static void
ekpubencrypt(const char *pubkeyfile, const char *ident, const char *msgfile, const char *encfile)
{
	struct ekcmsg ekcmsg;
	struct pubkey pubkey;
	uint8_t *msg;
	unsigned long long msglen;
	uint8_t enckey[ENCSECRETBYTES];

	getpubkey(pubkeyfile, ident, &pubkey);

	crypto_box_keypair(ekcmsg.pubkey, enckey);

	msg = readall(msgfile, &msglen);

	memcpy(ekcmsg.ekcalg, EKCALG, 2);
	memcpy(ekcmsg.pubfingerprint, pubkey.fingerprint, FPLEN);

	pubencryptmsg(msg, msglen, ekcmsg.box, pubkey.enckey, enckey);

	explicit_bzero(&enckey, sizeof(enckey));

	writeencfile(encfile, &ekcmsg, sizeof(ekcmsg), "<ephemeral>", msg, msglen);

	xfree(msg, msglen);
}

/*
 * encrypt a file using public key cryptography
 * authenticated secret key version
 */
static void
pubencrypt(const char *pubkeyfile, const char *ident, const char *seckeyfile,
    const char *msgfile, const char *encfile)
{
	char myident[IDENTLEN];
	struct encmsg encmsg;
	struct pubkey pubkey;
	struct seckey seckey;
	uint8_t *msg;
	unsigned long long msglen;
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };

	getpubkey(pubkeyfile, ident, &pubkey);

	getseckey(seckeyfile, &seckey, myident, allowstdin);

	msg = readall(msgfile, &msglen);

	memcpy(encmsg.encalg, ENCALG, 2);
	memcpy(encmsg.pubfingerprint, pubkey.fingerprint, FPLEN);
	memcpy(encmsg.secfingerprint, seckey.fingerprint, FPLEN);
	pubencryptmsg(msg, msglen, encmsg.box, pubkey.enckey, seckey.enckey);
	explicit_bzero(&seckey, sizeof(seckey));

	writeencfile(encfile, &encmsg, sizeof(encmsg), myident, msg, msglen);

	xfree(msg, msglen);
}

/*
 * encrypt a file using symmetric cryptography (a password)
 */
static void
symencrypt(const char *msgfile, const char *encfile, int rounds)
{
	struct symmsg symmsg;
	uint8_t symkey[SYMKEYBYTES];
	uint8_t *msg;
	unsigned long long msglen;
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
	kdf_confirm confirm = { 1 };

	msg = readall(msgfile, &msglen);

	memcpy(symmsg.kdfalg, KDFALG, 2);
	memcpy(symmsg.symalg, SYMALG, 2);
	symmsg.kdfrounds = htonl(rounds);
	randombytes(symmsg.salt, sizeof(symmsg.salt));
	kdf(symmsg.salt, sizeof(symmsg.salt), rounds,
	    allowstdin, confirm, symkey, sizeof(symkey));

	symencryptmsg(msg, msglen, symmsg.box, symkey);
	explicit_bzero(symkey, sizeof(symkey));

	writeencfile(encfile, &symmsg, sizeof(symmsg), "<symmetric>", msg, msglen);

	xfree(msg, msglen);
}

/*
 * decrypt a file, either public key or symmetric based on header
 */
static void
decrypt(const char *pubkeyfile, const char *seckeyfile, const char *msgfile,
    const char *encfile)
{
	char ident[IDENTLEN];
	uint8_t *encdata;
	unsigned long long encdatalen;
	uint8_t *msg;
	unsigned long long msglen;
	union {
		uint8_t alg[2];
		struct symmsg symmsg;
		struct encmsg encmsg;
		struct ekcmsg ekcmsg;
	} hdr;
	struct pubkey pubkey;
	struct seckey seckey;
	uint8_t symkey[SYMKEYBYTES];
	char *begin, *end;
	int fd, rounds, rv;
	const char *beginreopmsg = "-----BEGIN REOP ENCRYPTED MESSAGE-----\n";
	const char *beginreopdata = "-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n";
	const char *endreopmsg = "-----END REOP ENCRYPTED MESSAGE-----\n";

	encdata = readall(encfile, &encdatalen);
	if (strncmp(encdata, beginreopmsg, strlen(beginreopmsg)) != 0)
 		goto fail;
	begin = readident(encdata + 39, ident);
	if (!(end = strstr(begin, beginreopdata)))
 		goto fail;
	*end = 0;
	if ((rv = b64_pton(begin, (void *)&hdr, sizeof(hdr))) == -1)
 		goto fail;
	begin = end + 44;
	if (!(end = strstr(begin, endreopmsg)))
 		goto fail;
	*end = 0;

	msglen = (strlen(begin) + 3) / 4 * 3 + 1;
	msg = xmalloc(msglen);
	msglen = b64_pton(begin, msg, msglen);
	if (msglen == -1)
 		goto fail;

	if (memcmp(hdr.alg, SYMALG, 2) == 0) {
		kdf_allowstdin allowstdin = { strcmp(encfile, "-") != 0 };
		kdf_confirm confirm = { 0 };
		if (rv != sizeof(hdr.symmsg))
 			goto fail;
		if (memcmp(hdr.symmsg.kdfalg, KDFALG, 2) != 0)
			errx(1, "unsupported KDF");
		rounds = ntohl(hdr.symmsg.kdfrounds);
		kdf(hdr.symmsg.salt, sizeof(hdr.symmsg.salt), rounds,
		    allowstdin, confirm, symkey, sizeof(symkey));
		symdecryptmsg(msg, msglen, hdr.symmsg.box, symkey);
		explicit_bzero(symkey, sizeof(symkey));
	} else if (memcmp(hdr.alg, ENCALG, 2) == 0) {
		kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
		if (rv != sizeof(hdr.encmsg))
			goto fail;
		getpubkey(pubkeyfile, ident, &pubkey);
		getseckey(seckeyfile, &seckey, NULL, allowstdin);
		/* pub/sec pairs work both ways */
		if (memcmp(hdr.encmsg.pubfingerprint, pubkey.fingerprint, FPLEN) == 0) {
			if (memcmp(hdr.encmsg.secfingerprint, seckey.fingerprint, FPLEN) != 0)
				goto fpfail;
		} else if (memcmp(hdr.encmsg.pubfingerprint, seckey.fingerprint, FPLEN) != 0 ||
		    memcmp(hdr.encmsg.pubfingerprint, seckey.fingerprint, FPLEN) != 0)
			goto fpfail;

		pubdecryptmsg(msg, msglen, hdr.encmsg.box, pubkey.enckey, seckey.enckey);
		explicit_bzero(&seckey, sizeof(seckey));
	} else if (memcmp(hdr.alg, EKCALG, 2) == 0) {
		kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
		if (rv != sizeof(hdr.ekcmsg))
			goto fail;
		getseckey(seckeyfile, &seckey, NULL, allowstdin);
		if (memcmp(hdr.ekcmsg.pubfingerprint, seckey.fingerprint, FPLEN) != 0)
			goto fpfail;

		pubdecryptmsg(msg, msglen, hdr.ekcmsg.box, hdr.ekcmsg.pubkey, seckey.enckey);
		explicit_bzero(&seckey, sizeof(seckey));
	}
	fd = xopen(msgfile, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
	writeall(fd, msg, msglen, msgfile);
	close(fd);
	xfree(msg, msglen);
	return;

fail:
	errx(1, "invalid encrypted message: %s", encfile);
fpfail:
	errx(1, "fingerprint mismatch");
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
	enum {
		NONE,
		DECRYPT,
		EKPUBENCRYPT,
		ENCRYPT,
		GENERATE,
		SIGN,
		VERIFY
	} verb = NONE;

	rounds = 42;

	while ((ch = getopt(argc, argv, "ACDEGSVei:m:np:qs:x:")) != -1) {
		switch (ch) {
		case 'A':
			if (verb)
				usage(NULL);
			verb = EKPUBENCRYPT;
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
	case EKPUBENCRYPT:
	case ENCRYPT:
	case DECRYPT:
		if (!msgfile)
			usage("need msgfile");
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
	case EKPUBENCRYPT:
		ekpubencrypt(pubkeyfile, ident, msgfile, xfile);
		break;
	case ENCRYPT:
		if (seckeyfile && (!pubkeyfile && !ident))
			usage("specify a pubkey or ident");
		if (pubkeyfile || ident)
			pubencrypt(pubkeyfile, ident, seckeyfile, msgfile, xfile);
		else
			symencrypt(msgfile, xfile, rounds);
		break;
	case GENERATE:
		if (!ident && !(ident= getenv("USER")))
			ident = "unknown";

		/* can specify none, but not only one */
		if ((!pubkeyfile && seckeyfile) ||
		    (!seckeyfile && pubkeyfile))
			usage("must specify pubkey and seckey");
		generate(pubkeyfile, seckeyfile, rounds, ident);
		break;
	case SIGN:
		if (!msgfile)
			usage("must specify message");
		sign(seckeyfile, msgfile, xfile, embedded);
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
