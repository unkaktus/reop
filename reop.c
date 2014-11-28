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
#ifdef __OpenBSD__
#include <readpassphrase.h>
#include <util.h>
#else
#include "other.h"
#endif

#include <sodium.h>

#include "reop.h"

/* shorter names */
#define SIGBYTES crypto_sign_ed25519_BYTES
#define SIGSECRETBYTES crypto_sign_ed25519_SECRETKEYBYTES
#define SIGPUBLICBYTES crypto_sign_ed25519_PUBLICKEYBYTES

#define ENCSECRETBYTES crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
#define ENCPUBLICBYTES crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#define ENCNONCEBYTES crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define ENCZEROBYTES crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
#define ENCBOXZEROBYTES crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
#define ENCBOXBYTES crypto_box_curve25519xsalsa20poly1305_MACBYTES

#define SYMKEYBYTES crypto_secretbox_xsalsa20poly1305_KEYBYTES
#define SYMNONCEBYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
#define SYMZEROBYTES crypto_secretbox_xsalsa20poly1305_ZEROBYTES
#define SYMBOXZEROBYTES crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
#define SYMBOXBYTES crypto_secretbox_xsalsa20poly1305_MACBYTES

/* magic */
#define SIGALG "Ed"	/* Ed25519 */
#define ENCALG "eC"	/* ephemeral Curve25519-Salsa20 */
#define OLDENCALG "CS"	/* Curve25519-Salsa20 */
#define OLDEKCALG "eS"	/* ephemeral-curve25519-Salsa20 */
#define SYMALG "SP"	/* Salsa20-Poly1305 */
#define KDFALG "BK"	/* bcrypt kdf */
#define IDENTLEN 64
#define FPLEN 8
#define REOP_BINARY "RBF"

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
	uint8_t ephpubkey[ENCPUBLICBYTES];
	uint8_t ephbox[ENCNONCEBYTES + ENCBOXBYTES];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

struct oldencmsg {
	uint8_t encalg[2];
	uint8_t secfingerprint[FPLEN];
	uint8_t pubfingerprint[FPLEN];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

struct oldekcmsg {
	uint8_t ekcalg[2];
	uint8_t pubfingerprint[FPLEN];
	uint8_t pubkey[ENCPUBLICBYTES];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

/* utility */
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
	if (!p)
		return;
	sodium_memzero(p, len);
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
symencryptraw(uint8_t *buf, uint64_t buflen, uint8_t *box, const uint8_t *symkey)
{
	randombytes(box, SYMNONCEBYTES);
	crypto_secretbox_detached(buf, box + SYMNONCEBYTES, buf, buflen, box, symkey);
}

/*
 * wrapper around crypto_secretbox_open.
 * operates on buf "in place".
 * box contains the auth tag data.
 */
static void
symdecryptraw(uint8_t *buf, uint64_t buflen, const uint8_t *box,
    const uint8_t *symkey)
{
	if (crypto_secretbox_open_detached(buf, buf, box + SYMNONCEBYTES,
	    buflen, box, symkey) == -1)
		errx(1, "sym decryption failed");
}

/*
 * wrapper around crypto_box.
 * operates on buf "in place".
 * box will be used to hold randomly generated nonce and auth tag data.
 */
static void
pubencryptraw(uint8_t *buf, uint64_t buflen, uint8_t *box,
    const uint8_t *pubkey, const uint8_t *seckey)
{
	randombytes(box, ENCNONCEBYTES);
	crypto_box_detached(buf, box + ENCNONCEBYTES, buf, buflen, box,
	    pubkey, seckey);
}

/*
 * wrapper around crypto_box_open.
 * operates on buf "in place".
 * box contains nonce and auth tag data.
 */
static void
pubdecryptraw(uint8_t *buf, uint64_t buflen, uint8_t *box,
    const uint8_t *pubkey, const uint8_t *seckey)
{
	if (crypto_box_open_detached(buf, buf, box + ENCNONCEBYTES,
	    buflen, box, pubkey, seckey) == -1)
		errx(1, "pub decryption failed");
}

/*
 * wrapper around crypto_sign to generate detached signatures
 */
static void
signraw(const uint8_t *seckey, const uint8_t *buf, uint64_t buflen,
    uint8_t *sig)
{
	crypto_sign_detached(sig, NULL, buf, buflen, seckey);
}

/*
 * wrapper around crypto_sign_open supporting detached signatures
 */
static void
verifyraw(const uint8_t *pubkey, uint8_t *buf, uint64_t buflen,
    const uint8_t *sig)
{
	if (crypto_sign_verify_detached(sig, buf, buflen, pubkey) == -1)
		errx(1, "signature verification failed");
}

/* file utilities */
static uint8_t *
readall(const char *filename, uint64_t *msglenp)
{
	uint64_t msglen = 0;
	uint8_t *msg = NULL;
	struct stat sb;
	ssize_t x, space;
	int fd;
	const uint64_t maxmsgsize = 1UL << 30;

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
		errx(1, "Can't use default files without ~/.reop");
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
	const char *beginreop = "-----BEGIN REOP";
	const char *endreop = "-----END REOP";
	uint64_t keydatalen;

	char *keydata = readall(filename, &keydatalen);
	if (strncmp(keydata, beginreop, strlen(beginreop)) != 0)
		goto invalid;
	char *end;
	if (!(end = strstr(keydata, endreop)))
		goto invalid;
	*end = 0;
	char *begin;
	if (!(begin = strchr(keydata, '\n')))
		goto invalid;
	begin = readident(begin + 1, ident);
	*end = 0;
	if (b64_pton(begin, key, keylen) != keylen)
		errx(1, "invalid b64 encoding: %s", filename);

	xfree(keydata, keydatalen);
	return;

invalid:
	errx(1, "invalid key: %s", filename);
}
/*
 * generate a symmetric encryption key.
 * caller creates and provides salt.
 * if rounds is 0 (no password requested), generates a dummy zero key.
 */
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
		sodium_memzero(pass2, sizeof(pass2));
	}
	if (bcrypt_pbkdf(pass, strlen(pass), salt, saltlen, key,
	    keylen, rounds) == -1)
		errx(1, "bcrypt pbkdf");
	sodium_memzero(pass, sizeof(pass));
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
	const char *beginreop = "-----BEGIN REOP PUBLIC KEY-----\n";
	const char *endreop = "-----END REOP PUBLIC KEY-----\n";

	if (!done) {
		char line[1024];
		char buf[1024];
		int maxkeys = 0;
		
		done = 1;
		FILE *fp = fopen(gethomefile("pubkeyring"), "r");
		if (!fp)
			return NULL;

		while (fgets(line, sizeof(line), fp)) {
			buf[0] = 0;
			int identline = 1;
			if (line[0] == 0 || line[0] == '\n')
				continue;
			if (strncmp(line, beginreop, strlen(beginreop)) != 0)
				errx(1, "invalid keyring line: %s", line);
			if (numkeys == maxkeys) {
				maxkeys = maxkeys ? maxkeys * 2 : 4;
				if (!(keys = realloc(keys, sizeof(*keys) * maxkeys)))
					err(1, "realloc keyring");
			}
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
	for (int i = 0; i < numkeys; i++) {
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
const struct pubkey *
getpubkey(const char *pubkeyfile, const char *ident)
{
	char dummyident[IDENTLEN];

	struct pubkey *pubkey = xmalloc(sizeof(*pubkey));
	if (!pubkeyfile && ident) {
		const struct pubkey *identkey;
		if ((identkey = findpubkey(ident))) {
			*pubkey = *identkey;
			return pubkey;
		}
		errx(1, "unable to find a pubkey for %s", ident);
	}
	if (!pubkeyfile)
		pubkeyfile = gethomefile("pubkey");
	readkeyfile(pubkeyfile, pubkey, sizeof(*pubkey), dummyident);
	return pubkey;
}

void
freepubkey(const struct pubkey *pubkey)
{
	xfree((void *)pubkey, sizeof(*pubkey));
}

/*
 * 1. specified file
 * 2. default seckey file
 */
const struct seckey *
getseckey(const char *seckeyfile, char *ident, kdf_allowstdin allowstdin)
{
	char dummyident[IDENTLEN];
	uint8_t symkey[SYMKEYBYTES];
	kdf_confirm confirm = { 0 };

	if (!seckeyfile)
		seckeyfile = gethomefile("seckey");

	struct seckey *seckey = xmalloc(sizeof(*seckey));

	readkeyfile(seckeyfile, seckey, sizeof(*seckey), ident ? ident : dummyident);
	if (memcmp(seckey->kdfalg, KDFALG, 2) != 0)
		errx(1, "unsupported KDF");
	int rounds = ntohl(seckey->kdfrounds);
	kdf(seckey->salt, sizeof(seckey->salt), rounds,
	    allowstdin, confirm, symkey, sizeof(symkey));
	symdecryptraw(seckey->sigkey, sizeof(seckey->sigkey) + sizeof(seckey->enckey),
	    seckey->box, symkey);
	sodium_memzero(symkey, sizeof(symkey));

	return seckey;
}

void
freeseckey(const struct seckey *seckey)
{
	xfree((void *)seckey, sizeof(*seckey));
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
	sodium_memzero(b64, sizeof(b64));
	snprintf(header, sizeof(header), "-----END REOP %s-----\n", info);
	writeall(fd, header, strlen(header), filename);
	close(fd);
}

/*
 * generate two key pairs, one for signing and one for encryption.
 */
void
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
	memcpy(seckey.encalg, OLDENCALG, 2);
	memcpy(seckey.symalg, SYMALG, 2);
	memcpy(seckey.kdfalg, KDFALG, 2);
	seckey.kdfrounds = htonl(rounds);
	randombytes(seckey.salt, sizeof(seckey.salt));

	kdf(seckey.salt, sizeof(seckey.salt), rounds, allowstdin, confirm,
	    symkey, sizeof(symkey));
	symencryptraw(seckey.sigkey, sizeof(seckey.sigkey) + sizeof(seckey.enckey),
	    seckey.box, symkey);
	sodium_memzero(symkey, sizeof(symkey));

	writekeyfile(seckeyfile, "SECRET KEY", &seckey, sizeof(seckey),
	    ident, O_EXCL, 0600);
	sodium_memzero(&seckey, sizeof(seckey));

	memcpy(pubkey.fingerprint, fingerprint, FPLEN);
	memcpy(pubkey.sigalg, SIGALG, 2);
	memcpy(pubkey.encalg, OLDENCALG, 2);

	if (!pubkeyfile)
		pubkeyfile = gethomefile("pubkey");
	writekeyfile(pubkeyfile, "PUBLIC KEY", &pubkey, sizeof(pubkey),
	    ident, O_EXCL, 0666);
}

static void
writesignedmsg(const char *filename, const struct sig *sig,
    const char *ident, const uint8_t *msg, uint64_t msglen)
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
	sodium_memzero(b64, sizeof(b64));
	snprintf(header, sizeof(header), "-----END REOP SIGNED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	close(fd);
}

/*
 * main sign function
 */
const struct sig *
sign(const struct seckey *seckey, const uint8_t *msg, uint64_t msglen)
{
	struct sig *sig = xmalloc(sizeof(*sig));

	signraw(seckey->sigkey, msg, msglen, sig->sig);

	memcpy(sig->fingerprint, seckey->fingerprint, FPLEN);
	memcpy(sig->sigalg, SIGALG, 2);

	return sig;
}

void
freesig(const struct sig *sig)
{
	xfree((void *)sig, sizeof(*sig));
}

void
signfile(const char *seckeyfile, const char *msgfile, const char *sigfile,
    int embedded)
{
	uint64_t msglen;
	uint8_t *msg = readall(msgfile, &msglen);

	char ident[IDENTLEN];
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
	const struct seckey *seckey = getseckey(seckeyfile, ident, allowstdin);

	const struct sig *sig = sign(seckey, msg, msglen);

	freeseckey(seckey);

	if (embedded)
		writesignedmsg(sigfile, sig, ident, msg, msglen);
	else
		writekeyfile(sigfile, "SIGNATURE", sig, sizeof(*sig), ident,
		    O_TRUNC, 0666);

	freesig(sig);
	xfree(msg, msglen);
}

/*
 * simple case, detached signature
 */
void
verify(const struct pubkey *pubkey, uint8_t *buf, uint64_t buflen,
    const struct sig *sig)
{
	if (memcmp(pubkey->fingerprint, sig->fingerprint, FPLEN) != 0)
		errx(1, "verification failed: checked against wrong key");
	verifyraw(pubkey->sigkey, buf, buflen, sig->sig);
}

void
verifysimple(const char *pubkeyfile, const char *msgfile, const char *sigfile,
    int quiet)
{
	char ident[IDENTLEN];
	struct sig sig;
	uint64_t msglen;
	uint8_t *msg;

	msg = readall(msgfile, &msglen);

	readkeyfile(sigfile, &sig, sizeof(sig), ident);
	const struct pubkey *pubkey = getpubkey(pubkeyfile, ident);

	verify(pubkey, msg, msglen, &sig);
	if (!quiet)
		printf("Signature Verified\n");

	freepubkey(pubkey);
	xfree(msg, msglen);
}

/*
 * message followed by signature in one file
 */
void
verifyembedded(const char *pubkeyfile, const char *sigfile, int quiet)
{
	char ident[IDENTLEN];
	struct sig sig;
	uint8_t *msg;
	uint64_t msglen;
	uint8_t *msgdata;
	uint64_t msgdatalen;
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

	const struct pubkey *pubkey = getpubkey(pubkeyfile, ident);

	verify(pubkey, msg, msglen, &sig);
	if (!quiet)
		printf("Signature Verified\n");

	freepubkey(pubkey);
	xfree(msgdata, msgdatalen);

	return;
fail:
	errx(1, "invalid signature: %s", sigfile);
}

/*
 * write an reop encrypted message header, followed by base64 data
 */
static void
writeencfile(const char *filename, const void *hdr,
    size_t hdrlen, const char *ident, uint8_t *msg, uint64_t msglen,
    opt_binary binary)
{
	if (binary.v) {
		uint32_t identlen = strlen(ident);
		identlen = htonl(identlen);

		int fd = xopen(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);

		writeall(fd, REOP_BINARY, 4, filename);
		writeall(fd, hdr, hdrlen, filename);
		writeall(fd, &identlen, sizeof(identlen), filename);
		writeall(fd, ident, strlen(ident), filename);
		writeall(fd, msg, msglen, filename);
		close(fd);
	} else {
		char header[1024];
		char b64[1024];

		size_t b64len = (msglen + 2) / 3 * 4 + 1;
		char *b64data = xmalloc(b64len);
		if (b64_ntop(msg, msglen, b64data, b64len) == -1)
			errx(1, "b64 encode failed");

		int fd = xopen(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
		snprintf(header, sizeof(header), "-----BEGIN REOP ENCRYPTED MESSAGE-----\n");
		writeall(fd, header, strlen(header), filename);
		snprintf(header, sizeof(header), "ident:%s\n", ident);
		writeall(fd, header, strlen(header), filename);
		if (b64_ntop(hdr, hdrlen, b64, sizeof(b64)) == -1)
			errx(1, "b64 encode failed");
		writeb64data(fd, filename, b64);
		sodium_memzero(b64, sizeof(b64));

		snprintf(header, sizeof(header), "-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n");
		writeall(fd, header, strlen(header), filename);
		writeb64data(fd, filename, b64data);
		xfree(b64data, b64len);

		snprintf(header, sizeof(header), "-----END REOP ENCRYPTED MESSAGE-----\n");
		writeall(fd, header, strlen(header), filename);
		close(fd);
	}
}

/*
 * encrypt a file using public key cryptography
 * an ephemeral key is used to make the encryption one way
 * that key is then encrypted with our seckey to provide authentication
 */
void
pubencrypt(const char *pubkeyfile, const char *ident, const char *seckeyfile,
    const char *msgfile, const char *encfile, opt_binary binary)
{
	char myident[IDENTLEN];
	struct encmsg encmsg;
	uint8_t ephseckey[ENCSECRETBYTES];
	uint8_t *msg;
	uint64_t msglen;
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };

	msg = readall(msgfile, &msglen);

	const struct pubkey *pubkey = getpubkey(pubkeyfile, ident);
	const struct seckey *seckey = getseckey(seckeyfile, myident, allowstdin);

	memcpy(encmsg.encalg, ENCALG, 2);
	memcpy(encmsg.pubfingerprint, pubkey->fingerprint, FPLEN);
	memcpy(encmsg.secfingerprint, seckey->fingerprint, FPLEN);
	crypto_box_keypair(encmsg.ephpubkey, ephseckey);

	pubencryptraw(msg, msglen, encmsg.box, pubkey->enckey, ephseckey);

	pubencryptraw(encmsg.ephpubkey, sizeof(encmsg.ephpubkey), encmsg.ephbox, pubkey->enckey, seckey->enckey);

	freeseckey(seckey);
	freepubkey(pubkey);
	sodium_memzero(&ephseckey, sizeof(ephseckey));

	writeencfile(encfile, &encmsg, sizeof(encmsg), myident, msg, msglen, binary);

	xfree(msg, msglen);
}

/*
 * encrypt a file using public key cryptography
 * old version 1.0 variant
 */
void
v1pubencrypt(const char *pubkeyfile, const char *ident, const char *seckeyfile,
    const char *msgfile, const char *encfile, opt_binary binary)
{
	char myident[IDENTLEN];
	struct oldencmsg oldencmsg;
	uint8_t *msg;
	uint64_t msglen;
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };

	const struct pubkey *pubkey = getpubkey(pubkeyfile, ident);

	const struct seckey *seckey = getseckey(seckeyfile, myident, allowstdin);

	msg = readall(msgfile, &msglen);

	memcpy(oldencmsg.encalg, OLDENCALG, 2);
	memcpy(oldencmsg.pubfingerprint, pubkey->fingerprint, FPLEN);
	memcpy(oldencmsg.secfingerprint, seckey->fingerprint, FPLEN);
	pubencryptraw(msg, msglen, oldencmsg.box, pubkey->enckey, seckey->enckey);

	freeseckey(seckey);
	freepubkey(pubkey);

	writeencfile(encfile, &oldencmsg, sizeof(oldencmsg), myident, msg, msglen, binary);

	xfree(msg, msglen);
}

/*
 * encrypt a file using symmetric cryptography (a password)
 */
void
symencrypt(const char *msgfile, const char *encfile, int rounds, opt_binary binary)
{
	struct symmsg symmsg;
	uint8_t symkey[SYMKEYBYTES];
	uint8_t *msg;
	uint64_t msglen;
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
	kdf_confirm confirm = { 1 };

	msg = readall(msgfile, &msglen);

	memcpy(symmsg.kdfalg, KDFALG, 2);
	memcpy(symmsg.symalg, SYMALG, 2);
	symmsg.kdfrounds = htonl(rounds);
	randombytes(symmsg.salt, sizeof(symmsg.salt));
	kdf(symmsg.salt, sizeof(symmsg.salt), rounds,
	    allowstdin, confirm, symkey, sizeof(symkey));

	symencryptraw(msg, msglen, symmsg.box, symkey);
	sodium_memzero(symkey, sizeof(symkey));

	writeencfile(encfile, &symmsg, sizeof(symmsg), "<symmetric>", msg, msglen, binary);

	xfree(msg, msglen);
}

/*
 * decrypt a file, either public key or symmetric based on header
 */
void
decrypt(const char *pubkeyfile, const char *seckeyfile, const char *msgfile,
    const char *encfile)
{
	char ident[IDENTLEN];
	uint8_t *encdata;
	uint64_t encdatalen;
	uint8_t *msg;
	uint64_t msglen;
	union {
		uint8_t alg[2];
		struct symmsg symmsg;
		struct encmsg encmsg;
		struct oldencmsg oldencmsg;
		struct oldekcmsg oldekcmsg;
	} hdr;
	uint8_t symkey[SYMKEYBYTES];
	int rv;

	encdata = readall(encfile, &encdatalen);
	if (encdatalen > 6 && memcmp(encdata, REOP_BINARY, 4) == 0) {
		uint8_t *ptr = encdata + 4;
		uint8_t *endptr = encdata + encdatalen;
		uint32_t identlen;

		if (memcmp(ptr, SYMALG, 2) == 0) {
			rv = sizeof(hdr.symmsg);
			if (ptr + rv > endptr)
				goto fail;
			memcpy(&hdr.symmsg, ptr, rv);
			ptr += rv;
		} else if (memcmp(ptr, ENCALG, 2) == 0) {
			rv = sizeof(hdr.encmsg);
			if (ptr + rv > endptr)
				goto fail;
			memcpy(&hdr.encmsg, ptr, rv);
			ptr += rv;
		} else if (memcmp(ptr, OLDENCALG, 2) == 0) {
			rv = sizeof(hdr.oldencmsg);
			if (ptr + rv > endptr)
				goto fail;
			memcpy(&hdr.oldencmsg, ptr, rv);
			ptr += rv;
		} else if (memcmp(ptr, OLDEKCALG, 2) == 0) {
			rv = sizeof(hdr.oldekcmsg);
			if (ptr + rv > endptr)
				goto fail;
			memcpy(&hdr.oldekcmsg, ptr, rv);
			ptr += rv;
		} else {
			goto fail;
		}
		if (ptr + sizeof(identlen) > endptr)
			goto fail;
		memcpy(&identlen, ptr, sizeof(identlen));
		ptr += sizeof(identlen);
		identlen = ntohl(identlen);
		if (identlen > sizeof(ident))
			goto fail;
		if (ptr + identlen > endptr)
			goto fail;
		memcpy(ident, ptr, identlen);
		ptr += identlen;
		msg = ptr;
		msglen = endptr - ptr;
	} else {
		char *begin, *end;
		const char *beginreopmsg = "-----BEGIN REOP ENCRYPTED MESSAGE-----\n";
		const char *beginreopdata = "-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n";
		const char *endreopmsg = "-----END REOP ENCRYPTED MESSAGE-----\n";


		if (strncmp(encdata, beginreopmsg, strlen(beginreopmsg)) != 0)
			goto fail;
		begin = readident(encdata + strlen(beginreopmsg), ident);
		if (!(end = strstr(begin, beginreopdata)))
			goto fail;
		*end = 0;
		if ((rv = b64_pton(begin, (void *)&hdr, sizeof(hdr))) == -1)
			goto fail;
		begin = end + strlen(beginreopdata);
		if (!(end = strstr(begin, endreopmsg)))
			goto fail;
		*end = 0;

		msglen = (strlen(begin) + 3) / 4 * 3 + 1;
		msg = xmalloc(msglen);
		msglen = b64_pton(begin, msg, msglen);
		if (msglen == -1)
			goto fail;
		xfree(encdata, encdatalen);
		encdata = NULL;
	}

	kdf_allowstdin allowstdin = { strcmp(encfile, "-") != 0 };

	if (memcmp(hdr.alg, SYMALG, 2) == 0) {
		kdf_confirm confirm = { 0 };
		if (rv != sizeof(hdr.symmsg))
 			goto fail;
		if (memcmp(hdr.symmsg.kdfalg, KDFALG, 2) != 0)
			errx(1, "unsupported KDF");
		int rounds = ntohl(hdr.symmsg.kdfrounds);
		kdf(hdr.symmsg.salt, sizeof(hdr.symmsg.salt), rounds,
		    allowstdin, confirm, symkey, sizeof(symkey));
		symdecryptraw(msg, msglen, hdr.symmsg.box, symkey);
		sodium_memzero(symkey, sizeof(symkey));
	} else if (memcmp(hdr.alg, ENCALG, 2) == 0) {
		if (rv != sizeof(hdr.encmsg))
			goto fail;
		const struct pubkey *pubkey = getpubkey(pubkeyfile, ident);
		const struct seckey *seckey = getseckey(seckeyfile, NULL, allowstdin);
		if (memcmp(hdr.encmsg.pubfingerprint, seckey->fingerprint, FPLEN) != 0 ||
		    memcmp(hdr.encmsg.secfingerprint, pubkey->fingerprint, FPLEN) != 0)
			goto fpfail;

		pubdecryptraw(hdr.encmsg.ephpubkey, sizeof(hdr.encmsg.ephpubkey), hdr.encmsg.ephbox, pubkey->enckey, seckey->enckey);
		pubdecryptraw(msg, msglen, hdr.encmsg.box, hdr.encmsg.ephpubkey, seckey->enckey);
		freeseckey(seckey);
		freepubkey(pubkey);
	} else if (memcmp(hdr.alg, OLDENCALG, 2) == 0) {
		if (rv != sizeof(hdr.oldencmsg))
			goto fail;
		const struct pubkey *pubkey = getpubkey(pubkeyfile, ident);
		const struct seckey *seckey = getseckey(seckeyfile, NULL, allowstdin);
		/* pub/sec pairs work both ways */
		if (memcmp(hdr.oldencmsg.pubfingerprint, pubkey->fingerprint, FPLEN) == 0) {
			if (memcmp(hdr.oldencmsg.secfingerprint, seckey->fingerprint, FPLEN) != 0)
				goto fpfail;
		} else if (memcmp(hdr.oldencmsg.pubfingerprint, seckey->fingerprint, FPLEN) != 0 ||
		    memcmp(hdr.oldencmsg.pubfingerprint, seckey->fingerprint, FPLEN) != 0)
			goto fpfail;

		pubdecryptraw(msg, msglen, hdr.oldencmsg.box, pubkey->enckey, seckey->enckey);
		freeseckey(seckey);
		freepubkey(pubkey);
	} else if (memcmp(hdr.alg, OLDEKCALG, 2) == 0) {
		if (rv != sizeof(hdr.oldekcmsg))
			goto fail;
		const struct seckey *seckey = getseckey(seckeyfile, NULL, allowstdin);
		if (memcmp(hdr.oldekcmsg.pubfingerprint, seckey->fingerprint, FPLEN) != 0)
			goto fpfail;

		pubdecryptraw(msg, msglen, hdr.oldekcmsg.box, hdr.oldekcmsg.pubkey, seckey->enckey);
		freeseckey(seckey);
	} else {
		goto fail;
	}
	int fd = xopen(msgfile, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
	writeall(fd, msg, msglen, msgfile);
	close(fd);
	if (encdata)
		xfree(encdata, encdatalen);
	else
		xfree(msg, msglen);
	return;

fail:
	errx(1, "invalid encrypted message: %s", encfile);
fpfail:
	errx(1, "fingerprint mismatch");
}
