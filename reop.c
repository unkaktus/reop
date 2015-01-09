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

#include <arpa/inet.h>

#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <readpassphrase.h>
#include <util.h>
#include <reopbase64.h>

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
#define ENCKEYALG "CS"	/* same as "old", didn't change */
#define OLDEKCALG "eS"	/* ephemeral-curve25519-Salsa20 */
#define SYMALG "SP"	/* Salsa20-Poly1305 */
#define KDFALG "BK"	/* bcrypt kdf */
#define IDENTLEN 64
#define RANDOMIDLEN 8
#define REOP_BINARY "RBF"

/* metadata */
struct symmsg {
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t box[SYMNONCEBYTES + SYMBOXBYTES];
};

struct encmsg {
	uint8_t encalg[2];
	uint8_t secrandomid[RANDOMIDLEN];
	uint8_t pubrandomid[RANDOMIDLEN];
	uint8_t ephpubkey[ENCPUBLICBYTES];
	uint8_t ephbox[ENCNONCEBYTES + ENCBOXBYTES];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

struct oldencmsg {
	uint8_t encalg[2];
	uint8_t secrandomid[RANDOMIDLEN];
	uint8_t pubrandomid[RANDOMIDLEN];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

struct oldekcmsg {
	uint8_t ekcalg[2];
	uint8_t pubrandomid[RANDOMIDLEN];
	uint8_t pubkey[ENCPUBLICBYTES];
	uint8_t box[ENCNONCEBYTES + ENCBOXBYTES];
};

struct reop_seckey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint8_t randomid[RANDOMIDLEN];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t box[SYMNONCEBYTES + SYMBOXBYTES];
	uint8_t sigkey[SIGSECRETBYTES];
	uint8_t enckey[ENCSECRETBYTES];
	char ident[IDENTLEN];
};
const size_t seckeysize = offsetof(struct reop_seckey, ident);

struct reop_sig {
	uint8_t sigalg[2];
	uint8_t randomid[RANDOMIDLEN];
	uint8_t sig[SIGBYTES];
	char ident[IDENTLEN];
};
const size_t sigsize = offsetof(struct reop_sig, ident);

struct reop_pubkey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t randomid[RANDOMIDLEN];
	uint8_t sigkey[SIGPUBLICBYTES];
	uint8_t enckey[ENCPUBLICBYTES];
	char ident[IDENTLEN];
};
const size_t pubkeysize = offsetof(struct reop_pubkey, ident);

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

void
reop_freestr(const char *str)
{
	xfree((void *)str, strlen(str));
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
verifyraw(const uint8_t *pubkey, const uint8_t *buf, uint64_t buflen,
    const uint8_t *sig)
{
	if (crypto_sign_verify_detached(sig, buf, buflen, pubkey) == -1)
		errx(1, "signature verification failed");
}

/* file utilities */
static void *
readall(const char *filename, uint64_t *msglenp)
{
	struct stat sb;
	ssize_t x, space;
	const uint64_t maxmsgsize = 1UL << 30;

	int fd = xopen(filename, O_RDONLY | O_NOFOLLOW, 0);
	if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode)) {
		if (sb.st_size > maxmsgsize)
			errx(1, "msg too large in %s", filename);
		space = sb.st_size + 1;
	} else {
		space = 64 * 1024;
	}

	uint8_t *msg = xmalloc(space + 1);
	uint64_t msglen = 0;
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
	close(fd);

	msg[msglen] = 0;
	*msglenp = msglen;
	return msg;
}

static void
writeall(int fd, const void *buf, size_t buflen, const char *filename)
{
	while (buflen != 0) {
		ssize_t x = write(fd, buf, buflen);
		if (x == -1)
			err(1, "write to %s", filename);
		buflen -= x;
		buf = (char *)buf + x;
	}
}

/*
 * can really write any kind of data, but we're usually interested in line
 * wrapping for base64 encoded blocks
 */
static void
writeb64data(int fd, const char *filename, char *b64)
{
	size_t rem = strlen(b64);
	size_t pos = 0;
	while (rem > 0) {
		size_t amt = rem > 76 ? 76 : rem;
		writeall(fd, b64 + pos, amt, filename);
		writeall(fd, "\n", 1, filename);
		pos += amt;
		rem -= amt;
	}
}

/*
 * wrap lines in place.
 * start at the end and pull the string down we go.
 */
static void
wraplines(char *str, size_t space)
{
	size_t len = strlen(str);
	size_t num = (len - 1) / 76;
	if (len + num + 1 > space)
		return;
	while (num > 0) {
		size_t pos = 76 * num - 1;
		size_t amt = len - pos < 76 ? len - pos : 76;
		memmove(str + pos + num, str + pos, amt + 1);
		str[pos + num] = '\n';
		num--;
	}
}

/*
 * create a filename based on user's home directory.
 * requires that ~/.reop exist.
 */
static char *
gethomefile(const char *filename, char *buf)
{
	struct stat sb;
	const char *home;

	if (!(home = getenv("HOME")))
		return NULL;
	snprintf(buf, 1024, "%s/.reop", home);
	if (stat(buf, &sb) == -1 || !S_ISDIR(sb.st_mode))
		return NULL;
	snprintf(buf, 1024, "%s/.reop/%s", home, filename);
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
 * will parse a few different kinds of keys
 */
static void
parsekeydata(const char *keydataorig, void *key, size_t keylen, char *ident)
{
	const char *beginkey = "-----BEGIN REOP";
	const char *endkey = "-----END REOP";

	char *keydata = strdup(keydataorig);
	if (strncmp(keydata, beginkey, strlen(beginkey)) != 0)
		goto invalid;
	char *end;
	if (!(end = strstr(keydata, endkey)))
		goto invalid;
	*end = 0;
	char *begin;
	if (!(begin = strchr(keydata, '\n')))
		goto invalid;
	begin = readident(begin + 1, ident);
	*end = 0;
	if (reopb64_pton(begin, key, keylen) != keylen)
		errx(1, "invalid b64 encoding");

	xfree(keydata, strlen(keydata));
	return;

invalid:
	errx(1, "invalid key data");
}

/*
 * read and parse a key
 */
static void
readkeyfile(const char *filename, void *key, size_t keylen, char *ident)
{
	uint64_t keydatalen;
	char *keydata = readall(filename, &keydatalen);

	parsekeydata(keydata, key, keylen, ident);
	xfree(keydata, keydatalen);
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
 * secret keys are themselves encrypted before export to string format.
 * they must be decrypted before use. even zero round keys (passwordless)
 * are still encrypted with a null key.
 */
void
encryptseckey(struct reop_seckey *seckey)
{
	uint8_t symkey[SYMKEYBYTES];
	kdf_allowstdin allowstdin = { 1 };
	kdf_confirm confirm = { 1 };
	int rounds = ntohl(seckey->kdfrounds);

	kdf(seckey->salt, sizeof(seckey->salt), rounds,
	    allowstdin, confirm, symkey, sizeof(symkey));
	symencryptraw(seckey->sigkey, sizeof(seckey->sigkey) + sizeof(seckey->enckey),
	    seckey->box, symkey);
	sodium_memzero(symkey, sizeof(symkey));
}

void
decryptseckey(struct reop_seckey *seckey, kdf_allowstdin allowstdin)
{
	if (memcmp(seckey->kdfalg, KDFALG, 2) != 0)
		errx(1, "unsupported KDF");

	uint8_t symkey[SYMKEYBYTES];
	kdf_confirm confirm = { 0 };
	int rounds = ntohl(seckey->kdfrounds);

	kdf(seckey->salt, sizeof(seckey->salt), rounds,
	    allowstdin, confirm, symkey, sizeof(symkey));
	symdecryptraw(seckey->sigkey, sizeof(seckey->sigkey) + sizeof(seckey->enckey),
	    seckey->box, symkey);
	sodium_memzero(symkey, sizeof(symkey));
}

/*
 * read user's pubkeyring file to allow lookup by ident
 */
static const struct reop_pubkey *
findpubkey(const char *ident)
{
	static struct reop_pubkey *keys;
	static int numkeys;
	static int done;
	const char *beginkey = "-----BEGIN REOP PUBLIC KEY-----\n";
	const char *endkey = "-----END REOP PUBLIC KEY-----\n";

	if (!done) {
		char line[1024];
		char buf[1024];
		int maxkeys = 0;
		
		done = 1;
		char namebuf[1024];
		const char *keyringname = gethomefile("pubkeyring", namebuf);
		if (!keyringname)
			return NULL;
		FILE *fp = fopen(keyringname, "r");
		if (!fp)
			return NULL;

		while (fgets(line, sizeof(line), fp)) {
			buf[0] = 0;
			int identline = 1;
			if (line[0] == 0 || line[0] == '\n')
				continue;
			if (strncmp(line, beginkey, strlen(beginkey)) != 0)
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
				if (strncmp(line, endkey, strlen(endkey)) == 0)
					break;
				strlcat(buf, line, sizeof(buf));
			}
			if (reopb64_pton(buf, (void *)&keys[numkeys], pubkeysize) != pubkeysize)
				errx(1, "invalid keyring b64 encoding");
			if (numkeys++ > 1000000)
				errx(1, "too many keys");
		}
	}
	for (int i = 0; i < numkeys; i++) {
		if (strcmp(ident, keys[i].ident) == 0)
			return &keys[i];
	}
	return NULL;
}

/*
 * 1. specified file
 * 2. lookup ident
 * 3. default pubkey file
 */
const struct reop_pubkey *
reop_getpubkey(const char *pubkeyfile, const char *ident)
{
	struct reop_pubkey *pubkey = malloc(sizeof(*pubkey));
	if (!pubkey)
		return NULL;

	if (!pubkeyfile && ident) {
		const struct reop_pubkey *identkey;
		if ((identkey = findpubkey(ident))) {
			*pubkey = *identkey;
			return pubkey;
		}
		return NULL;
	}
	char namebuf[1024];
	if (!pubkeyfile)
		pubkeyfile = gethomefile("pubkey", namebuf);
	if (!pubkeyfile) {
		free(pubkey);
		return NULL;
	}

	readkeyfile(pubkeyfile, pubkey, pubkeysize, pubkey->ident);
	return pubkey;
}

/*
 * free pubkey
 */
void
reop_freepubkey(const struct reop_pubkey *pubkey)
{
	xfree((void *)pubkey, sizeof(*pubkey));
}

/*
 * 1. specified file
 * 2. default seckey file
 */
const struct reop_seckey *
reop_getseckey(const char *seckeyfile, kdf_allowstdin allowstdin)
{
	struct reop_seckey *seckey = malloc(sizeof(*seckey));
	if (!seckey)
		return NULL;

	char namebuf[1024];
	if (!seckeyfile)
		seckeyfile = gethomefile("seckey", namebuf);
	if (!seckeyfile) {
		free(seckey);
		return NULL;
	}

	readkeyfile(seckeyfile, seckey, seckeysize, seckey->ident);
	decryptseckey(seckey, allowstdin);
	return seckey;
}

/*
 * free seckey
 */
void
reop_freeseckey(const struct reop_seckey *seckey)
{
	xfree((void *)seckey, sizeof(*seckey));
}

/*
 * can write a few different file types
 */
static const char *
encodekey(const char *info, const void *key, size_t keylen, const char *ident)
{
	char buf[1024];
	char b64[1024];

	if (reopb64_ntop(key, keylen, b64, sizeof(b64)) == -1)
		errx(1, "b64 encode failed");
	wraplines(b64, sizeof(b64));
	snprintf(buf, sizeof(buf), "-----BEGIN REOP %s-----\n"
	    "ident:%s\n"
	    "%s\n"
	    "-----END REOP %s-----\n",
	    info, ident, b64, info);
	char *str = strdup(buf);
	sodium_memzero(b64, sizeof(b64));
	sodium_memzero(buf, sizeof(buf));
	return str;
}

static void
writekeyfile(const char *filename, const char *info, const void *key,
    size_t keylen, const char *ident, int oflags, mode_t mode)
{
	int fd = xopen(filename, O_CREAT|oflags|O_NOFOLLOW|O_WRONLY, mode);
	const char *keydata = encodekey(info, key, keylen, ident);
	writeall(fd, keydata, strlen(keydata), filename);
	reop_freestr(keydata);
	close(fd);
}

/*
 * generate a complete key pair (actually two, for signing and encryption)
 */
struct reop_keypair
reop_generate(int rounds, const char *ident)
{
	uint8_t randomid[RANDOMIDLEN];

	struct reop_pubkey *pubkey = xmalloc(sizeof(*pubkey));
	memset(pubkey, 0, sizeof(*pubkey));

	struct reop_seckey *seckey = xmalloc(sizeof(*seckey));
	memset(seckey, 0, sizeof(*seckey));

	strlcpy(pubkey->ident, ident, sizeof(pubkey->ident));
	strlcpy(seckey->ident, ident, sizeof(seckey->ident));

	crypto_sign_ed25519_keypair(pubkey->sigkey, seckey->sigkey);
	crypto_box_keypair(pubkey->enckey, seckey->enckey);
	randombytes(randomid, sizeof(randomid));

	memcpy(seckey->randomid, randomid, RANDOMIDLEN);
	memcpy(seckey->sigalg, SIGALG, 2);
	memcpy(seckey->encalg, ENCKEYALG, 2);
	memcpy(seckey->symalg, SYMALG, 2);
	memcpy(seckey->kdfalg, KDFALG, 2);
	seckey->kdfrounds = htonl(rounds);
	randombytes(seckey->salt, sizeof(seckey->salt));

	memcpy(pubkey->randomid, randomid, RANDOMIDLEN);
	memcpy(pubkey->sigalg, SIGALG, 2);
	memcpy(pubkey->encalg, ENCKEYALG, 2);

	struct reop_keypair keypair = { pubkey, seckey };
	return keypair;
}

/*
 * parse pubkey data into struct
 */
const struct reop_pubkey *
reop_parsepubkey(const char *pubkeydata)
{
	struct reop_pubkey *pubkey = xmalloc(sizeof(*pubkey));
	parsekeydata(pubkeydata, pubkey, pubkeysize, pubkey->ident);
	return pubkey;
}

/*
 * encode a pubkey to a string
 */
const char *
reop_encodepubkey(const struct reop_pubkey *pubkey)
{
	return encodekey("PUBLIC KEY", pubkey, pubkeysize, pubkey->ident);
}

/*
 * parse seckey data into struct
 */
const struct reop_seckey *
reop_parseseckey(const char *seckeydata)
{
	struct reop_seckey *seckey = xmalloc(sizeof(*seckey));
	parsekeydata(seckeydata, seckey, seckeysize, seckey->ident);

	kdf_allowstdin allowstdin = { 0 };
	decryptseckey(seckey, allowstdin);
	return seckey;
}

/*
 * encode a seckey to a string
 */
const char *
reop_encodeseckey(const struct reop_seckey *seckey)
{
	struct reop_seckey copy = *seckey;
	encryptseckey(&copy);
	const char *rv = encodekey("SECRET KEY", &copy, seckeysize, seckey->ident);
	sodium_memzero(&copy, sizeof(copy));
	return rv;
}

void
generate(const char *pubkeyfile, const char *seckeyfile,
    int rounds, const char *ident)
{

	struct reop_keypair keypair = reop_generate(rounds, ident);
	struct reop_seckey copy = *keypair.seckey;
	encryptseckey(&copy);

	char secnamebuf[1024];
	if (!seckeyfile)
		seckeyfile = gethomefile("seckey", secnamebuf);
	if (!seckeyfile)
		errx(1, "no seckeyfile");
	writekeyfile(seckeyfile, "SECRET KEY", &copy, seckeysize,
	    ident, O_EXCL, 0600);

	char pubnamebuf[1024];
	if (!pubkeyfile)
		pubkeyfile = gethomefile("pubkey", pubnamebuf);
	if (!pubkeyfile)
		errx(1, "no pubkeyfile");
	writekeyfile(pubkeyfile, "PUBLIC KEY", keypair.pubkey, pubkeysize,
	    ident, O_EXCL, 0666);

	sodium_memzero(&copy, sizeof(copy));
	reop_freepubkey(keypair.pubkey);
	reop_freeseckey(keypair.seckey);
}

/*
 * write a combined message and signature
 */
static void
writesignedmsg(const char *filename, const struct reop_sig *sig,
    const char *ident, const uint8_t *msg, uint64_t msglen)
{
	char header[1024];
	char b64[1024];

	int fd = xopen(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
	snprintf(header, sizeof(header), "-----BEGIN REOP SIGNED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	writeall(fd, msg, msglen, filename);

	snprintf(header, sizeof(header), "-----BEGIN REOP SIGNATURE-----\n"
	    "ident:%s\n", ident);
	writeall(fd, header, strlen(header), filename);
	if (reopb64_ntop((void *)sig, sigsize, b64, sizeof(b64)) == -1)
		errx(1, "b64 encode failed");
	writeb64data(fd, filename, b64);
	sodium_memzero(b64, sizeof(b64));
	snprintf(header, sizeof(header), "-----END REOP SIGNED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	close(fd);
}

/*
 * basic sign function
 */
const struct reop_sig *
reop_sign(const struct reop_seckey *seckey, const uint8_t *msg, uint64_t msglen)
{
	struct reop_sig *sig = xmalloc(sizeof(*sig));

	signraw(seckey->sigkey, msg, msglen, sig->sig);

	memcpy(sig->randomid, seckey->randomid, RANDOMIDLEN);
	memcpy(sig->sigalg, SIGALG, 2);
	strlcpy(sig->ident, seckey->ident, sizeof(sig->ident));

	return sig;
}

/*
 * free sig
 */
void
reop_freesig(const struct reop_sig *sig)
{
	xfree((void *)sig, sizeof(*sig));
}

/*
 * parse signature data into struct
 */
const struct reop_sig *
reop_parsesig(const char *sigdata)
{
	struct reop_sig *sig = xmalloc(sizeof(*sig));
	parsekeydata(sigdata, sig, sigsize, sig->ident);
	return sig;
}

/*
 * encode a signature to a string
 */
const char *
reop_encodesig(const struct reop_sig *sig)
{
	return encodekey("SIGNATURE", sig, sigsize, sig->ident);
}

/*
 * read signature file
 */
static const struct reop_sig *
readsigfile(const char *sigfile)
{
	uint64_t sigdatalen;
	char *sigdata = readall(sigfile, &sigdatalen);
	const struct reop_sig *sig = reop_parsesig(sigdata);
	xfree(sigdata, sigdatalen);
	return sig;
}

/*
 * sign a file
 */
void
signfile(const char *seckeyfile, const char *msgfile, const char *sigfile,
    int embedded)
{
	uint64_t msglen;
	uint8_t *msg = readall(msgfile, &msglen);

	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
	const struct reop_seckey *seckey = reop_getseckey(seckeyfile, allowstdin);
	if (!seckey)
		errx(1, "no seckey");

	const struct reop_sig *sig = reop_sign(seckey, msg, msglen);

	reop_freeseckey(seckey);

	if (embedded)
		writesignedmsg(sigfile, sig, sig->ident, msg, msglen);
	else
		writekeyfile(sigfile, "SIGNATURE", sig, sigsize,
		    sig->ident, O_TRUNC, 0666);

	reop_freesig(sig);
	xfree(msg, msglen);
}

/*
 * basic verify function
 */
void
reop_verify(const struct reop_pubkey *pubkey, const uint8_t *msg, uint64_t msglen,
    const struct reop_sig *sig)
{
	if (memcmp(pubkey->randomid, sig->randomid, RANDOMIDLEN) != 0)
		errx(1, "verification failed: checked against wrong key");
	verifyraw(pubkey->sigkey, msg, msglen, sig->sig);
}

/*
 * simple case, detached signature
 */
void
verifysimple(const char *pubkeyfile, const char *msgfile, const char *sigfile,
    int quiet)
{
	uint64_t msglen;
	uint8_t *msg = readall(msgfile, &msglen);

	const struct reop_sig *sig = readsigfile(sigfile);
	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, sig->ident);
	if (!pubkey)
		errx(1, "no pubkey");

	reop_verify(pubkey, msg, msglen, sig);
	if (!quiet)
		printf("Signature Verified\n");

	reop_freesig(sig);
	reop_freepubkey(pubkey);
	xfree(msg, msglen);
}

/*
 * message followed by signature in one file
 */
void
verifyembedded(const char *pubkeyfile, const char *sigfile, int quiet)
{
	const char *beginmsg = "-----BEGIN REOP SIGNED MESSAGE-----\n";
	const char *beginsig = "-----BEGIN REOP SIGNATURE-----\n";

	uint64_t msgdatalen;
	char *msgdata = readall(sigfile, &msgdatalen);

	if (strncmp(msgdata, beginmsg, strlen(beginmsg)) != 0)
 		goto fail;
	char *msg = msgdata + 36;
	char *sigdata, *nextsig;
	if (!(sigdata = strstr(msg, beginsig)))
 		goto fail;
	while ((nextsig = strstr(sigdata + 1, beginsig)))
		sigdata = nextsig;
	uint64_t msglen = sigdata - msg;

	const struct reop_sig *sig = reop_parsesig(sigdata);
	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, sig->ident);
	if (!pubkey)
		errx(1, "no pubkey");

	reop_verify(pubkey, (uint8_t*)msg, msglen, sig);
	if (!quiet)
		printf("Signature Verified\n");

	reop_freesig(sig);
	reop_freepubkey(pubkey);
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
		if (reopb64_ntop(msg, msglen, b64data, b64len) == -1)
			errx(1, "b64 encode failed");

		int fd = xopen(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
		snprintf(header, sizeof(header), "-----BEGIN REOP ENCRYPTED MESSAGE-----\n");
		writeall(fd, header, strlen(header), filename);
		snprintf(header, sizeof(header), "ident:%s\n", ident);
		writeall(fd, header, strlen(header), filename);
		if (reopb64_ntop(hdr, hdrlen, b64, sizeof(b64)) == -1)
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
	struct encmsg encmsg;
	uint8_t ephseckey[ENCSECRETBYTES];

	uint64_t msglen;
	uint8_t *msg = readall(msgfile, &msglen);

	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
	if (!pubkey)
		errx(1, "no pubkey");
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
	const struct reop_seckey *seckey = reop_getseckey(seckeyfile, allowstdin);
	if (!seckey)
		errx(1, "no seckey");

	if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");
	if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");
	memcpy(encmsg.encalg, ENCALG, 2);
	memcpy(encmsg.pubrandomid, pubkey->randomid, RANDOMIDLEN);
	memcpy(encmsg.secrandomid, seckey->randomid, RANDOMIDLEN);
	crypto_box_keypair(encmsg.ephpubkey, ephseckey);

	pubencryptraw(msg, msglen, encmsg.box, pubkey->enckey, ephseckey);
	pubencryptraw(encmsg.ephpubkey, sizeof(encmsg.ephpubkey), encmsg.ephbox, pubkey->enckey, seckey->enckey);

	writeencfile(encfile, &encmsg, sizeof(encmsg), seckey->ident, msg, msglen, binary);

	reop_freeseckey(seckey);
	reop_freepubkey(pubkey);
	sodium_memzero(&ephseckey, sizeof(ephseckey));

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
	struct oldencmsg oldencmsg;

	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
	if (!pubkey)
		errx(1, "no pubkey");
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
	const struct reop_seckey *seckey = reop_getseckey(seckeyfile, allowstdin);
	if (!seckey)
		errx(1, "no seckey");

	uint64_t msglen;
	uint8_t *msg = readall(msgfile, &msglen);

	if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");
	if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");
	memcpy(oldencmsg.encalg, OLDENCALG, 2);
	memcpy(oldencmsg.pubrandomid, pubkey->randomid, RANDOMIDLEN);
	memcpy(oldencmsg.secrandomid, seckey->randomid, RANDOMIDLEN);
	pubencryptraw(msg, msglen, oldencmsg.box, pubkey->enckey, seckey->enckey);

	writeencfile(encfile, &oldencmsg, sizeof(oldencmsg), seckey->ident, msg, msglen, binary);

	reop_freeseckey(seckey);
	reop_freepubkey(pubkey);

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
	kdf_allowstdin allowstdin = { strcmp(msgfile, "-") != 0 };
	kdf_confirm confirm = { 1 };

	uint64_t msglen;
	uint8_t *msg = readall(msgfile, &msglen);

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
	int hdrsize;

	uint64_t encdatalen;
	char *encdata = readall(encfile, &encdatalen);
	if (encdatalen > 6 && memcmp(encdata, REOP_BINARY, 4) == 0) {
		uint8_t *ptr = (uint8_t *)encdata + 4;
		uint8_t *endptr = (uint8_t *)encdata + encdatalen;
		uint32_t identlen;

		if (memcmp(ptr, SYMALG, 2) == 0) {
			hdrsize = sizeof(hdr.symmsg);
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.symmsg, ptr, hdrsize);
			ptr += hdrsize;
		} else if (memcmp(ptr, ENCALG, 2) == 0) {
			hdrsize = sizeof(hdr.encmsg);
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.encmsg, ptr, hdrsize);
			ptr += hdrsize;
		} else if (memcmp(ptr, OLDENCALG, 2) == 0) {
			hdrsize = sizeof(hdr.oldencmsg);
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.oldencmsg, ptr, hdrsize);
			ptr += hdrsize;
		} else if (memcmp(ptr, OLDEKCALG, 2) == 0) {
			hdrsize = sizeof(hdr.oldekcmsg);
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.oldekcmsg, ptr, hdrsize);
			ptr += hdrsize;
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
		const char *beginmsg = "-----BEGIN REOP ENCRYPTED MESSAGE-----\n";
		const char *begindata = "-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n";
		const char *endmsg = "-----END REOP ENCRYPTED MESSAGE-----\n";


		if (strncmp(encdata, beginmsg, strlen(beginmsg)) != 0)
			goto fail;
		begin = readident(encdata + strlen(beginmsg), ident);
		if (!(end = strstr(begin, begindata)))
			goto fail;
		*end = 0;
		if ((hdrsize = reopb64_pton(begin, (void *)&hdr, sizeof(hdr))) == -1)
			goto fail;
		begin = end + strlen(begindata);
		if (!(end = strstr(begin, endmsg)))
			goto fail;
		*end = 0;

		msglen = (strlen(begin) + 3) / 4 * 3 + 1;
		msg = xmalloc(msglen);
		msglen = reopb64_pton(begin, msg, msglen);
		if (msglen == -1)
			goto fail;
		xfree(encdata, encdatalen);
		encdata = NULL;
	}

	kdf_allowstdin allowstdin = { strcmp(encfile, "-") != 0 };

	if (memcmp(hdr.alg, SYMALG, 2) == 0) {
		kdf_confirm confirm = { 0 };
		if (hdrsize != sizeof(hdr.symmsg))
 			goto fail;
		if (memcmp(hdr.symmsg.kdfalg, KDFALG, 2) != 0)
			errx(1, "unsupported KDF");
		int rounds = ntohl(hdr.symmsg.kdfrounds);
		kdf(hdr.symmsg.salt, sizeof(hdr.symmsg.salt), rounds,
		    allowstdin, confirm, symkey, sizeof(symkey));
		symdecryptraw(msg, msglen, hdr.symmsg.box, symkey);
		sodium_memzero(symkey, sizeof(symkey));
	} else if (memcmp(hdr.alg, ENCALG, 2) == 0) {
		if (hdrsize != sizeof(hdr.encmsg))
			goto fail;
		const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
		if (!pubkey)
			errx(1, "no pubkey");
		const struct reop_seckey *seckey = reop_getseckey(seckeyfile, allowstdin);
		if (!seckey)
			errx(1, "no seckey");
		if (memcmp(hdr.encmsg.pubrandomid, seckey->randomid, RANDOMIDLEN) != 0 ||
		    memcmp(hdr.encmsg.secrandomid, pubkey->randomid, RANDOMIDLEN) != 0)
			goto fpfail;

		if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
			errx(1, "unsupported key format");
		if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
			errx(1, "unsupported key format");
		pubdecryptraw(hdr.encmsg.ephpubkey, sizeof(hdr.encmsg.ephpubkey), hdr.encmsg.ephbox, pubkey->enckey, seckey->enckey);
		pubdecryptraw(msg, msglen, hdr.encmsg.box, hdr.encmsg.ephpubkey, seckey->enckey);
		reop_freeseckey(seckey);
		reop_freepubkey(pubkey);
	} else if (memcmp(hdr.alg, OLDENCALG, 2) == 0) {
		if (hdrsize != sizeof(hdr.oldencmsg))
			goto fail;
		const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
		if (!pubkey)
			errx(1, "no pubkey");
		const struct reop_seckey *seckey = reop_getseckey(seckeyfile, allowstdin);
		if (!seckey)
			errx(1, "no seckey");
		/* pub/sec pairs work both ways */
		if (memcmp(hdr.oldencmsg.pubrandomid, pubkey->randomid, RANDOMIDLEN) == 0) {
			if (memcmp(hdr.oldencmsg.secrandomid, seckey->randomid, RANDOMIDLEN) != 0)
				goto fpfail;
		} else if (memcmp(hdr.oldencmsg.pubrandomid, seckey->randomid, RANDOMIDLEN) != 0 ||
		    memcmp(hdr.oldencmsg.pubrandomid, seckey->randomid, RANDOMIDLEN) != 0)
			goto fpfail;

		if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
			errx(1, "unsupported key format");
		if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
			errx(1, "unsupported key format");
		pubdecryptraw(msg, msglen, hdr.oldencmsg.box, pubkey->enckey, seckey->enckey);
		reop_freeseckey(seckey);
		reop_freepubkey(pubkey);
	} else if (memcmp(hdr.alg, OLDEKCALG, 2) == 0) {
		if (hdrsize != sizeof(hdr.oldekcmsg))
			goto fail;
		const struct reop_seckey *seckey = reop_getseckey(seckeyfile, allowstdin);
		if (!seckey)
			errx(1, "no seckey");
		if (memcmp(hdr.oldekcmsg.pubrandomid, seckey->randomid, RANDOMIDLEN) != 0)
			goto fpfail;

		pubdecryptraw(msg, msglen, hdr.oldekcmsg.box, hdr.oldekcmsg.pubkey, seckey->enckey);
		reop_freeseckey(seckey);
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
	errx(1, "key mismatch");
}
