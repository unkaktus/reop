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

struct seckey;
struct pubkey;
struct sig;
struct symmsg;
struct encmsg;

typedef struct { int v; } kdf_allowstdin;
typedef struct { int v; } kdf_confirm;
typedef struct { int v; } opt_binary;

const struct pubkey *getpubkey(const char *pubkeyfile, const char *ident);
void freepubkey(const struct pubkey *pubkey);

const struct seckey *getseckey(const char *seckeyfile, char *ident, kdf_allowstdin allowstdin);
void freeseckey(const struct seckey *seckey);

void generate(const char *pubkeyfile, const char *seckeyfile, int rounds, const char *ident);

const struct sig *sign(const struct seckey *seckey, const uint8_t *msg, uint64_t msglen);
void freesig(const struct sig *sig);
void signfile(const char *seckeyfile, const char *msgfile, const char *sigfile,
    int embedded);

void verify(const struct pubkey *pubkey, uint8_t *buf, uint64_t buflen,
    const struct sig *sig);
void verifysimple(const char *pubkeyfile, const char *msgfile, const char *sigfile,
    int quiet);
void verifyembedded(const char *pubkeyfile, const char *sigfile, int quiet);

void pubencrypt(const char *pubkeyfile, const char *ident, const char *seckeyfile,
    const char *msgfile, const char *encfile, opt_binary binary);
void v1pubencrypt(const char *pubkeyfile, const char *ident, const char *seckeyfile,
    const char *msgfile, const char *encfile, opt_binary binary);
void symencrypt(const char *msgfile, const char *encfile, int rounds, opt_binary binary);
void decrypt(const char *pubkeyfile, const char *seckeyfile, const char *msgfile,
    const char *encfile);
