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

struct reopseckey;
struct reoppubkey;
struct reopsig;

typedef struct { int v; } kdf_allowstdin;
typedef struct { int v; } kdf_confirm;
typedef struct { int v; } opt_binary;

void reopfreestr(const char *str);

const struct reoppubkey *reopgetpubkey(const char *pubkeyfile, const char *ident);
void reopfreepubkey(const struct reoppubkey *reoppubkey);

const struct reopseckey *reopgetseckey(const char *seckeyfile, kdf_allowstdin allowstdin);
void reopfreeseckey(const struct reopseckey *reopseckey);

const struct reopsig *reopsign(const struct reopseckey *seckey, const uint8_t *msg, uint64_t msglen);
void reopverify(const struct reoppubkey *reoppubkey, uint8_t *msg, uint64_t msglen, const struct reopsig *reopsig);

void reopfreesig(const struct reopsig *sig);
const struct reopsig *reopparsesig(const char *sigdata);
const char *reopencodesig(const struct reopsig *sig);

/* application code; yet to be converted */
struct pubkey;
struct symmsg;
struct encmsg;

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
void generate(const char *pubkeyfile, const char *seckeyfile, int rounds, const char *ident);

void signfile(const char *seckeyfile, const char *msgfile, const char *sigfile,
    int embedded);
