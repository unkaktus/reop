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

struct reop_seckey;
struct reop_pubkey;
struct reop_sig;

struct reop_keypair {
	const struct reop_pubkey *pubkey;
	const struct reop_seckey *seckey;
};

typedef struct { int v; } kdf_confirm;
typedef struct { int v; } opt_binary;

enum reop_verify_code {
	REOP_V_OK = 0,
	REOP_V_FAIL,
	REOP_V_MISMATCH,
};
typedef struct { enum reop_verify_code v; } reop_verify_result;
enum reop_decrypt_code {
	REOP_D_OK = 0,
	REOP_D_FAIL,
	REOP_D_MISMATCH,
};
typedef struct { enum reop_decrypt_code v; } reop_decrypt_result;


/* generic */
void				reop_init(void);
void				reop_freestr(const char *str);

/* generate a keypair */
struct reop_keypair		reop_generate(const char *ident);

/* pubkey functions */
const struct reop_pubkey *	reop_getpubkey(const char *pubkeyfile, const char *ident);
const struct reop_pubkey *	reop_parsepubkey(const char *pubkeydata);
const char *			reop_encodepubkey(const struct reop_pubkey *pubkey);
void				reop_freepubkey(const struct reop_pubkey *reop_pubkey);

/* seckey functions */
const struct reop_seckey *	reop_getseckey(const char *seckeyfile, const char *password);
const struct reop_seckey *	reop_parseseckey(const char *seckeydata, const char *password);
const char *			reop_encodeseckey(const struct reop_seckey *seckey, const char *password);
void				reop_freeseckey(const struct reop_seckey *reop_seckey);

/* sign and verify */
const struct reop_sig *		reop_sign(const struct reop_seckey *seckey, const uint8_t *msg,
    uint64_t msglen);
reop_verify_result		reop_verify(const struct reop_pubkey *reop_pubkey, const uint8_t *msg,
    uint64_t msglen, const struct reop_sig *reop_sig);

/* sig functions */
const struct reop_sig *		reop_parsesig(const char *sigdata);
const char *			reop_encodesig(const struct reop_sig *sig);
void				reop_freesig(const struct reop_sig *sig);

const struct reop_symmsg *	reop_symencrypt(uint8_t *msg, uint64_t msglen, const char *password);
const struct reop_encmsg *	reop_pubencrypt(const struct reop_pubkey *pubkey,
    const struct reop_seckey *seckey, uint8_t *msg, uint64_t msglen);

void				reop_freesymmsg(const struct reop_symmsg *);
void				reop_freeencmsg(const struct reop_encmsg *);
