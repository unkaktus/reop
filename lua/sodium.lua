
local ffi = require "ffi"

ffi.cdef[[
int crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk);
int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
void randombytes(unsigned char * const buf, const unsigned long long buf_len);
int crypto_secretbox_detached(unsigned char *c, unsigned char *mac,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *n, const unsigned char *k);
]]

local symnoncebytes = 24

local lib = ffi.load("libsodium")

local sodium = { }

function sodium.randombytes(buf, buflen)
	lib.randombytes(buf, buflen)
end

function sodium.sign_keypair(pk, sk)
	lib.crypto_sign_ed25519_keypair(pk, sk)
end

function sodium.box_keypair(pk, sk)
	lib.crypto_box_keypair(pk, sk)
end

function sodium.symencrypt(buf, buflen, box, symkey)
	lib.randombytes(box, symnoncebytes)
	lib.crypto_secretbox_detached(buf, box + symnoncebytes, buf, buflen, box, symkey)
end

return sodium
