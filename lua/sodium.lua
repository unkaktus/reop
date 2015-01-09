
local ffi = require "ffi"

ffi.cdef[[
int crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk);
int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
void randombytes(unsigned char * const buf, const unsigned long long buf_len);
]]

local sodium = ffi.load("libsodium")

return sodium
