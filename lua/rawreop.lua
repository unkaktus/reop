local ffi = require "ffi"
local sodium = require "sodium"

ffi.cdef[[
struct symmsg {
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t box[24U + (32U -      16U)];
};
struct encmsg {
	uint8_t encalg[2];
	uint8_t secrandomid[8];
	uint8_t pubrandomid[8];
	uint8_t ephpubkey[32U];
	uint8_t ephbox[24U + (32U -      16U)];
	uint8_t box[24U + (32U -      16U)];
};
struct oldencmsg {
	uint8_t encalg[2];
	uint8_t secrandomid[8];
	uint8_t pubrandomid[8];
	uint8_t box[24U + (32U -      16U)];
};
struct oldekcmsg {
	uint8_t ekcalg[2];
	uint8_t pubrandomid[8];
	uint8_t pubkey[32U];
	uint8_t box[24U + (32U -      16U)];
};
struct seckey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint8_t randomid[8];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t box[40];
	uint8_t sigkey[64];
	uint8_t enckey[32];
};
struct sig {
	uint8_t sigalg[2];
	uint8_t randomid[8];
	uint8_t sig[64U];
};
struct pubkey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t randomid[8];
	uint8_t sigkey[32];
	uint8_t enckey[32];
};
]]
local seckeysize = 172
local pubkeysize = 76
local sigsize = 74
local randomidlen = 8
local SIGALG = "Ed"
local ENCKEYALG = "CS"
local SYMALG = "SP"
local KDFALG = "BK"

local function generate(ident)
	local pubkey = ffi.new("struct pubkey")
	local seckey = ffi.new("struct seckey")
	local randomid = ffi.new("uint8_t[?]", randomidlen)

	sodium.crypto_sign_ed25519_keypair(pubkey.sigkey, seckey.sigkey);
	sodium.crypto_box_keypair(pubkey.enckey, seckey.enckey);
	sodium.randombytes(randomid, randomidlen)


	ffi.copy(seckey.randomid, randomid, randomidlen)
	ffi.copy(seckey.sigalg, SIGALG, 2);
	ffi.copy(seckey.encalg, ENCKEYALG, 2);
	ffi.copy(seckey.symalg, SYMALG, 2);
	ffi.copy(seckey.kdfalg, KDFALG, 2);


	ffi.copy(pubkey.randomid, randomid, randomidlen)
	ffi.copy(pubkey.sigalg, SIGALG, 2);
	ffi.copy(pubkey.encalg, ENCKEYALG, 2);


	return { key = pubkey, ident = ident },
		{ key = seckey, ident = ident }
end

local raw = {
	seckeysize = seckeysize,
	pubkeysize = pubkeysize,
	sigsize = sigsize,

	generate = generate,
}

return raw
