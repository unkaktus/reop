local ffi = require "ffi"

local fd = io.open("../reop.h", "r")
local header = fd:read("*a")
fd:close()

ffi.cdef(header)

local lib = ffi.load("../libreop.so")

local keypair = lib.reop_generate("luatest")
local msg = "Attack at midnight!"

local sig = lib.reop_sign(keypair.seckey, msg, msg:len())
local sigdata = lib.reop_encodesig(sig)
local sig2 = lib.reop_parsesig(sigdata)

lib.reop_verify(keypair.pubkey, msg, msg:len(), sig2)
print("Lua passed.")
