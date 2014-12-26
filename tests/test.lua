local ffi = require "ffi"

local fd = io.open("../reop.h", "r")
local header = fd:read("*a")
fd:close()

ffi.cdef(header)

local reop = ffi.load("../libreop.so")

local keypair = reop.reopgenerate(0, "luatest")
local msg = "Attack at midnight!"

local sig = reop.reopsign(keypair.seckey, msg, msg:len())
local sigdata = reop.reopencodesig(sig)
local sig2 = reop.reopparsesig(sigdata)

reop.reopverify(keypair.pubkey, msg, msg:len(), sig2)
print("Lua passed.")
