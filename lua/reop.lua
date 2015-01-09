local raw = require "rawreop"
local base64 = require "base64"
local ffi = require "ffi"

local strict = require "strict"

local function encodepubkey(pub)
	local buf = ffi.new("uint8_t[?]", raw.pubkeysize)
	ffi.copy(buf, pub.key, raw.pubkeysize)
	local str = base64.encode(ffi.string(buf, raw.pubkeysize))

	return string.format(
[[
-----BEGIN REOP PUBLIC KEY-----
ident:%s
%s
-----END REOP PUBLIC KEY-----
]],
		pub.ident, str)

end

local function encodeseckey(sec)
	local buf = ffi.new("uint8_t[?]", raw.seckeysize)
	ffi.copy(buf, sec.key, raw.seckeysize)
	local str = base64.encode(ffi.string(buf, raw.seckeysize))

	return string.format(
[[
-----BEGIN REOP SECRET KEY-----
ident:%s
%s
-----END REOP SECRET KEY-----
]],
		sec.ident, str)

end

local pub, sec = raw.generate("testing")
raw.encryptseckey(sec)
print(encodepubkey(pub))
print(encodeseckey(sec))

