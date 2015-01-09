local mime = require "mime"


local function encode(data)
	local str = mime.b64(data)
	str = mime.wrp(76, str, 76):gsub("\r", "")
	return str
end

local function decode(str)
	local data = mime.unb64(str)
	return data
end

local base64 = {
	encode = encode,
	decode = decode,
}

return base64
