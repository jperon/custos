local ossl = require("openssl")
local hmac = ossl.hmac
local digest = ossl.digest
local HKDF_methods = { }
HKDF_methods.extract = function(self, salt, ikm)
  return hmac.new(self._digest_name, salt):final(ikm)
end
HKDF_methods.expand = function(self, prk, info, length)
  local h = hmac.new(self._digest_name, prk)
  local hash_len
  if self._digest_name == "sha256" then
    hash_len = 32
  else
    local _ = 64
  end
  local n = math.ceil(length / hash_len)
  assert(n <= 255, "Too much output length for HKDF")
  local t, okm = "", ""
  for i = 1, n do
    t = h:final(t .. info .. string.char(i))
    okm = okm .. t
  end
  return okm:sub(1, length)
end
local new
new = function(digest_name)
  local hkdf_obj = {
    _digest_name = digest_name:lower()
  }
  setmetatable(hkdf_obj, {
    __index = HKDF_methods
  })
  return hkdf_obj
end
return {
  new = new
}
