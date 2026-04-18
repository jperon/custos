local open, popen
do
  local _obj_0 = io
  open, popen = _obj_0.open, _obj_0.popen
end
local tmpname
tmpname = os.tmpname
local rm
rm = require("sh").rm
local bin2hex
bin2hex = require("util").bin2hex
local read
read = function(self)
  if self then
    local ret = self:read("*a")
    return self:close() and ret
  end
end
local fread
fread = function(self)
  return read(open(self))
end
local skcipher = { }
skcipher.new = function(cipher_name)
  local self = { }
  self.cipher_name = cipher_name
  self.key = nil
  self.ossl_cipher = nil
  setmetatable(self, {
    __index = skcipher
  })
  return self
end
skcipher.setkey = function(self, key)
  local mode, algo = self.cipher_name:match("^(%w+)%((%w+)%)")
  local key_len = #key * 8
  if algo == "aes" and mode == "cbc" and key_len ~= 128 and key_len ~= 192 and key_len ~= 256 then
    error("Invalid key length for AES-CBC")
  end
  self.ossl_cipher = algo:upper() .. "-" .. key_len .. "-" .. mode:upper()
  self.key = key
end
local operation
operation = function(op)
  if op == nil then
    op = "e"
  end
  return function(self, iv, data)
    local tmp = tmpname()
    do
      local p = popen("openssl enc -nopad -" .. tostring(self.ossl_cipher) .. " -" .. tostring(op) .. " -K " .. tostring(bin2hex(self.key)) .. " -iv " .. tostring(bin2hex(iv)) .. " >" .. tmp, "w")
      if p then
        p:write(data)
        p:close()
        return fread(tmp), rm(tmp)
      end
    end
  end
end
skcipher.encrypt = operation("e")
skcipher.decrypt = operation("d")
return skcipher
