local ffi = require("ffi")
local bit = require("bit")
local crypto
do
  local ok, lib = pcall(ffi.load, "crypto")
  if not (ok) then
    error("libcrypto introuvable (paquet openssl requis)")
  end
  crypto = lib
end
ffi.cdef([[  int PKCS5_PBKDF2_HMAC(
    const char *pass, int passlen,
    const unsigned char *salt, int saltlen,
    int iter,
    const void *digest,
    int keylen, unsigned char *out
  );
  const void* EVP_sha256(void);
  int RAND_bytes(unsigned char *buf, int num);
]])
local HASH_LEN = 32
local DEFAULT_ITER = 100000
local DEFAULT_SALT_LEN = 16
local hex_to_buf
hex_to_buf = function(hex)
  local n = math.floor(#hex / 2)
  local buf = ffi.new("uint8_t[?]", n)
  for i = 0, n - 1 do
    buf[i] = tonumber(hex:sub(i * 2 + 1, i * 2 + 2), 16)
  end
  return buf, n
end
local buf_to_hex
buf_to_hex = function(buf, len)
  local t = { }
  for i = 0, len - 1 do
    t[i + 1] = string.format("%02x", buf[i])
  end
  return table.concat(t)
end
local pbkdf2
pbkdf2 = function(password, salt_hex, iterations)
  local salt_buf, salt_len = hex_to_buf(salt_hex)
  local out = ffi.new("uint8_t[32]")
  local rc = crypto.PKCS5_PBKDF2_HMAC(password, #password, salt_buf, salt_len, iterations, crypto.EVP_sha256(), HASH_LEN, out)
  if not (rc == 1) then
    error("PKCS5_PBKDF2_HMAC a échoué")
  end
  return buf_to_hex(out, HASH_LEN)
end
local hash_password
hash_password = function(password, iterations)
  iterations = iterations or DEFAULT_ITER
  local salt_buf = ffi.new("uint8_t[?]", DEFAULT_SALT_LEN)
  local rc = crypto.RAND_bytes(salt_buf, DEFAULT_SALT_LEN)
  if not (rc == 1) then
    error("RAND_bytes a échoué")
  end
  local salt_hex = buf_to_hex(salt_buf, DEFAULT_SALT_LEN)
  local hash = pbkdf2(password, salt_hex, iterations)
  return "pbkdf2-sha256:" .. tostring(iterations) .. ":" .. tostring(salt_hex) .. ":" .. tostring(hash)
end
local verify_password
verify_password = function(password, stored)
  local algo, iter_s, salt_hex, hash_hex = stored:match("^([^:]+):(%d+):([0-9a-f]+):([0-9a-f]+)$")
  if not (algo == "pbkdf2-sha256" and iter_s and salt_hex and hash_hex) then
    return false
  end
  local computed = pbkdf2(password, salt_hex, tonumber(iter_s))
  if #computed ~= #hash_hex then
    return false
  end
  local diff = 0
  for i = 1, #computed do
    diff = bit.bor(diff, bit.bxor(computed:byte(i), hash_hex:byte(i)))
  end
  return diff == 0
end
local load_secrets
load_secrets = function(path)
  local fh, err = io.open(path, "r")
  if not (fh) then
    return nil, "impossible d'ouvrir " .. tostring(path) .. " : " .. tostring(err)
  end
  local secrets = { }
  for line in fh:lines() do
    line = line:match("^%s*(.-)%s*$")
    if line ~= "" and not line:match("^#") then
      local user, stored = line:match("^([^:]+):(.+)$")
      if user and stored then
        secrets[user] = stored
      end
    end
  end
  fh:close()
  return secrets
end
return {
  pbkdf2 = pbkdf2,
  hash_password = hash_password,
  verify_password = verify_password,
  load_secrets = load_secrets
}
