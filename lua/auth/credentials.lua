local bit = require("bit")
local ffi = require("ffi")
ffi.cdef([[  int chmod(const char *path, unsigned int mode);
]])
local HASH_LEN = 32
local DEFAULT_ITER = 100000
local DEFAULT_SALT_LEN = 16
local is_hex_digest
is_hex_digest = function(s)
  return type(s) == "string" and #s == 64 and s:match("^[0-9a-fA-F]+$") ~= nil
end
local load_sha
load_sha = function()
  local ok, mod = pcall(require, "ipparse.lib.sha")
  if ok and mod and mod.hmac and mod.sha256 then
    return mod
  end
  ok, mod = pcall(require, "ipparse.lib.sha2")
  if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin then
    return mod
  end
  ok, mod = pcall(require, "sha2")
  if ok and mod and mod.hmac and mod.sha256 and mod.hex_to_bin then
    return mod
  end
  return error("Aucun backend SHA/HMAC disponible")
end
local sha = load_sha()
local hmac, sha256
hmac, sha256 = sha.hmac, sha.sha256
local hex_to_bin = sha.hex_to_bin or function(hex)
  local out = { }
  for i = 1, #hex, 2 do
    out[#out + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(out)
end
local hmac_bin
hmac_bin = function(key, msg)
  local d = hmac(sha256, key, msg)
  if is_hex_digest(d) then
    return hex_to_bin(d)
  else
    return d
  end
end
local bin_to_hex
bin_to_hex = function(s)
  return (s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end
local u32be
u32be = function(n)
  return string.char(bit.band(bit.rshift(n, 24), 0xFF), bit.band(bit.rshift(n, 16), 0xFF), bit.band(bit.rshift(n, 8), 0xFF), bit.band(n, 0xFF))
end
local xor_bytes
xor_bytes = function(a, b)
  local out = { }
  for i = 1, #a do
    out[i] = string.char(bit.bxor(a:byte(i), b:byte(i)))
  end
  return table.concat(out)
end
local pbkdf2_raw
pbkdf2_raw = function(password, salt_bin, iterations, dk_len)
  if dk_len == nil then
    dk_len = HASH_LEN
  end
  local hlen = HASH_LEN
  local blocks = math.ceil(dk_len / hlen)
  local t = { }
  for i = 1, blocks do
    local u = hmac_bin(password, salt_bin .. u32be(i))
    local acc = u
    for _ = 2, iterations do
      u = hmac_bin(password, u)
      acc = xor_bytes(acc, u)
    end
    t[#t + 1] = acc
  end
  local derived = table.concat(t)
  return derived:sub(1, dk_len)
end
local pbkdf2
pbkdf2 = function(password, salt_hex, iterations)
  local salt_bin = hex_to_bin(salt_hex)
  local out = pbkdf2_raw(password, salt_bin, iterations, HASH_LEN)
  return bin_to_hex(out)
end
local read_urandom
read_urandom = function(n)
  local fh, err = io.open("/dev/urandom", "rb")
  if not (fh) then
    error("Impossible d'ouvrir /dev/urandom : " .. tostring(err))
  end
  local data = fh:read(n)
  fh:close()
  if not (data and #data == n) then
    error("Lecture incomplète de /dev/urandom")
  end
  return data
end
local hash_password
hash_password = function(password, iterations)
  iterations = iterations or DEFAULT_ITER
  local salt_hex = bin_to_hex(read_urandom(DEFAULT_SALT_LEN))
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
local valid_username
valid_username = function(username)
  if not (#username >= 3 and #username <= 64) then
    return false
  end
  if not (username:match("^[a-zA-Z0-9_.%-+]+@[a-zA-Z0-9_.%-]+%.[a-zA-Z]+$")) then
    return false
  end
  return true
end
local register_user
register_user = function(username, password, secrets_path, current_secrets)
  if not (valid_username(username)) then
    return nil, "Adresse de courriel invalide."
  end
  if #password < 8 then
    return nil, "Le mot de passe doit contenir au moins 8 caractères."
  end
  if current_secrets and current_secrets[username] then
    return nil, "Ce nom d'utilisateur est déjà pris."
  end
  local hash_entry = hash_password(password)
  local tmp_path = secrets_path .. ".new"
  local fh, err = io.open(tmp_path, "w")
  if not (fh) then
    return nil, "Impossible de créer le fichier temporaire : " .. tostring(err)
  end
  local existing = io.open(secrets_path, "r")
  if existing then
    for line in existing:lines() do
      fh:write(line .. "\n")
    end
    existing:close()
  end
  fh:write(tostring(username) .. ":" .. tostring(hash_entry) .. "\n")
  fh:close()
  ffi.C.chmod(tmp_path, 0x180)
  local ok, rename_err = os.rename(tmp_path, secrets_path)
  if not (ok) then
    os.remove(tmp_path)
    return nil, "Impossible de renommer le fichier secrets : " .. tostring(rename_err)
  end
  local new_secrets, load_err = load_secrets(secrets_path)
  if not (new_secrets) then
    return nil, "Impossible de recharger le fichier secrets : " .. tostring(load_err)
  end
  return new_secrets
end
return {
  pbkdf2 = pbkdf2,
  hash_password = hash_password,
  verify_password = verify_password,
  load_secrets = load_secrets,
  valid_username = valid_username,
  register_user = register_user
}
