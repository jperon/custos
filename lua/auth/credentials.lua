local ffi = require("ffi")
local bit = require("bit")
local crypto
do
  local ok, lib = pcall(ffi.load, "crypto")
  if not (ok) then
    ok, lib = pcall(ffi.load, "libcrypto.so.3")
  end
  if not (ok) then
    ok, lib = pcall(ffi.load, "libcrypto.so.1.1")
  end
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
local valid_username
valid_username = function(username)
  return (username:match("^[a-zA-Z0-9_.%-]+$")) ~= nil and #username >= 3 and #username <= 32
end
local register_user
register_user = function(username, password, secrets_path, current_secrets)
  if not (valid_username(username)) then
    return nil, "Nom d'utilisateur invalide (3-32 caractères alphanumériques, _, . ou -)."
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
  local existing, exist_err = io.open(secrets_path, "r")
  if existing then
    for line in existing:lines() do
      fh:write(line .. "\n")
    end
    existing:close()
  else
    if not (exist_err:match("No such file")) then
      fh:close()
      os.remove(tmp_path)
      return nil, "Impossible de lire le fichier secrets : " .. tostring(exist_err)
    end
  end
  fh:write(tostring(username) .. ":" .. tostring(hash_entry) .. "\n")
  fh:close()
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
