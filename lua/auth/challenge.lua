local bit = require("bit")
local credentials = require("auth.credentials")
local hmac_bin, bin_to_hex, DEFAULT_ITER, DEFAULT_SALT_LEN, parse_record
hmac_bin, bin_to_hex, DEFAULT_ITER, DEFAULT_SALT_LEN, parse_record = credentials.hmac_bin, credentials.bin_to_hex, credentials.DEFAULT_ITER, credentials.DEFAULT_SALT_LEN, credentials.parse_record
local read_urandom
read_urandom = function(n)
  local fh = assert(io.open("/dev/urandom", "rb"), "Impossible d'ouvrir /dev/urandom")
  local data = fh:read(n)
  fh:close()
  assert(data and #data == n, "Lecture incomplète /dev/urandom")
  return data
end
local norm_mac
norm_mac = function(mac)
  if mac and mac ~= "" then
    return tostring(mac):lower()
  else
    return "unknown"
  end
end
local sign
sign = function(token_key, payload)
  return bin_to_hex(hmac_bin(token_key, payload))
end
local hex_equal_ct
hex_equal_ct = function(a, b)
  if not (type(a) == "string" and type(b) == "string") then
    return false
  end
  if #a ~= #b then
    return false
  end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
  end
  return diff == 0
end
local make_nonce
make_nonce = function(token_key, mac, ttl)
  if ttl == nil then
    ttl = 120
  end
  local rand = bin_to_hex(read_urandom(8))
  local expires = os.time() + (tonumber(ttl) or 120)
  local payload = tostring(rand) .. "." .. tostring(expires) .. "." .. tostring(norm_mac(mac))
  return tostring(payload) .. "." .. tostring(sign(token_key, payload))
end
local verify_nonce
verify_nonce = function(token_key, mac, nonce)
  if not (type(nonce) == "string" and #nonce > 0) then
    return false, "nonce absent"
  end
  local rand, expires_s, n_mac, sig = nonce:match("^(%x+)%.(%d+)%.([^.]+)%.(%x+)$")
  if not (rand and expires_s and n_mac and sig) then
    return false, "nonce malformé"
  end
  local payload = tostring(rand) .. "." .. tostring(expires_s) .. "." .. tostring(n_mac)
  if not (hex_equal_ct(sig, sign(token_key, payload))) then
    return false, "signature invalide"
  end
  if not (n_mac == norm_mac(mac)) then
    return false, "mac inattendue"
  end
  if os.time() > tonumber(expires_s) then
    return false, "nonce expiré"
  end
  return true
end
local salt_iter_for
salt_iter_for = function(secrets, token_key, user)
  local rec = parse_record((secrets and secrets[user]))
  if rec then
    return {
      salt = rec.salt_hex,
      iter = rec.iter
    }
  else
    local user_lc = tostring(user or ""):lower()
    local fake = bin_to_hex(hmac_bin(token_key, "salt:" .. tostring(user_lc)))
    return {
      salt = fake:sub(1, DEFAULT_SALT_LEN * 2),
      iter = DEFAULT_ITER
    }
  end
end
return {
  make_nonce = make_nonce,
  verify_nonce = verify_nonce,
  salt_iter_for = salt_iter_for
}
