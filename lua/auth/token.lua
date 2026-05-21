local bit = require("bit")
local ffi = require("ffi")
local KEY_LEN = 32
local load_sha
load_sha = function()
  local _list_0 = {
    "ipparse.lib.sha",
    "ipparse.lib.sha2",
    "sha2"
  }
  for _index_0 = 1, #_list_0 do
    local name = _list_0[_index_0]
    local ok, mod = pcall(require, name)
    if ok and mod and mod.hmac and mod.sha256 then
      return mod
    end
  end
  return error("Aucun backend SHA/HMAC disponible")
end
local sha_mod = load_sha()
local hmac, sha256
hmac, sha256 = sha_mod.hmac, sha_mod.sha256
local hex_to_bin = sha_mod.hex_to_bin or function(hex)
  local out = { }
  for i = 1, #hex, 2 do
    out[#out + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(out)
end
local bin_to_hex
bin_to_hex = function(s)
  return s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end)
end
local hmac_bin
hmac_bin = function(key, msg)
  local d = hmac(sha256, key, msg)
  if #d == 64 then
    return hex_to_bin(d)
  else
    return d
  end
end
local read_urandom
read_urandom = function(n)
  local fh = assert(io.open("/dev/urandom", "rb"), "Impossible d'ouvrir /dev/urandom")
  local data = fh:read(n)
  fh:close()
  assert(data and #data == n, "Lecture incomplète /dev/urandom")
  return data
end
local encode_payload
encode_payload = function(type_, user, mac, expires, nonce)
  return "user=" .. tostring(user or "") .. "&mac=" .. tostring(mac or "") .. "&expires=" .. tostring(expires or 0) .. "&type=" .. tostring(type_ or "user") .. "&nonce=" .. tostring(nonce or "")
end
local decode_payload
decode_payload = function(s)
  local t = { }
  for k, v in s:gmatch("([^&=]+)=([^&]*)") do
    t[k] = v
  end
  t.expires = tonumber(t.expires)
  return t
end
local generate
generate = function(type_, user, mac, expires, key)
  local nonce = bin_to_hex(read_urandom(8))
  local encoded = encode_payload(type_, user, mac, expires, nonce)
  local sig = bin_to_hex(hmac_bin(key, encoded))
  return encoded .. "." .. sig
end
local verify
verify = function(token, key)
  if not (token and #token > 0) then
    return nil, "token absent"
  end
  local dot = token:find(".", 1, true)
  if not (dot) then
    return nil, "token malformé"
  end
  local encoded = token:sub(1, dot - 1)
  local sig_hex = token:sub(dot + 1)
  if #sig_hex ~= 64 then
    return nil, "signature trop courte"
  end
  local expected = bin_to_hex(hmac_bin(key, encoded))
  local diff = 0
  for i = 1, 64 do
    diff = bit.bor(diff, bit.bxor(sig_hex:byte(i), expected:byte(i)))
  end
  if diff ~= 0 then
    return nil, "signature invalide"
  end
  local p = decode_payload(encoded)
  if os.time() > (p.expires or 0) then
    return nil, "token expiré"
  end
  return p, nil
end
local load_key
load_key = function(path)
  local fh = io.open(path, "rb")
  if fh then
    local key = fh:read(KEY_LEN)
    fh:close()
    if key and #key == KEY_LEN then
      return key
    end
  end
  local key = read_urandom(KEY_LEN)
  local err
  fh, err = io.open(path, "wb")
  if not (fh) then
    error("Impossible d'écrire " .. tostring(path) .. " : " .. tostring(err))
  end
  fh:write(key)
  fh:close()
  return key
end
local get_cookie
get_cookie = function(header_val, name)
  if not (header_val) then
    return nil
  end
  local pattern = name .. "=([^;]+)"
  return header_val:match(pattern)
end
return {
  generate = generate,
  verify = verify,
  load_key = load_key,
  get_cookie = get_cookie
}
