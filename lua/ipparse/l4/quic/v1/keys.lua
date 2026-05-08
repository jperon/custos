local load_hkdf
load_hkdf = function()
  local mod_name = "ipparse.lib.hkdf"
  local cached = package.loaded[mod_name]
  if type(cached) == "table" and cached.hkdf_extract and cached.hkdf_expand_label and cached.hex_to_bin then
    return cached
  end
  package.loaded[mod_name] = nil
  local ok, mod_or_err = pcall(require, mod_name)
  if not (ok and mod_or_err) then
    error("quic_hkdf_load_failed: " .. tostring(mod_or_err))
  end
  return mod_or_err
end
local hkdf_extract, hkdf_expand_label, hex_to_bin
do
  local _obj_0 = load_hkdf()
  hkdf_extract, hkdf_expand_label, hex_to_bin = _obj_0.hkdf_extract, _obj_0.hkdf_expand_label, _obj_0.hex_to_bin
end
local INITIAL_SALT = hex_to_bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
local derive_initial_secrets
derive_initial_secrets = function(dcid)
  local initial_secret = hkdf_extract(INITIAL_SALT, dcid)
  local client_secret = hex_to_bin(hkdf_expand_label(initial_secret, "client in", "", 32))
  local server_secret = hex_to_bin(hkdf_expand_label(initial_secret, "server in", "", 32))
  return client_secret, server_secret
end
local derive_keys
derive_keys = function(secret)
  local key = hex_to_bin(hkdf_expand_label(secret, "quic key", "", 16))
  local iv = hex_to_bin(hkdf_expand_label(secret, "quic iv", "", 12))
  local hp = hex_to_bin(hkdf_expand_label(secret, "quic hp", "", 16))
  return key, iv, hp
end
return {
  INITIAL_SALT = INITIAL_SALT,
  derive_initial_secrets = derive_initial_secrets,
  derive_keys = derive_keys
}
