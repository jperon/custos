local hkdf_extract, hkdf_expand_label_bin, hex_to_bin
do
  local _obj_0 = require("ipparse.lib.hkdf")
  hkdf_extract, hkdf_expand_label_bin, hex_to_bin = _obj_0.hkdf_extract, _obj_0.hkdf_expand_label_bin, _obj_0.hex_to_bin
end
local INITIAL_SALT = hex_to_bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
local derive_initial_secrets
derive_initial_secrets = function(dcid)
  local initial_secret = hkdf_extract(INITIAL_SALT, dcid)
  local client_secret = hkdf_expand_label_bin(initial_secret, "client in", "", 32)
  local server_secret = hkdf_expand_label_bin(initial_secret, "server in", "", 32)
  return client_secret, server_secret
end
local derive_keys
derive_keys = function(secret)
  local key = hkdf_expand_label_bin(secret, "quic key", "", 16)
  local iv = hkdf_expand_label_bin(secret, "quic iv", "", 12)
  local hp = hkdf_expand_label_bin(secret, "quic hp", "", 16)
  return key, iv, hp
end
return {
  INITIAL_SALT = INITIAL_SALT,
  derive_initial_secrets = derive_initial_secrets,
  derive_keys = derive_keys
}
