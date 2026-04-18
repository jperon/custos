local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local parse_extension
parse_extension = require("ipparse.l7.tls.handshake.extension").parse
local band, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, rshift = _obj_0.band, _obj_0.rshift
end
local pack
pack = function(self)
  return sp(">B BH", self.type, rshift(self.len, 16), band(self.len, 0xffff))
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  local _type, _len, len, _off = su(">B BH", self, off)
  len = len + lshift(_len, 16)
  return setmetatable({
    type = _type,
    len = len
  }, _mt), _off
end
local parse_ciphers
parse_ciphers = function(self)
  local _accum_0 = { }
  local _len_0 = 1
  for i = 1, #self, 2 do
    _accum_0[_len_0] = su(">H", self, i)
    _len_0 = _len_0 + 1
  end
  return _accum_0
end
local parse_compressions
parse_compressions = function(self)
  local _accum_0 = { }
  local _len_0 = 1
  for i = 1, #self do
    _accum_0[_len_0] = su("B", self, i)
    _len_0 = _len_0 + 1
  end
  return _accum_0
end
local iter_extensions
iter_extensions = function(self, off, len)
  if off == nil then
    off = 1
  end
  if len == nil then
    len = #self
  end
  local _max = off + len
  return function()
    if off < _max then
      local extension
      extension, off = parse_extension(self, off)
      return extension
    end
  end
end
local message_types = bidirectional({
  [0x00] = "hello_request",
  [0x01] = "client_hello",
  [0x02] = "server_hello",
  [0x04] = "new_session_ticket",
  [0x0b] = "certificate",
  [0x0c] = "server_key_exchange",
  [0x0d] = "certificate_request",
  [0x0e] = "server_hello_done",
  [0x0f] = "certificate_verify",
  [0x10] = "client_key_exchange",
  [0x11] = "finished",
  [0x12] = "certificate_url",
  [0x13] = "certificate_status",
  [0x14] = "supplemental_data",
  [0x15] = "key_update"
})
local ciphers = bidirectional({
  [0x0005] = "TLS_RSA_WITH_RC4_128_SHA",
  [0x000a] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
  [0x003c] = "TLS_RSA_WITH_AES_128_CBC_SHA256",
  [0x003d] = "TLS_RSA_WITH_AES_256_CBC_SHA256",
  [0x009c] = "TLS_RSA_WITH_AES_128_GCM_SHA256",
  [0x009d] = "TLS_RSA_WITH_AES_256_GCM_SHA384",
  [0x009e] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
  [0x009f] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
  [0xc008] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
  [0xc012] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
  [0xc023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
  [0xc024] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
  [0xc027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
  [0xc028] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
  [0xc02b] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  [0xc02c] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  [0xc02f] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  [0xc030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  [0x1301] = "TLS_AES_128_GCM_SHA256",
  [0x1302] = "TLS_AES_256_GCM_SHA384",
  [0x1303] = "TLS_CHACHA20_POLY1305_SHA256",
  [0xcca8] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  [0xcca9] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
})
local compressions = bidirectional({
  [0x00] = "NULL",
  [0x01] = "DEFLATE",
  [0x02] = "LZS",
  [0x03] = "SNAPPY",
  [0xff] = "unknown"
})
local extensions = bidirectional({
  [0x00] = "server_name",
  [0x01] = "max_fragment_length",
  [0x02] = "client_certificate_url",
  [0x03] = "trusted_ca_keys",
  [0x04] = "truncated_hmac",
  [0x05] = "status_request",
  [0x06] = "user_mapping",
  [0x07] = "client_authz",
  [0x08] = "server_authz",
  [0x09] = "cert_type",
  [0x0a] = "supported_groups",
  [0x0b] = "ec_point_formats",
  [0x0c] = "srp",
  [0x0d] = "signature_algorithms",
  [0x0e] = "use_srtp",
  [0x0f] = "heartbeat",
  [0x10] = "application_layer_protocol_negotiation",
  [0x11] = "status_request_v2",
  [0x12] = "signed_certificate_timestamp",
  [0x13] = "client_certificate_type",
  [0x14] = "server_certificate_type",
  [0x15] = "padding",
  [0x16] = "encrypt_then_mac",
  [0x17] = "extended_master_secret",
  [0x18] = "token_binding",
  [0x19] = "cached_info",
  [0x1a] = "tls_ticket_early_data_info",
  [0x1b] = "pre_shared_key",
  [0x1c] = "early_data",
  [0x1d] = "supported_versions",
  [0x1e] = "cookie",
  [0x1f] = "psk_key_exchange_modes",
  [0x20] = "ticket_early_data_info",
  [0x21] = "test",
  [0x22] = "compress_certificate",
  [0x23] = "record_size_limit",
  [0xff] = "unknown"
})
return {
  parse = parse,
  pack = pack,
  ciphers = ciphers,
  compressions = compressions,
  extensions = extensions,
  message_types = message_types,
  parse_ciphers = parse_ciphers,
  parse_compressions = parse_compressions,
  iter_extensions = iter_extensions
}
