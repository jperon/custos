local bit = require("bit")
local extract_sni
extract_sni = require("auth.sni_extractor").extract_sni
local make_clienthello_sni
make_clienthello_sni = function(hostname)
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local session_id_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local sni_entry = string.char(0x00) .. string.char(bit.rshift(#hostname, 8), bit.band(#hostname, 0xFF)) .. hostname
  local sni_list = string.char(bit.rshift(#sni_entry, 8), bit.band(#sni_entry, 0xFF)) .. sni_entry
  local sni_ext = string.char(0x00, 0x00) .. string.char(bit.rshift(#sni_list, 8), bit.band(#sni_list, 0xFF)) .. sni_list
  local extensions = sni_ext
  local ch_body = ver .. random .. session_id_len .. cipher_suites .. compression .. string.char(bit.rshift(#extensions, 8), bit.band(#extensions, 0xFF)) .. extensions
  local ch_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_clienthello_no_sni
make_clienthello_no_sni = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local session_id_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local ch_body = ver .. random .. session_id_len .. cipher_suites .. compression .. string.char(0x00, 0x00)
  local ch_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_tls_record_with_hstype
make_tls_record_with_hstype = function(hs_type_byte, body)
  body = body or string.rep("\x00", 40)
  local body_len = #body
  local handshake = string.char(hs_type_byte) .. string.char(bit.rshift(body_len, 16), bit.rshift(bit.band(body_len, 0xFF00), 8), bit.band(body_len, 0xFF)) .. body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_truncated_record
make_truncated_record = function()
  return string.char(0x16, 0x03, 0x01, 0x01, 0x00) .. string.rep("\x00", 50)
end
local make_truncated_at_cipher_suites
make_truncated_at_cipher_suites = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local ch_body = ver .. random .. sid_len
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_truncated_at_compression
make_truncated_at_compression = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local ch_body = ver .. random .. sid_len .. cipher_suites
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_no_extensions_field
make_no_extensions_field = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local ch_body = ver .. random .. sid_len .. cipher_suites .. compression
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_truncated_extensions
make_truncated_extensions = function(hostname)
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local extensions_len_bytes = string.char(0x00, 0x64)
  local fake_ext_data = string.rep("\x00", 5)
  local ch_body = ver .. random .. sid_len .. cipher_suites .. compression .. extensions_len_bytes .. fake_ext_data
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_sni_ext_truncated
make_sni_ext_truncated = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local sni_ext_header = string.char(0x00, 0x00)
  local ext_len = string.char(0x00, 0x00)
  local ext_data = sni_ext_header .. ext_len
  local ext_data_len = #ext_data
  local extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  local ch_body = ver .. random .. sid_len .. cipher_suites .. compression .. extensions_len_bytes .. ext_data
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_sni_list_truncated
make_sni_list_truncated = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local sni_payload = string.char(0x00, 0x07)
  local sni_ext_body = sni_payload
  local sni_ext = string.char(0x00, 0x00) .. string.char(bit.rshift(#sni_ext_body, 8), bit.band(#sni_ext_body, 0xFF)) .. sni_ext_body
  local ext_data_len = #sni_ext
  local extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  local ch_body = ver .. random .. sid_len .. cipher_suites .. compression .. extensions_len_bytes .. sni_ext
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_sni_unknown_name_type
make_sni_unknown_name_type = function()
  local hostname = "example.com"
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local sni_name = hostname
  local snl_inner = string.char(0x01) .. string.char(bit.rshift(#sni_name, 8), bit.band(#sni_name, 0xFF)) .. sni_name
  local snl_len_bytes = string.char(bit.rshift(#snl_inner, 8), bit.band(#snl_inner, 0xFF))
  local sni_payload = snl_len_bytes .. snl_inner
  local sni_ext = string.char(0x00, 0x00) .. string.char(bit.rshift(#sni_payload, 8), bit.band(#sni_payload, 0xFF)) .. sni_payload
  local ext_data_len = #sni_ext
  local extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  local ch_body = ver .. random .. sid_len .. cipher_suites .. compression .. extensions_len_bytes .. sni_ext
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_sni_name_truncated
make_sni_name_truncated = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local fake_hostname = "hello"
  local snl_inner = string.char(0x00) .. string.char(0x00, 0x64) .. fake_hostname
  local snl_len_bytes = string.char(bit.rshift(#snl_inner, 8), bit.band(#snl_inner, 0xFF))
  local sni_payload = snl_len_bytes .. snl_inner
  local sni_ext = string.char(0x00, 0x00) .. string.char(bit.rshift(#sni_payload, 8), bit.band(#sni_payload, 0xFF)) .. sni_payload
  local ext_data_len = #sni_ext
  local extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  local ch_body = ver .. random .. sid_len .. cipher_suites .. compression .. extensions_len_bytes .. sni_ext
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
local make_non_sni_extension
make_non_sni_extension = function()
  local ver = string.char(0x03, 0x03)
  local random = string.rep("\x00", 32)
  local sid_len = string.char(0x00)
  local cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  local compression = string.char(0x01, 0x00)
  local fake_payload = string.char(0x00, 0x01, 0x02, 0x03)
  local other_ext = string.char(0xFF, 0xFF) .. string.char(bit.rshift(#fake_payload, 8), bit.band(#fake_payload, 0xFF)) .. fake_payload
  local ext_data_len = #other_ext
  local extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  local ch_body = ver .. random .. sid_len .. cipher_suites .. compression .. extensions_len_bytes .. other_ext
  local hs_len = #ch_body
  local handshake = string.char(0x01) .. string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) .. ch_body
  local rec_len = #handshake
  return string.char(0x16, 0x03, 0x01) .. string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) .. handshake
end
return describe("auth/sni_extractor", function()
  it("retourne nil si payload trop court", function()
    assert.is_nil(extract_sni(""))
    return assert.is_nil(extract_sni("short"))
  end)
  it("retourne nil si ce n'est pas un handshake TLS", function()
    return assert.is_nil(extract_sni(string.rep("\x00", 50)))
  end)
  it("retourne nil si ce n'est pas un ClientHello (ServerHello)", function()
    local rec = string.char(0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00)
    return assert.is_nil(extract_sni(rec))
  end)
  it("extrait le SNI d'un ClientHello valide", function()
    local ch = make_clienthello_sni("example.com")
    return assert.equals("example.com", extract_sni(ch))
  end)
  it("extrait le SNI avec tiret et sous-domaine", function()
    local ch = make_clienthello_sni("my-host.example.co.uk")
    return assert.equals("my-host.example.co.uk", extract_sni(ch))
  end)
  it("retourne nil si le hostname contient des caractères interdits", function()
    local ch = make_clienthello_sni("bad!host.com")
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si aucune extension SNI n'est présente", function()
    local ch = make_clienthello_no_sni()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si le record TLS est tronqué (record_length > données dispo)", function()
    local ch = make_truncated_record()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil pour un ServerHello (hs_type=0x02) avec record complet", function()
    local body = string.rep("\x00", 50)
    local ch = make_tls_record_with_hstype(0x02, body)
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil pour un handshake hs_type=0x03 avec record complet", function()
    local body = string.rep("\x00", 50)
    local ch = make_tls_record_with_hstype(0x03, body)
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si cipher_suites est tronqué", function()
    local ch = make_truncated_at_cipher_suites()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si compression est tronquée", function()
    local ch = make_truncated_at_compression()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si le champ extensions est absent", function()
    local ch = make_no_extensions_field()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si extensions_len = 0 (extensions déclarées vides)", function()
    local ch = make_clienthello_no_sni()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si le payload des extensions est tronqué", function()
    local ch = make_truncated_extensions()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si le payload SNI est tronqué (snl_truncated)", function()
    local ch = make_sni_ext_truncated()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si la liste SNI est tronquée (sn_header_truncated)", function()
    local ch = make_sni_list_truncated()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si name_type est différent de 0 (unknown_name_type)", function()
    local ch = make_sni_unknown_name_type()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil si le nom SNI est tronqué (name_len > bytes dispo)", function()
    local ch = make_sni_name_truncated()
    return assert.is_nil(extract_sni(ch))
  end)
  it("retourne nil s'il y a une extension non-SNI et pas de SNI (no_sni_extension)", function()
    local ch = make_non_sni_extension()
    return assert.is_nil(extract_sni(ch))
  end)
  it("extrait le SNI avec wildcard", function()
    local ch = make_clienthello_sni("*.example.com")
    return assert.equals("*.example.com", extract_sni(ch))
  end)
  return it("ne crashe pas si payload est nil (retourne nil ou erreur capturée)", function()
    local ok, result = pcall(extract_sni, nil)
    return assert.is_true(ok == false or result == nil)
  end)
end)
