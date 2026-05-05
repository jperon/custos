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
  return it("retourne nil si aucune extension SNI n'est présente", function()
    local ch = make_clienthello_no_sni()
    return assert.is_nil(extract_sni(ch))
  end)
end)
