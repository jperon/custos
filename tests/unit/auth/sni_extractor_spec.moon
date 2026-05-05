-- tests/unit/auth/sni_extractor_spec.moon
-- Tests du parser TLS ClientHello SNI (pur, pas de FFI).

bit = require "bit"
{ :extract_sni } = require "auth.sni_extractor"

-- ── Helper : construit un TLS ClientHello minimal avec SNI ──────────────────
make_clienthello_sni = (hostname) ->
  ver           = string.char 0x03, 0x03
  random        = string.rep "\x00", 32
  session_id_len = string.char 0x00
  cipher_suites = string.char 0x00, 0x02, 0x13, 0x01
  compression   = string.char 0x01, 0x00

  sni_entry = string.char(0x00) ..
    string.char(bit.rshift(#hostname, 8), bit.band(#hostname, 0xFF)) ..
    hostname
  sni_list = string.char(bit.rshift(#sni_entry, 8), bit.band(#sni_entry, 0xFF)) .. sni_entry
  sni_ext = string.char(0x00, 0x00) ..
    string.char(bit.rshift(#sni_list, 8), bit.band(#sni_list, 0xFF)) ..
    sni_list

  extensions = sni_ext
  ch_body = ver .. random .. session_id_len .. cipher_suites .. compression ..
    string.char(bit.rshift(#extensions, 8), bit.band(#extensions, 0xFF)) ..
    extensions
  ch_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : ClientHello sans extension SNI ─────────────────────────────────
make_clienthello_no_sni = ->
  ver           = string.char 0x03, 0x03
  random        = string.rep "\x00", 32
  session_id_len = string.char 0x00
  cipher_suites = string.char 0x00, 0x02, 0x13, 0x01
  compression   = string.char 0x01, 0x00
  ch_body = ver .. random .. session_id_len .. cipher_suites .. compression ..
    string.char(0x00, 0x00)   -- extensions_len = 0
  ch_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(ch_len, 16), bit.rshift(bit.band(ch_len, 0xFF00), 8), bit.band(ch_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

describe "auth/sni_extractor", ->

  it "retourne nil si payload trop court", ->
    assert.is_nil extract_sni ""
    assert.is_nil extract_sni "short"

  it "retourne nil si ce n'est pas un handshake TLS", ->
    assert.is_nil extract_sni string.rep("\x00", 50)

  it "retourne nil si ce n'est pas un ClientHello (ServerHello)", ->
    rec = string.char 0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00
    assert.is_nil extract_sni rec

  it "extrait le SNI d'un ClientHello valide", ->
    ch = make_clienthello_sni "example.com"
    assert.equals "example.com", extract_sni(ch)

  it "extrait le SNI avec tiret et sous-domaine", ->
    ch = make_clienthello_sni "my-host.example.co.uk"
    assert.equals "my-host.example.co.uk", extract_sni(ch)

  it "retourne nil si le hostname contient des caractères interdits", ->
    ch = make_clienthello_sni "bad!host.com"
    assert.is_nil extract_sni ch

  it "retourne nil si aucune extension SNI n'est présente", ->
    ch = make_clienthello_no_sni!
    assert.is_nil extract_sni ch
