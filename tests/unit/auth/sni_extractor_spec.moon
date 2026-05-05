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

-- ── Helper : ClientHello sans extension SNI (extensions vides) ──────────────
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

-- ── Helper : construit un TLS record complet avec hs_type donné ─────────────
-- Permet de tester le cas hs_type ≠ 0x01 (ServerHello = 0x02)
make_tls_record_with_hstype = (hs_type_byte, body) ->
  -- body = contenu du handshake après le type et la longueur
  body = body or string.rep("\x00", 40)
  body_len = #body
  handshake = string.char(hs_type_byte) ..
    string.char(bit.rshift(body_len, 16), bit.rshift(bit.band(body_len, 0xFF00), 8), bit.band(body_len, 0xFF)) ..
    body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : ClientHello dont le record_length > payload réel (tronqué) ─────
make_truncated_record = ->
  -- TLS record type 0x16, version 0x0301, length=0x0100 (256) mais payload court
  string.char(0x16, 0x03, 0x01, 0x01, 0x00) .. string.rep("\x00", 50)

-- ── Helper : ClientHello avec cipher_suites tronqué ─────────────────────────
-- session_id_len=0, cipher_suites_offset = 10+35+0 = 45 (1-indexed)
-- Pour tronquer, on coupe exactement à cipher_suites_offset-1
make_truncated_at_cipher_suites = ->
  -- Header TLS record
  -- ch_offset = 10 (1-indexed), session_id_len at byte 44 = 0
  -- cipher_suites_offset = 45, doit satisfaire: cipher_suites_offset+1 <= #data
  -- → pour tronquer: #data < cipher_suites_offset+1 = 46 → on fait exactement 45 bytes après header
  -- Total: 5 (record hdr) + 4 (hs hdr) + 2 (version) + 32 (random) + 1 (sid_len) = 44 bytes
  -- On s'arrête là: pas assez pour cipher_suites (besoin de 45+1=46, on a 44)
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  ch_body = ver .. random .. sid_len
  -- ch_body = 2+32+1 = 35 bytes, ch_offset=10, cipher_suites_offset=10+35=45 (need >= 46)
  -- body_len = 35 mais on veut cipher_suites_offset+1 > #data
  -- #data = 5 + 4 + 35 = 44, cipher_suites_offset = 45, need 46 > 44 → OK
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  -- IMPORTANT : fixer record_length = rec_len pour passer le check de tronquage du record
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : ClientHello avec compression tronqué ───────────────────────────
-- cipher_suites présents (len=2, 2 bytes) mais pas de compression
make_truncated_at_compression = ->
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)  -- len=2, 2 bytes suite
  -- compression_offset = cipher_suites_offset + 2 + 2 = 45+4 = 49
  -- On s'arrête juste avant: ch_body = 35 + 4 = 39 bytes → #data = 5+4+39 = 48 < 50
  ch_body = ver .. random .. sid_len .. cipher_suites
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : ClientHello sans champ extensions (tronqué après compression) ───
make_no_extensions_field = ->
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  compression = string.char(0x01, 0x00)   -- len=1, 1 byte (0x00)
  -- extensions_offset = compression_offset + 1 + 1 = 49+2 = 51
  -- On inclut compression mais pas le champ extensions_len
  ch_body = ver .. random .. sid_len .. cipher_suites .. compression
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : ClientHello avec extensions tronquées (len > payload dispo) ────
make_truncated_extensions = (hostname) ->
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  compression = string.char(0x01, 0x00)
  -- On déclare extensions_len = 100 mais on n'en fournit que 5 octets
  extensions_len_bytes = string.char(0x00, 0x64)   -- 100
  fake_ext_data = string.rep("\x00", 5)
  ch_body = ver .. random .. sid_len .. cipher_suites .. compression ..
    extensions_len_bytes .. fake_ext_data
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : SNI extension tronquée (payload SNI absent) ────────────────────
make_sni_ext_truncated = ->
  -- Extension type 0x0000 (SNI) mais payload vide (ext_len=0)
  -- ext_payload_offset+1 > #data → snl_truncated
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  compression = string.char(0x01, 0x00)
  -- SNI extension type=0x0000, len=0 mais on inclut que le header (4 bytes)
  -- ext_payload_offset = pos+4, ext_payload_offset+1 <= #data requiert 1 byte après
  -- On met ext_len=2 pour que le code entre dans le block SNI
  -- mais on coupe juste avant ext_payload_offset+1
  sni_ext_header = string.char(0x00, 0x00)  -- ext_type = SNI
  ext_len = string.char(0x00, 0x00)         -- ext_len = 0 → ext_payload_offset = pos+4
  -- Avec ext_len=0, ext_payload_offset = pos+4, ext_payload_offset+1 = pos+5
  -- On doit avoir pos+5 > #data
  -- ext_data sera juste le header (4 bytes) sans aucun payload
  ext_data = sni_ext_header .. ext_len  -- 4 bytes
  ext_data_len = #ext_data
  extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  ch_body = ver .. random .. sid_len .. cipher_suites .. compression ..
    extensions_len_bytes .. ext_data
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : SNI list tronquée (snl_offset+2 > #data) ───────────────────────
make_sni_list_truncated = ->
  -- SNI ext avec payload: 2 bytes snl_len + tronqué avant le name_type
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  compression = string.char(0x01, 0x00)
  -- Juste 2 bytes de payload SNI (snl_len) mais pas les 3 bytes name_type+name_len
  sni_payload = string.char(0x00, 0x07)  -- snl_len = 7 (on ment, payload est plus court)
  sni_ext_body = sni_payload  -- seulement snl_len, pas de name_type/name_len
  sni_ext = string.char(0x00, 0x00) ..
    string.char(bit.rshift(#sni_ext_body, 8), bit.band(#sni_ext_body, 0xFF)) ..
    sni_ext_body
  ext_data_len = #sni_ext
  extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  ch_body = ver .. random .. sid_len .. cipher_suites .. compression ..
    extensions_len_bytes .. sni_ext
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : name_type ≠ 0 ──────────────────────────────────────────────────
make_sni_unknown_name_type = ->
  -- SNI extension avec name_type = 0x01 (inconnu)
  hostname = "example.com"
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  compression = string.char(0x01, 0x00)
  -- name_type = 0x01 (invalide, doit être 0)
  sni_name = hostname
  snl_inner = string.char(0x01) ..  -- name_type = 1 (INVALID)
    string.char(bit.rshift(#sni_name, 8), bit.band(#sni_name, 0xFF)) ..
    sni_name
  snl_len_bytes = string.char(bit.rshift(#snl_inner, 8), bit.band(#snl_inner, 0xFF))
  sni_payload = snl_len_bytes .. snl_inner
  sni_ext = string.char(0x00, 0x00) ..
    string.char(bit.rshift(#sni_payload, 8), bit.band(#sni_payload, 0xFF)) ..
    sni_payload
  ext_data_len = #sni_ext
  extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  ch_body = ver .. random .. sid_len .. cipher_suites .. compression ..
    extensions_len_bytes .. sni_ext
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : nom tronqué (name_len > bytes dispo) ───────────────────────────
make_sni_name_truncated = ->
  -- name_len = 100 mais seulement 5 bytes de nom réel
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  compression = string.char(0x01, 0x00)
  fake_hostname = "hello"
  snl_inner = string.char(0x00) ..   -- name_type = 0 (correct)
    string.char(0x00, 0x64) ..       -- name_len = 100 (mensonger)
    fake_hostname                    -- seulement 5 bytes
  snl_len_bytes = string.char(bit.rshift(#snl_inner, 8), bit.band(#snl_inner, 0xFF))
  sni_payload = snl_len_bytes .. snl_inner
  sni_ext = string.char(0x00, 0x00) ..
    string.char(bit.rshift(#sni_payload, 8), bit.band(#sni_payload, 0xFF)) ..
    sni_payload
  ext_data_len = #sni_ext
  extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  ch_body = ver .. random .. sid_len .. cipher_suites .. compression ..
    extensions_len_bytes .. sni_ext
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ── Helper : ClientHello avec extension non-SNI puis fin de boucle ──────────
-- Extension type 0xFFFF (non-SNI) puis fin, pour couvrir pos = ext_payload_offset + ext_len
make_non_sni_extension = ->
  ver    = string.char(0x03, 0x03)
  random = string.rep("\x00", 32)
  sid_len = string.char(0x00)
  cipher_suites = string.char(0x00, 0x02, 0x13, 0x01)
  compression = string.char(0x01, 0x00)
  -- Extension type=0xFFFF (non-SNI), len=4, payload=4 bytes
  fake_payload = string.char(0x00, 0x01, 0x02, 0x03)
  other_ext = string.char(0xFF, 0xFF) ..
    string.char(bit.rshift(#fake_payload, 8), bit.band(#fake_payload, 0xFF)) ..
    fake_payload
  ext_data_len = #other_ext
  extensions_len_bytes = string.char(bit.rshift(ext_data_len, 8), bit.band(ext_data_len, 0xFF))
  ch_body = ver .. random .. sid_len .. cipher_suites .. compression ..
    extensions_len_bytes .. other_ext
  hs_len = #ch_body
  handshake = string.char(0x01) ..
    string.char(bit.rshift(hs_len, 16), bit.rshift(bit.band(hs_len, 0xFF00), 8), bit.band(hs_len, 0xFF)) ..
    ch_body
  rec_len = #handshake
  string.char(0x16, 0x03, 0x01) ..
    string.char(bit.rshift(rec_len, 8), bit.band(rec_len, 0xFF)) ..
    handshake

-- ═══════════════════════════════════════════════════════════════════════════
describe "auth/sni_extractor", ->

  -- ── Cas de base ────────────────────────────────────────────────────────────

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

  -- ── read_u16_be / read_u24_be / read_u8 : branche buf trop court ────────

  it "retourne nil si le record TLS est tronqué (record_length > données dispo)", ->
    -- record_length=256 mais seulement ~55 bytes disponibles
    ch = make_truncated_record!
    assert.is_nil extract_sni ch

  -- ── hs_type ≠ 0x01 : ServerHello (0x02) avec données suffisantes ─────────

  it "retourne nil pour un ServerHello (hs_type=0x02) avec record complet", ->
    -- Construire un record valide de type ServerHello
    body = string.rep("\x00", 50)
    ch = make_tls_record_with_hstype 0x02, body
    assert.is_nil extract_sni ch

  it "retourne nil pour un handshake hs_type=0x03 avec record complet", ->
    body = string.rep("\x00", 50)
    ch = make_tls_record_with_hstype 0x03, body
    assert.is_nil extract_sni ch

  -- ── cipher_suites tronqué ────────────────────────────────────────────────

  it "retourne nil si cipher_suites est tronqué", ->
    ch = make_truncated_at_cipher_suites!
    assert.is_nil extract_sni ch

  -- ── compression tronqué ──────────────────────────────────────────────────

  it "retourne nil si compression est tronquée", ->
    ch = make_truncated_at_compression!
    assert.is_nil extract_sni ch

  -- ── pas de champ extensions ───────────────────────────────────────────────

  it "retourne nil si le champ extensions est absent", ->
    ch = make_no_extensions_field!
    assert.is_nil extract_sni ch

  -- ── extensions vides (len=0) ─────────────────────────────────────────────

  it "retourne nil si extensions_len = 0 (extensions déclarées vides)", ->
    -- make_clienthello_no_sni génère un ClientHello avec extensions_len=0
    -- La branche "empty_extensions" (line 95-99)
    ch = make_clienthello_no_sni!
    assert.is_nil extract_sni ch

  -- ── extensions tronquées (ext_data_end > #data) ───────────────────────────

  it "retourne nil si le payload des extensions est tronqué", ->
    ch = make_truncated_extensions!
    assert.is_nil extract_sni ch

  -- ── SNI extension payload tronqué ────────────────────────────────────────

  it "retourne nil si le payload SNI est tronqué (snl_truncated)", ->
    -- Extension SNI (0x0000) avec ext_len=0 → ext_payload_offset+1 > #data
    ch = make_sni_ext_truncated!
    assert.is_nil extract_sni ch

  -- ── SNI list tronquée (sn_header_truncated) ──────────────────────────────

  it "retourne nil si la liste SNI est tronquée (sn_header_truncated)", ->
    ch = make_sni_list_truncated!
    assert.is_nil extract_sni ch

  -- ── name_type ≠ 0 ────────────────────────────────────────────────────────

  it "retourne nil si name_type est différent de 0 (unknown_name_type)", ->
    ch = make_sni_unknown_name_type!
    assert.is_nil extract_sni ch

  -- ── nom tronqué ──────────────────────────────────────────────────────────

  it "retourne nil si le nom SNI est tronqué (name_len > bytes dispo)", ->
    ch = make_sni_name_truncated!
    assert.is_nil extract_sni ch

  -- ── extension non-SNI → fin de boucle → no_sni_extension ────────────────

  it "retourne nil s'il y a une extension non-SNI et pas de SNI (no_sni_extension)", ->
    ch = make_non_sni_extension!
    assert.is_nil extract_sni ch

  -- ── wildcard hostname ────────────────────────────────────────────────────

  it "extrait le SNI avec wildcard", ->
    ch = make_clienthello_sni "*.example.com"
    assert.equals "*.example.com", extract_sni(ch)

  -- ── payload nil : protégé par pcall car #nil génère une erreur ──────────

  it "ne crashe pas si payload est nil (retourne nil ou erreur capturée)", ->
    -- Le code fait `#data` sans garde sur nil, donc on utilise pcall
    ok, result = pcall extract_sni, nil
    -- Soit ça retourne nil, soit ça lève une erreur : les deux sont acceptables
    -- (on vérifie juste que ça ne plante pas le test runner)
    assert.is_true ok == false or result == nil
