-- tests/unit/worker_tls_sni_spec.moon
-- Couverture du cœur du parsing SNI de worker_tls : extraction TLS (HTTPS
-- "standard"), garde-fous QUIC, flow key, et éviction TTL des sessions QUIC.

bit = require "bit"
{ :rshift, :band } = bit

sni = require "worker_tls"

-- Encode un entier sur 2 octets big-endian.
u16 = (n) -> string.char rshift(n, 8), band(n, 0xFF)

-- ── Builders de ClientHello TLS ────────────────────────────────────

-- Extension server_name (type 0x0000) encapsulant `hostname`.
make_sni_ext = (hostname) ->
  name_len = #hostname
  list_len = name_len + 3          -- name_type(1) + name_len(2) + name
  ext_len  = list_len + 2          -- list_len(2) + list
  table.concat {
    u16 0x0000                      -- ext_type = server_name
    u16 ext_len
    u16 list_len
    string.char 0x00                -- name_type = host_name
    u16 name_len
    hostname
  }

-- Extension supported_versions (type 0x002b) annonçant TLS 1.3.
make_supported_versions_ext = ->
  body = string.char 0x02, 0x03, 0x04   -- list_len(1)=2 + version 0x0304
  table.concat { u16(0x002b), u16(#body), body }

-- Assemble un enregistrement TLS Handshake/ClientHello complet.
build_client_hello = (extensions_bin, opts={}) ->
  ch_body = table.concat {
    string.char 0x03, 0x03                  -- legacy_version TLS1.2
    string.rep "\0", 32                     -- random
    string.char 0x00                        -- session_id_len = 0
    string.char 0x00, 0x02, 0x13, 0x01      -- cipher_suites
    string.char 0x01, 0x00                  -- compression_methods
    u16 #extensions_bin
    extensions_bin
  }
  hs_len = #ch_body
  hs_len_bin = string.char band(rshift(hs_len, 16), 0xFF), band(rshift(hs_len, 8), 0xFF), band(hs_len, 0xFF)
  handshake = table.concat {
    string.char opts.hs_type or 0x01
    hs_len_bin
    ch_body
  }
  rec_len = #handshake
  table.concat {
    string.char opts.record_type or 0x16
    string.char 0x03, 0x03
    u16 rec_len
    handshake
  }

describe "worker_tls extract_sni_from_tls (HTTPS/TLS)", ->
  it "extrait le SNI d'un ClientHello complet via ipparse (chemin strict)", ->
    payload = build_client_hello make_sni_ext "example.com"
    host, reason, meta = sni.extract_sni_from_tls payload
    assert.equals "example.com", host
    assert.is_nil reason
    -- Un ClientHello complet doit être parsé par ipparse (chemin strict),
    -- pas par le fallback tolérant réservé aux paquets tronqués/segmentés.
    assert.equals "strict", meta.tls_parser_path

  it "extrait le SNI quand il suit une autre extension", ->
    exts = make_supported_versions_ext! .. make_sni_ext "alt.example.org"
    host = sni.extract_sni_from_tls build_client_hello exts
    assert.equals "alt.example.org", host

  it "remonte la version TLS négociée (supported_versions)", ->
    exts = make_supported_versions_ext! .. make_sni_ext "v13.example"
    host, _, meta = sni.extract_sni_from_tls build_client_hello exts
    assert.equals "v13.example", host
    assert.equals "TLS1.3", meta.tls_supported_version

  it "renvoie nil + raison si l'enregistrement n'est pas un handshake", ->
    payload = build_client_hello make_sni_ext("x.example"), record_type: 0x17
    host, reason = sni.extract_sni_from_tls payload
    assert.is_nil host
    assert.equals "not_handshake_record", reason

  it "renvoie nil + raison si le handshake n'est pas un ClientHello", ->
    payload = build_client_hello make_sni_ext("x.example"), hs_type: 0x02
    host, reason = sni.extract_sni_from_tls payload
    assert.is_nil host
    assert.equals "not_client_hello", reason

  it "renvoie nil + short_payload sur payload trop court", ->
    host, reason = sni.extract_sni_from_tls "\x16\x03\x03\x00"
    assert.is_nil host
    assert.equals "short_payload", reason

  it "renvoie nil + no_sni quand l'extension SNI est absente", ->
    host, reason = sni.extract_sni_from_tls build_client_hello make_supported_versions_ext!
    assert.is_nil host
    assert.equals "no_sni_in_extensions", reason

describe "worker_tls quic_flow_key", ->
  it "est symétrique (même clé pour les deux sens du flux)", ->
    a = sni.quic_flow_key "10.0.0.1", "8.8.8.8", 4000, 443
    b = sni.quic_flow_key "8.8.8.8", "10.0.0.1", 443, 4000
    assert.equals a, b

  it "distingue les ports", ->
    a = sni.quic_flow_key "10.0.0.1", "8.8.8.8", 4000, 443
    b = sni.quic_flow_key "10.0.0.1", "8.8.8.8", 4001, 443
    assert.not_equals a, b

  it "tolère des champs nil", ->
    k = sni.quic_flow_key nil, nil, nil, nil
    assert.is_string k

describe "worker_tls extract_sni_from_quic (garde-fous)", ->
  it "rejette un payload trop court", ->
    host, reason, meta = sni.extract_sni_from_quic "\x00\x01"
    assert.is_nil host
    assert.equals "short_payload", reason
    assert.equals "none", meta.quic_parser_path

  it "ne plante pas et renvoie une raison quic_* sur en-tête non-Initial", ->
    -- En-tête court (bit high = 0) → non long-header / non Initial.
    host, reason = sni.extract_sni_from_quic string.rep("\x40", 32)
    assert.is_nil host
    assert.is_truthy reason\match "^quic_"

describe "worker_tls éviction des sessions QUIC", ->
  before_each -> sni.reset_quic_sessions!

  it "démarre à zéro", ->
    assert.equals 0, sni.quic_session_count!

  it "évince les flux inactifs au-delà du TTL", ->
    now = 1000000
    sni.seed_quic_session "old", now - 60   -- > TTL (30s)
    sni.seed_quic_session "fresh", now - 5  -- < TTL
    assert.equals 2, sni.quic_session_count!

    removed = sni.prune_quic_sessions now
    assert.equals 1, removed
    assert.equals 1, sni.quic_session_count!

  it "ne touche pas aux flux récents", ->
    now = 2000000
    sni.seed_quic_session "a", now
    sni.seed_quic_session "b", now - 1
    assert.equals 0, sni.prune_quic_sessions now
    assert.equals 2, sni.quic_session_count!

  it "reset_quic_sessions vide tout", ->
    sni.seed_quic_session "x"
    sni.reset_quic_sessions!
    assert.equals 0, sni.quic_session_count!

describe "worker_tls réassemblage TLS fragmenté (feed_tls_segment)", ->
  before_each -> sni.reset_tcp_sessions!

  PSH_ACK = 0x18

  it "réassemble un ClientHello scindé sur deux segments TCP", ->
    record = build_client_hello make_sni_ext "split.example.com"
    cut = math.floor #record / 2
    seg1 = record\sub 1, cut
    seg2 = record\sub cut + 1

    -- 1er segment : record incomplet → rien à extraire encore.
    assert.is_nil sni.feed_tls_segment "flow", seg1, PSH_ACK, 1000
    -- 2e segment : record complet → buffer reconstitué.
    buf = sni.feed_tls_segment "flow", seg2, PSH_ACK, 1000 + cut
    assert.equals record, buf

    host = sni.extract_sni_from_tls buf
    assert.equals "split.example.com", host

  it "rend immédiatement un ClientHello non fragmenté", ->
    record = build_client_hello make_sni_ext "whole.example"
    buf = sni.feed_tls_segment "flow", record, PSH_ACK, 1
    assert.equals record, buf

  it "ne bufferise pas le trafic 443 non-TLS (premier octet != 0x16)", ->
    -- Données applicatives (record type 0x17) : livrées telles quelles, sans
    -- accumulation, pour éviter de retenir des flux établis en mémoire.
    appdata = "\x17\x03\x03\x00\x05hello"
    buf = sni.feed_tls_segment "flow", appdata, PSH_ACK, 1
    assert.equals appdata, buf

  it "isole les flux distincts par clé", ->
    record = build_client_hello make_sni_ext "a.example"
    cut = math.floor #record / 2
    assert.is_nil sni.feed_tls_segment "flowA", record\sub(1, cut), PSH_ACK, 1
    -- Un autre flux ne doit pas voir le fragment de flowA.
    other = build_client_hello make_sni_ext "b.example"
    assert.equals other, sni.feed_tls_segment "flowB", other, PSH_ACK, 1

  it "bufferise un fragment Handshake plus court que l'en-tête de record", ->
    -- Premier segment de moins de 5 octets : impossible de lire la longueur du
    -- record → on attend la suite (tls_record_complete renvoie false).
    assert.is_nil sni.feed_tls_segment "flow", "\x16\x03", PSH_ACK, 1
    record = build_client_hello make_sni_ext "tiny.example"
    -- Le reste du record complète le ClientHello.
    buf = sni.feed_tls_segment "flow", record\sub(3), PSH_ACK, 3
    assert.equals record, buf

  it "déclenche la purge périodique sans perdre l'état actif", ->
    -- 512 segments non-TLS (livrés immédiatement) franchissent le seuil de purge.
    appdata = "\x17\x03\x03\x00\x01x"
    sni.feed_tls_segment "noise", appdata, PSH_ACK, i for i = 1, 512
    -- Un ClientHello complet reste correctement extrait après la purge.
    record = build_client_hello make_sni_ext "after.purge"
    assert.equals record, sni.feed_tls_segment "flow", record, PSH_ACK, 1

  it "abandonne le buffer sur FIN/RST", ->
    record = build_client_hello make_sni_ext "reset.example"
    cut = math.floor #record / 2
    assert.is_nil sni.feed_tls_segment "flow", record\sub(1, cut), PSH_ACK, 1
    -- Segment RST : efface la session, renvoie nil.
    assert.is_nil sni.feed_tls_segment "flow", record\sub(cut + 1), 0x04, 1 + cut
    -- Le flux repart de zéro : un nouveau record complet est rendu directement.
    assert.equals record, sni.feed_tls_segment "flow", record, PSH_ACK, 9000

  it "rend immédiatement un record Handshake non-ClientHello après un ClientHello (mode integral)", ->
    -- Scénario mode integral : ClientHello, puis Client Key Exchange (0x10) sur
    -- la même clé de flux.  Après que tcp_stream a consommé et effacé le
    -- ClientHello, le Client Key Exchange arrive en nouveau flux ; il doit être
    -- retourné immédiatement par feed_tls_segment (tls_record_complete = true
    -- pour tout record 0x16 de longueur valide) afin que le handler puisse
    -- l'identifier comme non-ClientHello et rendre NF_ACCEPT sans appeler
    -- extract_sni_from_tls.
    ch = build_client_hello make_sni_ext "integral.example"
    -- 1. Le ClientHello est consommé normalement.
    assert.equals ch, sni.feed_tls_segment "conn", ch, PSH_ACK, 1
    -- 2. Client Key Exchange : record Handshake (0x16) de type 0x10.
    cke_body = "\x10\x00\x00\x02\xab\xcd"  -- type=ClientKeyExchange, len=2, body
    cke_record = "\x16\x03\x03" .. u16(#cke_body) .. cke_body
    -- Rendu immédiatement (session effacée, record complet dès le premier segment).
    buf = sni.feed_tls_segment "conn", cke_record, PSH_ACK, 1 + #ch
    assert.equals cke_record, buf
    -- 3. Le buffer doit être identifiable comme non-ClientHello via ipparse.
    tls = require "ipparse.l7.tls"
    hs  = require "ipparse.l7.tls.handshake"
    ok_rec, rec = pcall -> tls.parse buf, 1
    assert.is_true ok_rec
    assert.equals tls.record_types.handshake, rec.type
    ok_hs, hdr = pcall -> hs.parse buf, rec.data_off
    assert.is_true ok_hs
    assert.not_equal hs.message_types.client_hello, hdr.type
