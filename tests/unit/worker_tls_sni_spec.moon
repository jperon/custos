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

describe "worker_tls extract_sni_from_tls (repli tolérant, paquets tronqués)", ->
  full = -> build_client_hello make_sni_ext "fallback.example"

  it "payload trop court avant le random → fallback_short_random", ->
    host, reason = sni.extract_sni_from_tls (full!)\sub(1, 20)
    assert.is_nil host
    assert.equals "fallback_short_random", reason

  it "longueur de session_id incohérente → fallback_short_session_id", ->
    p = (full!)\sub(1, 50)
    p = p\sub(1, 43) .. string.char(200) .. p\sub(45)
    host, reason = sni.extract_sni_from_tls p
    assert.is_nil host
    assert.equals "fallback_short_session_id", reason

  it "cipher suites tronquées → fallback_short_cipher_len/cipher_suites", ->
    _, r1 = sni.extract_sni_from_tls (full!)\sub(1, 44)
    assert.equals "fallback_short_cipher_len", r1
    _, r2 = sni.extract_sni_from_tls (full!)\sub(1, 47)
    assert.equals "fallback_short_cipher_suites", r2

  it "compression et extensions tronquées → raisons dédiées", ->
    _, r1 = sni.extract_sni_from_tls (full!)\sub(1, 49)
    assert.equals "fallback_short_compression", r1
    _, r2 = sni.extract_sni_from_tls (full!)\sub(1, 51)
    assert.equals "fallback_short_extensions_len", r2

  it "extension SNI trop courte → fallback_short_sni_ext", ->
    short_ext = table.concat { u16(0x0000), u16(3), "abc" }
    host, reason = sni.extract_sni_from_tls build_client_hello short_ext
    assert.is_nil host
    assert.equals "fallback_short_sni_ext", reason

  it "nomme les versions TLS 1.0/1.1 et une version inconnue", ->
    -- Mutation directe des octets 10-11 (legacy_version du ClientHello).
    for case in *{
      { 0x0301, "TLS1.0" }
      { 0x0302, "TLS1.1" }
      { 0x0300, "0x0300" }
    }
      p = full!
      p = p\sub(1, 9) .. string.char(rshift(case[1], 8), band(case[1], 0xFF)) .. p\sub(12)
      _, _, meta = sni.extract_sni_from_tls p
      assert.equals case[2], meta.tls_client_hello_version

describe "worker_tls sni_action_for (décision pure)", ->
  it "fail-open si le filtre est absent ou lève", ->
    assert.equals "accept", sni.sni_action_for nil
    assert.equals "accept", sni.sni_action_for {}

  it "mappe verdict et modificateurs vers l'action symbolique", ->
    assert.equals "block", sni.sni_action_for { verdict: false }
    assert.equals "dnsonly", sni.sni_action_for { verdict: "dnsonly" }
    assert.equals "redirect", sni.sni_action_for { verdict: true, redirects_destination: true }
    assert.equals "validate", sni.sni_action_for { verdict: true, allow_modifiers: { validate: true } }
    assert.equals "allow", sni.sni_action_for { verdict: true }

describe "worker_tls sessions QUIC (seams)", ->
  it "seed/count/prune/reset suivent les sessions et leur TTL", ->
    sni.reset_quic_sessions!
    assert.equals 0, sni.quic_session_count!
    assert.equals 1, sni.seed_quic_session "k1", 100
    assert.equals 2, sni.seed_quic_session "k2", 100
    -- Le seed d'une clé existante ne recompte pas.
    assert.equals 2, sni.seed_quic_session "k1", 150
    assert.equals 1, sni.prune_quic_sessions 151
    assert.equals 1, sni.quic_session_count!
    sni.reset_quic_sessions!
    assert.equals 0, sni.quic_session_count!

describe "worker_tls validate_sni et cache de verdict", ->
  before_each ->
    sni.reset_sni_verdicts!

  after_each ->
    sni.reset_sni_verdicts!
    sni.set_validator_state { validator_mod: nil, cname_mod: nil, second_opinion_cfg: nil }

  it "sans domaine ou sans résolveur → non bloqué avec raison", ->
    assert.same { false, nil }, { sni.validate_sni nil, true }
    sni.set_validator_state { second_opinion_cfg: { resolvers: {} } }
    blocked, reason = sni.validate_sni "x.test", true
    assert.is_false blocked
    assert.equals "no_validator_resolvers", reason

  it "interroge le validateur puis sert le cache pendant le TTL", ->
    calls = 0
    sni.set_validator_state {
      second_opinion_cfg: { resolvers: { "1.1.1.1" }, verdict_ttl_s: 30 }
      validator_mod: {
        query_verdict: (dns_raw, resolvers, budget, doh_budget) ->
          calls += 1
          true, "malware"
      }
    }
    blocked, reason = sni.validate_sni "bad.test", true
    assert.is_true blocked
    assert.equals "malware", reason
    assert.equals 1, calls
    blocked2, reason2 = sni.validate_sni "bad.test", true
    assert.is_true blocked2
    assert.equals "malware", reason2
    assert.equals 1, calls

  it "une exception du validateur est fail-open et n'empoisonne pas le cache", ->
    sni.set_validator_state {
      second_opinion_cfg: { resolvers: { "1.1.1.1" } }
      validator_mod: { query_verdict: -> error "boom" }
    }
    blocked, reason = sni.validate_sni "err.test", true
    assert.is_false blocked
    assert.is_nil reason
    -- Entrée cachée non bloquante : pas de nouvel appel nécessaire.
    blocked2 = sni.validate_sni "err.test", true
    assert.is_false blocked2

  it "prune_sni_verdicts purge les entrées expirées", ->
    sni.set_validator_state {
      second_opinion_cfg: { resolvers: { "1.1.1.1" }, verdict_ttl_s: 0 }
      validator_mod: { query_verdict: -> true, "x" }
    }
    sni.validate_sni "ttl.test", true
    removed = sni.prune_sni_verdicts os.time! + 10
    assert.is_true removed >= 1

describe "worker_tls build_validator_query et CNAME", ->
  it "construit une requête DNS A wire-format pour le domaine", ->
    q = sni.build_validator_query "sub.example.test"
    assert.equals 1, q\byte(3)                     -- flags hi: RD
    assert.equals 1, q\byte(6)                     -- qdcount = 1
    assert.equals 3, q\byte 13
    assert.equals "sub", q\sub 14, 16
    assert.equals 7, q\byte 17
    assert.equals "example", q\sub 18, 24
    assert.equals "test", q\sub 26, 29
    assert.equals 0, q\byte 30
    assert.equals 0x00, q\byte(#q - 3)             -- QTYPE A
    assert.equals 0x01, q\byte(#q - 2)

  it "dst_matches_cname échoue sans cible ou sans IP connue", ->
    assert.same { false, false }, { sni.dst_matches_cname nil, "1.2.3.4", 4 }
    assert.same { false, false }, { sni.dst_matches_cname "target.test", "unknown", 4 }
