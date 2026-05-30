-- tests/unit/worker_doh_spec.moon
-- Tests unitaires du worker DoH : fonctions pures de parsing HTTP/DNS.
-- La détection PRI (HTTP/2 sans ALPN) est couverte par le test E2E G12.

ffi = require "ffi"

-- Stubs minimaux pour charger worker_doh sans dépendances runtime.
package.loaded["config"] = package.loaded["config"] or {
  doh:     { enabled: true, port: 8443, upstream_ipv4: "1.1.1.3",
             upstream_ipv6: "", upstream_port: 53, upstream_timeout_ms: 2000,
             cert: nil, key: nil, prefer_ipv6: false }
  runtime: { log_level: "INFO", benchmark: false }
  nft:     { family: "bridge", ip_timeout: "5m" }
  filter:  { rules: {}, default_rules: {}, decision: {}, sources: {},
             nets: {}, macs: {}, times: {}, userlists: {}, users: {} }
  auth:    { port: 33443 }
  sni:     {}
}
package.loaded["log"] = {
  debug: (->), info: (->), warn: (->), error: (->)
  rate_limited: (-> (->))
}
package.loaded["mac_learner_ipc"] = { get_mac: (ip) -> nil }
package.loaded["doh.upstream"]    = {
  new_client: (ip, port, ms) -> {}, nil
  query:      (c, raw)        -> nil, "stub"
  close:      (c)             -> nil
  probe_ipv6: (ip, port)      -> false
}
package.loaded["doh.query"]       = {
  process_query: (raw, ip, mac, up) -> nil, "stub"
}
package.loaded["auth.cert_cache"] = {
  create_cache: (n, ttl) -> { set: (->), get: (-> nil), stats: (-> {size:0}) }
}
package.loaded["auth.cert"]       = {
  load_static:            (k, c) -> nil, "stub"
  load_or_generate_sni:   (ip, cache) -> nil, "stub"
}
package.loaded["auth.ffi_wolfssl"] = {
  wrap: (sock, ctx) -> nil, "stub"
}
package.loaded["lib.socket"]  = { tcp: (-> nil), tcp6: (-> nil), select: (-> {}, {}) }
package.loaded["lib.process"] = { fork_child: (-> 1) }
package.loaded["lib.http"]    = { read_request: (-> nil, "stub"), send_response: (->) }

doh = require "worker_doh"

-- ── b64url_decode ─────────────────────────────────────────────────────────────

describe "worker_doh.b64url_decode", ->

  it "décode une chaîne base64url valide (requête DNS example.com A)", ->
    -- "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    raw = doh.b64url_decode "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
    assert.is_not_nil raw
    assert.is_true #raw > 0, "doit retourner des octets"
    -- Les 2 premiers octets sont le transaction ID (0x0000 dans cet exemple)
    assert.equals 0, raw\byte 1
    assert.equals 0, raw\byte 2

  it "décode correctement sans padding (base64url standard)", ->
    -- "dGVzdA" = "test" en base64url (sans padding)
    result = doh.b64url_decode "dGVzdA"
    assert.equals "test", result

  it "retourne une chaîne vide si entrée vide", ->
    result = doh.b64url_decode ""
    assert.equals "", result

  it "tolère le padding explicite", ->
    result = doh.b64url_decode "dGVzdA=="
    assert.equals "test", result

-- ── query_param ──────────────────────────────────────────────────────────────

describe "worker_doh.query_param", ->

  it "extrait un paramètre simple", ->
    assert.equals "google.com", doh.query_param "/dns-query?name=google.com&type=A", "name"

  it "extrait le type", ->
    assert.equals "A", doh.query_param "/dns-query?name=google.com&type=A", "type"

  it "retourne nil si paramètre absent", ->
    assert.is_nil doh.query_param "/dns-query?name=google.com", "type"

  it "fonctionne avec le paramètre dns", ->
    assert.equals "AAABAAABAAAAAAAAA", doh.query_param "/dns-query?dns=AAABAAABAAAAAAAAA", "dns"

-- ── build_dns_query ──────────────────────────────────────────────────────────

describe "worker_doh.build_dns_query", ->

  it "construit une requête A valide", ->
    raw = doh.build_dns_query "example.com", 1  -- type A = 1
    assert.is_not_nil raw
    assert.is_true #raw >= 12, "header DNS = 12 octets minimum"
    -- Structure fin : QTYPE (2 octets) + QCLASS (2 octets)
    -- QTYPE A = 0x0001 : octet de poids fort = 0, poids faible = 1
    assert.equals 0, raw\byte(#raw - 3)
    assert.equals 1, raw\byte(#raw - 2)

  it "construit une requête AAAA valide", ->
    raw = doh.build_dns_query "example.com", 28  -- type AAAA = 28 = 0x001C
    assert.is_not_nil raw
    -- QTYPE AAAA = 0x001C
    assert.equals 0,  raw\byte(#raw - 3)
    assert.equals 28, raw\byte(#raw - 2)

  it "retourne nil pour un nom de domaine nil", ->
    raw = doh.build_dns_query nil, 1
    assert.is_nil raw

  it "retourne nil pour un nom de domaine vide", ->
    raw = doh.build_dns_query "", 1
    assert.is_nil raw
