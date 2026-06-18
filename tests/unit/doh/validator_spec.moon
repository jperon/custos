-- tests/unit/doh/validator_spec.moon
-- Tests unitaires de doh.validator.query_verdict.
-- doh.upstream est stubbé pour éviter toute I/O réseau.

sp = require("ipparse.lib.pack_compat").pack

-- Construit une réponse DNS minimale avec un rcode donné.
make_response = (rcode=0, txid=0x1234) ->
  -- QR=1 RA=1, rcode dans les 4 bits bas du 4e octet des flags
  flags = 0x8180 + rcode
  sp ">H H H H H H", txid, flags, 0, 0, 0, 0

-- Résolveurs stub : premier répond avec `resp`, second répond avec `resp2`.
-- `nil` simule un timeout/erreur réseau.
make_upstream_stub = (resp, resp2=nil) ->
  call = 0
  {
    new_client: (ip, port, timeout) -> { fd: 1, upstream_ip: ip, upstream_port: port }
    query: (client, raw) ->
      call += 1
      r = if call == 1 then resp else resp2
      r and r or nil, (r and nil or "timeout")
    close: (->)
  }

eval_log = (f) -> (type(f) == "function") and f!
package.loaded["log"] = {
  log_warn: eval_log, log_debug: eval_log, log_info: eval_log
}

-- Stub doh.upstream_doh : retourne un handle avec _mod, query renvoie resp.
make_doh_upstream_stub = (resp) ->
  call = 0
  mod = {}
  mod.new_client = (url, timeout) ->
    assert.is_string url, "new_client: url doit être une string (pas #{type url})"
    { url: url, _mod: mod }
  mod.query = (client, raw) ->
    call += 1
    resp and resp or nil, (resp and nil or "doh_timeout")
  mod.close = (->)
  mod

-- Charge le module après avoir positionné les stubs dans package.loaded.
load_validator = (upstream_stub, curl_stub=nil) ->
  package.loaded["doh.upstream"]          = upstream_stub
  package.loaded["doh.upstream_doh_curl"] = curl_stub
  package.loaded["doh.validator"]         = nil
  require "doh.validator"

describe "doh.validator.query_verdict", ->

  it "NOERROR → non bloqué", ->
    mod = load_validator make_upstream_stub make_response 0
    blocked, reason = mod.query_verdict "dns_raw", { "1.1.1.1" }
    assert.is_false blocked
    assert.is_nil reason

  it "REFUSED → bloqué avec raison", ->
    mod = load_validator make_upstream_stub make_response 5
    blocked, reason = mod.query_verdict "dns_raw", { "1.1.1.1" }
    assert.is_true blocked
    assert.is_not_nil reason
    assert.truthy reason\find "REFUSED"

  it "NXDOMAIN → bloqué avec raison", ->
    mod = load_validator make_upstream_stub make_response 3
    blocked, reason = mod.query_verdict "dns_raw", { "1.1.1.1" }
    assert.is_true blocked
    assert.truthy reason\find "block"

  it "SERVFAIL (2) → non bloqué (fail-open)", ->
    mod = load_validator make_upstream_stub make_response 2
    blocked, _ = mod.query_verdict "dns_raw", { "1.1.1.1" }
    assert.is_false blocked

  it "premier résolveur KO → essaie le second", ->
    mod = load_validator make_upstream_stub nil, make_response(5)
    blocked, _ = mod.query_verdict "dns_raw", { "1.1.1.1", "2.2.2.2" }
    assert.is_true blocked

  it "tous les résolveurs KO → fail-open", ->
    mod = load_validator make_upstream_stub nil, nil
    blocked, _ = mod.query_verdict "dns_raw", { "1.1.1.1", "2.2.2.2" }
    assert.is_false blocked

  it "liste vide → fail-open", ->
    mod = load_validator make_upstream_stub make_response 5
    blocked, _ = mod.query_verdict "dns_raw", {}
    assert.is_false blocked

  it "réponse DNS illisible → essaie le suivant puis fail-open", ->
    upstream = {
      new_client: (ip, port, t) -> { fd: 1, upstream_ip: ip }
      query: (client, raw) -> "garbage_bytes", nil
      close: (->)
    }
    mod = load_validator upstream
    blocked, _ = mod.query_verdict "dns_raw", { "1.1.1.1" }
    assert.is_false blocked

  -- ── Endpoints DoH (https://) ─────────────────────────────────────────────

  it "endpoint DoH REFUSED → bloqué", ->
    doh_stub = make_doh_upstream_stub make_response 5
    mod = load_validator (make_upstream_stub nil), doh_stub
    blocked, reason = mod.query_verdict "dns_raw", { "https://1.1.1.1/dns-query" }
    assert.is_true blocked
    assert.truthy reason\find "REFUSED"

  it "endpoint DoH NOERROR → non bloqué", ->
    doh_stub = make_doh_upstream_stub make_response 0
    mod = load_validator (make_upstream_stub nil), doh_stub
    blocked, _ = mod.query_verdict "dns_raw", { "https://1.1.1.1/dns-query" }
    assert.is_false blocked

  it "endpoint DoH KO → fail-open", ->
    doh_stub = make_doh_upstream_stub nil
    mod = load_validator (make_upstream_stub nil), doh_stub
    blocked, _ = mod.query_verdict "dns_raw", { "https://1.1.1.1/dns-query" }
    assert.is_false blocked

  it "liste mixte IP + DoH : IP KO, DoH REFUSED → bloqué", ->
    doh_stub = make_doh_upstream_stub make_response 5
    up_stub  = make_upstream_stub nil   -- IP résolveur KO
    mod = load_validator up_stub, doh_stub
    blocked, reason = mod.query_verdict "dns_raw", { "1.1.1.1", "https://9.9.9.9/dns-query" }
    assert.is_true blocked
    assert.truthy reason\find "REFUSED"

-- Réponse DNS NOERROR avec un answer A donné (rdata 4 octets).
make_a_response = (rdata, txid=0x1234) ->
  question = "\3foo\3bar\0" .. sp ">H H", 1, 1   -- A, IN
  answer   = "\192\012" .. sp ">H H I4 s2", 1, 1, 60, rdata
  (sp ">H H H H H H", txid, 0x8180, 1, 1, 0, 0) .. question .. answer

describe "doh.validator.query_classified", ->

  it "NXDOMAIN → override block", ->
    mod = load_validator make_upstream_stub make_response 3
    override = mod.query_classified "dns_raw", { "1.1.1.1" }
    assert.equals "block", override.kind

  it "REFUSED → override block", ->
    mod = load_validator make_upstream_stub make_response 5
    override = mod.query_classified "dns_raw", { "1.1.1.1" }
    assert.equals "block", override.kind

  it "NOERROR sans answer → pass (nil)", ->
    mod = load_validator make_upstream_stub make_response 0
    override = mod.query_classified "dns_raw", { "1.1.1.1" }
    assert.is_nil override

  it "réponse A 0.0.0.0 → override sinkhole", ->
    mod = load_validator make_upstream_stub make_a_response "\0\0\0\0"
    override = mod.query_classified "dns_raw", { "1.1.1.1" }
    assert.equals "sinkhole", override.kind
    assert.equals 1, #override.a

  it "tous KO → pass (nil)", ->
    mod = load_validator make_upstream_stub nil, nil
    override = mod.query_classified "dns_raw", { "1.1.1.1", "2.2.2.2" }
    assert.is_nil override
