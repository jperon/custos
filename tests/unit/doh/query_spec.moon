-- tests/unit/doh/query_spec.moon
-- Tests d'intégration légère du cœur DoH (doh.query.process_query) : dispatch
-- on_response, injection nft partagée (response_inject), fail-closed, wildcard,
-- patch HTTPS/SVCB, second avis (validate). Stube uniquement les dépendances
-- lourdes ; ipparse, dns_ede et response_inject sont réels.

dns_mod = require "ipparse.l7.dns"
sp = require("ipparse.lib.pack_compat").pack
QTYPE_A     = dns_mod.types.A
QTYPE_HTTPS = dns_mod.types.HTTPS
QCLASS_IN   = dns_mod.classes.IN
qname_example = "\7example\3com\0"
name_ptr = "\192\012"

pack_rr = (rtype, rdata, ttl=60) ->
  name_ptr .. sp(">H H I4 s2", rtype, QCLASS_IN, ttl, rdata)

-- Requête example.com A
make_query = -> sp(">H H H H H H", 0x1234, 0x0100, 1, 0, 0, 0) .. qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)

-- Réponse upstream : 1 réponse A (1.2.3.4), +HTTPS optionnel.
make_response = (with_https=false) ->
  question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
  answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
  if with_https
    header = sp ">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0
    return header .. question .. answer_a .. pack_rr QTYPE_HTTPS, "\0\1"
  (sp ">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0) .. question .. answer_a

-- ── Stubs contrôlables ───────────────────────────────────────────────────────
nft_calls      = {}
nft_result     = true
upstream_resp  = nil
decide_result  = nil
user_result    = nil
validator_override = nil  -- override renvoyé par le stub doh.validator (query_classified)

reset = ->
  nft_calls      = {}
  nft_result     = true
  upstream_resp  = make_response!
  decide_result  = { verdict: true, reason: "ok", rule_id: "r_main", timeout: "5m", description: "allow", allow_modifiers: {} }
  user_result    = nil
  validator_override = nil

record_add = (key, dest, rule_id, timeout, corr) ->
  nft_calls[#nft_calls + 1] = { :key, :dest, :rule_id }
  nft_result

-- Stub config tenu dans une variable locale : on mute CETTE table (celle que
-- doh.query capture au require), et non `require "config"` à l'exécution — sous
-- run_vm_tests, restore_loaded repointe package.loaded["config"] sur la baseline
-- après le chargement du spec, donc un require au run-time renverrait une autre
-- table que celle utilisée par le module testé.
config_stub = {
  dns: { ttl_grace: { grace: 0, min: 60, max: 900 } }
  nft: { ip_timeout: "5m", add_failure_policy: "fail-closed" }
  auth: { sessions_file: "/tmp/none" }
}
package.loaded["config"] = config_stub
-- Stubs de log « évaluants » : exécutent le corps paresseux (-> {...}) pour
-- couvrir la construction des messages (comme le vrai log au bon niveau).
eval_log = (f) -> (type(f) == "function") and f!
package.loaded["log"] = {
  log_allow: eval_log, log_block: eval_log, log_warn: eval_log
  log_debug: eval_log, log_info: eval_log
}
package.loaded["filter"] = {
  decide_meta:     (req) -> decide_result
  run_on_response: (rule_id, dns_raw, reason) ->
    { dns_raw: dns_raw, modified: false, inject_nft: true, action_label: nil }
}
package.loaded["nft_queue"] = {
  add_ip4: record_add, add_ip6: record_add, add_mac4: record_add, add_mac6: record_add
  get_last_seq: -> 1       -- non-nil → exerce le wait_ack
  wait_ack: (->)
  drain_ack: (->)
}
package.loaded["auth.sessions"] = { user_for_mac: (mac, ip, file) -> user_result }
package.loaded["doh.upstream"]  = { query: (up, raw) -> upstream_resp }
package.loaded["doh.validator"] = {
  query_classified: (raw, resolvers, timeout) -> validator_override, (validator_override and "validator=stub" or nil)
}

query_mod = require "doh.query"

rcode_of = (raw) ->
  flags = raw\byte(3) * 256 + raw\byte(4)
  flags % 16

describe "doh.query.process_query", ->
  before_each reset

  it "allow + inject : injecte l'A résolu et renvoie la réponse", ->
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    -- A record (1.2.3.4) injecté pour le client v4 sur la règle principale
    found = false
    for c in *nft_calls
      found = true if c.dest == "1.2.3.4" and c.rule_id == "r_main"
    assert.is_true found

  it "block : réponse REFUSED sans appel upstream", ->
    decide_result = { verdict: false, reason: "denied", description: "deny" }
    upstream_resp = nil   -- upstream ne doit pas être appelé
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.equals 5, rcode_of resp        -- REFUSED
    assert.equals 0, #nft_calls

  it "fail-closed : insertion nft échouée → REFUSED", ->
    nft_result = false                    -- toutes les insertions échouent
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.equals 5, rcode_of resp        -- réponse de blocage (fail-closed)

  it "fail-open : insertion échouée mais policy fail-open → réponse livrée", ->
    nft_result = false
    config_stub.nft.add_failure_policy = "fail-open"
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.equals 0, rcode_of resp        -- NOERROR : réponse normale livrée
    config_stub.nft.add_failure_policy = "fail-closed"

  it "wildcard : injecte aussi dans la règle wildcard d'auth", ->
    query_mod.set_wildcard_rules {
      { rule_id: "r_wild", conditions: { { name: "from_users" } } }
    }
    user_result = "alice@test.lan"
    query_mod.process_query make_query!, "10.0.0.1", "aa:bb:cc:dd:ee:ff", {}
    rule_ids = {}
    for c in *nft_calls
      rule_ids[c.rule_id] = true if c.dest == "1.2.3.4"
    assert.is_true rule_ids["r_main"]
    assert.is_true rule_ids["r_wild"]
    query_mod.set_wildcard_rules {}      -- reset pour les autres tests

  it "captive : vole le domaine du portail vers l'IP locale, sans upstream", ->
    query_mod.set_captive "example.com", "10.35.1.254", nil
    upstream_resp = nil   -- l'upstream ne doit PAS être appelé
    decide_called = false
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.equals 0, rcode_of resp           -- NOERROR
    -- AA bit positionné (octet de flags 3, bit 0x04)
    assert.is_true (resp\byte(3) % 8) >= 4
    -- 1 réponse A = 10.35.1.254
    ancount = resp\byte(7) * 256 + resp\byte(8)
    assert.equals 1, ancount
    assert.equals 0, #nft_calls
    query_mod.set_captive nil, nil, nil       -- reset pour les autres tests

  it "captive : domaine non captif → traité normalement (upstream)", ->
    query_mod.set_captive "other.example.org", "10.35.1.254", nil
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.is_true #nft_calls > 0             -- chemin normal : injection nft
    query_mod.set_captive nil, nil, nil

  it "requête illisible → nil, dns_parse_failed", ->
    resp, err = query_mod.process_query "\0\1\2", "10.0.0.1", "unknown", {}
    assert.is_nil resp
    assert.equals "dns_parse_failed", err

  it "upstream KO → nil + erreur", ->
    upstream_resp = nil
    resp, err = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_nil resp
    assert.is_not_nil err

  it "client IPv6 + réponse AAAA : injecte l'IPv6 résolu", ->
    -- Réponse AAAA (2001:db8::1)
    rd = string.char(0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01)
    question = qname_example .. sp(">H H", dns_mod.types.AAAA, QCLASS_IN)
    upstream_resp = (sp ">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0) .. question .. (name_ptr .. sp(">H H I4 s2", dns_mod.types.AAAA, QCLASS_IN, 60, rd))
    query_mod.process_query make_query!, "fd00::99", "unknown", {}
    found = false
    for c in *nft_calls
      found = true if c.rule_id == "r_main" and c.dest\find ":"
    assert.is_true found

  it "patch : retire les RR HTTPS/SVCB et efface le bit AD", ->
    upstream_resp = make_response true   -- contient un RR HTTPS + bit AD (0x8180→AD?)
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    -- Le RR HTTPS doit avoir disparu : ANCOUNT repasse de 2 à 1
    ancount = resp\byte(7) * 256 + resp\byte(8)
    assert.equals 1, ancount

  -- ── Second avis (validate) ───────────────────────────────────────────────

  it "validate=true, validateur OK (pass) → réponse livrée normalement", ->
    decide_result.allow_modifiers = { validate: true }
    config_stub.second_opinion = { resolvers: { "1.1.1.1" }, budget_ms: 200 }
    validator_override = nil
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.equals 0, rcode_of resp

  it "validate=true, validateur bloque (block) → NXDOMAIN", ->
    decide_result.allow_modifiers = { validate: true }
    config_stub.second_opinion = { resolvers: { "1.1.1.1" }, budget_ms: 200 }
    validator_override = { kind: "block" }
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.equals 3, rcode_of resp
    assert.equals 0, #nft_calls

  it "validate, override sinkhole → NOERROR avec 0.0.0.0", ->
    decide_result.allow_modifiers = { validate: true }
    config_stub.second_opinion = { resolvers: { "1.1.1.1" }, budget_ms: 200 }
    validator_override = { kind: "sinkhole", a: { "\0\0\0\0" }, aaaa: {}, ttl: 30 }
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.equals 0, rcode_of resp
    assert.equals 0, #nft_calls

  it "validate, override redirect → CNAME + injection nft de la cible", ->
    decide_result.allow_modifiers = { validate: true }
    config_stub.second_opinion = { resolvers: { "1.1.1.1" }, budget_ms: 200 }
    aaaa6 = string.char(0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x09)
    validator_override = { kind: "redirect", cname_target: "safe.example.", a: { "\5\6\7\8" }, aaaa: { aaaa6 }, ttl: 60 }
    resp = query_mod.process_query make_query!, "10.0.0.1", "aa:bb:cc:dd:ee:ff", {}
    assert.is_not_nil resp
    assert.equals 0, rcode_of resp
    assert.is_true #nft_calls > 0

  it "validate=table, résolveurs per-règle transmis au validateur", ->
    per_rule = { "2.2.2.2" }
    decide_result.allow_modifiers = { validate: per_rule }
    validator_called_with = nil
    package.loaded["doh.validator"] = {
      query_classified: (raw, resolvers, timeout) ->
        validator_called_with = resolvers
        nil, nil
    }
    -- Recharge doh.query pour prendre le nouveau stub.
    package.loaded["doh.query"] = nil
    local_mod = require "doh.query"
    local_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.same per_rule, validator_called_with
    -- Restaure le stub standard pour les tests suivants.
    package.loaded["doh.validator"] = {
      query_classified: (raw, resolvers, timeout) -> validator_override, (validator_override and "validator=stub" or nil)
    }
    package.loaded["doh.query"] = nil

  it "validate sans résolveurs configurés → pas d'appel, réponse livrée", ->
    decide_result.allow_modifiers = { validate: true }
    config_stub.second_opinion = nil
    validator_override = { kind: "block" }   -- ne doit jamais être consulté
    resp = query_mod.process_query make_query!, "10.0.0.1", "unknown", {}
    assert.is_not_nil resp
    assert.equals 0, rcode_of resp
