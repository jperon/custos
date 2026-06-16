-- tests/unit/worker_tls_enforce_spec.moon
-- Couverture de l'enforcement SNI aligné sur le filtrage DNS :
--   • sni_action_for : mapping pur decide_meta → action SNI
--   • validate_sni   : second avis synchrone + cache + fail-open
--   • dst_matches_cname : laisser passer si l'IP dst est déjà la cible CNAME
--   • build_validator_query : requête DNS A bien formée

sni = require "worker_tls"

describe "sni_action_for (mapping pur)", ->
  it "fail-open si meta nil ou verdict nil", ->
    assert.are.equal "accept", sni.sni_action_for nil
    assert.are.equal "accept", sni.sni_action_for { verdict: nil }

  it "block sur verdict false", ->
    assert.are.equal "block", sni.sni_action_for { verdict: false }

  it "dnsonly sur verdict dnsonly", ->
    assert.are.equal "dnsonly", sni.sni_action_for { verdict: "dnsonly" }

  it "allow pur sur verdict true sans modifier", ->
    assert.are.equal "allow", sni.sni_action_for { verdict: true }

  it "redirect prioritaire si redirects_destination", ->
    meta = { verdict: true, redirects_destination: true, allow_modifiers: { validate: true } }
    assert.are.equal "redirect", sni.sni_action_for meta

  it "validate si allow_modifiers.validate et pas de redirect", ->
    meta = { verdict: true, allow_modifiers: { validate: true } }
    assert.are.equal "validate", sni.sni_action_for meta

  it "allow si verdict true et dns_strip seul (pas de redirect, pas de validate)", ->
    -- dns_strip n'expose ni redirects_destination ni validate → allow pur.
    meta = { verdict: true, allow_modifiers: {} }
    assert.are.equal "allow", sni.sni_action_for meta

describe "build_validator_query", ->
  it "produit une requête DNS A avec le bon QNAME", ->
    raw = sni.build_validator_query "google.com"
    -- En-tête 12 octets, qdcount=1.
    assert.are.equal 1, raw\byte(5) * 256 + raw\byte(6)
    -- QNAME : 6 google 3 com 0
    assert.are.equal 6, raw\byte(13)
    assert.are.equal "google", raw\sub(14, 19)
    assert.are.equal 3, raw\byte(20)
    assert.are.equal "com", raw\sub(21, 23)
    assert.are.equal 0, raw\byte(24)
    -- QTYPE A (1) + QCLASS IN (1)
    assert.are.equal 1, raw\byte(25) * 256 + raw\byte(26)
    assert.are.equal 1, raw\byte(27) * 256 + raw\byte(28)

describe "validate_sni (second avis + cache)", ->
  before_each ->
    sni.reset_sni_verdicts!

  it "renvoie bloqué quand le validateur bloque", ->
    calls = 0
    sni.set_validator_state {
      validator_mod: { query_verdict: (raw, resolvers, b, db) ->
        calls += 1
        true, "validator=1.1.1.1 rcode=3"
      }
      second_opinion_cfg: { resolvers: { "1.1.1.1" }, verdict_ttl_s: 60 }
    }
    blocked, reason = sni.validate_sni "blocked.example", true
    assert.is_true blocked
    assert.are.equal 1, calls
    assert.is_truthy reason\match "rcode=3"

  it "met le verdict en cache (pas de 2e requête upstream)", ->
    calls = 0
    sni.set_validator_state {
      validator_mod: { query_verdict: (raw, resolvers, b, db) ->
        calls += 1
        false, nil
      }
      second_opinion_cfg: { resolvers: { "1.1.1.1" } }
    }
    sni.validate_sni "ok.example", true
    sni.validate_sni "ok.example", true
    assert.are.equal 1, calls

  it "fail-open si query_verdict lève une exception", ->
    sni.set_validator_state {
      validator_mod: { query_verdict: -> error "boom" }
      second_opinion_cfg: { resolvers: { "1.1.1.1" } }
    }
    blocked = sni.validate_sni "boom.example", true
    assert.is_false blocked

  it "prune_sni_verdicts évince les entrées expirées", ->
    sni.set_validator_state {
      validator_mod: { query_verdict: -> false, nil }
      second_opinion_cfg: { resolvers: { "1.1.1.1" }, verdict_ttl_s: 10 }
    }
    -- Peuple le cache (expires_at = now + 10).
    sni.validate_sni "soon.example", true
    -- Avant expiration : rien évincé.
    assert.are.equal 0, sni.prune_sni_verdicts os.time!
    -- Bien après expiration : l'entrée est retirée.
    removed = sni.prune_sni_verdicts os.time! + 3600
    assert.are.equal 1, removed

  it "fail-open si aucun résolveur configuré", ->
    sni.set_validator_state {
      validator_mod: { query_verdict: -> true, "blocked" }
      second_opinion_cfg: { resolvers: {} }
    }
    blocked = sni.validate_sni "x.example", true
    assert.is_false blocked

  it "utilise les résolveurs per-règle quand fournis (table)", ->
    seen = nil
    sni.set_validator_state {
      validator_mod: { query_verdict: (raw, resolvers) ->
        seen = resolvers
        false, nil
      }
      second_opinion_cfg: { resolvers: { "9.9.9.9" } }
    }
    sni.validate_sni "y.example", { "8.8.8.8" }
    assert.are.same { "8.8.8.8" }, seen

describe "dst_matches_cname", ->
  -- ip2s sur des rdata bruts ; on fabrique des octets IPv4/IPv6.
  v4 = (a, b, c, d) -> string.char a, b, c, d

  it "matche si l'IP dst fait partie des A de la cible", ->
    sni.set_validator_state {
      cname_mod: {
        pick_resolver_ip: -> "1.1.1.1"
        resolve_target_rrs: -> { a: { v4(192, 178, 183, 102) }, aaaa: {} }
      }
    }
    matched, resolved = sni.dst_matches_cname "forcesafesearch.google.com", "192.178.183.102", 4
    assert.is_true matched
    assert.is_true resolved

  it "ne matche pas si l'IP dst diffère", ->
    sni.set_validator_state {
      cname_mod: {
        pick_resolver_ip: -> "1.1.1.1"
        resolve_target_rrs: -> { a: { v4(192, 178, 183, 102) }, aaaa: {} }
      }
    }
    matched, resolved = sni.dst_matches_cname "forcesafesearch.google.com", "8.8.8.8", 4
    assert.is_false matched
    assert.is_true resolved

  it "resolved=false si la cible est injoignable (fail-closed côté redirect)", ->
    sni.set_validator_state {
      cname_mod: {
        pick_resolver_ip: -> "1.1.1.1"
        resolve_target_rrs: -> nil
      }
    }
    matched, resolved = sni.dst_matches_cname "forcesafesearch.google.com", "8.8.8.8", 4
    assert.is_false matched
    assert.is_false resolved
