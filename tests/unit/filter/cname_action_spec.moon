-- tests/unit/filter/cname_action_spec.moon
-- Tests de l'action générique cname (réécriture de la réponse en CNAME).

package.loaded["ipc"] or= { register_modifier: -> nil }

describe "filter.actions.cname", ->
  cname_factory = (require "filter.actions.cname").factory
  dns_mod = require "ipparse.l7.dns"
  { :encode_dns_name } = require "lib.dns_name"
  cfg = {}

  make_query = (name = "www.google.com", qtype = 1) ->
    q = dns_mod.new {
      header: dns_mod.new_header id: 0x1234, rd: true
      questions: {{ qname: encode_dns_name(name), qtype: qtype, qclass: 1 }}
    }
    "#{q}"

  decode_cname = (rdata) ->
    labels = {}
    i = 1
    while i <= #rdata
      l = rdata\byte i
      break if l == 0
      labels[#labels + 1] = rdata\sub i + 1, i + l
      i += l + 1
    table.concat labels, "."

  it "eval ne change pas le verdict (nil) et expose un message de contexte", ->
    action = (cname_factory cfg) { cname: "forcesafesearch.google.com", description: "SafeSearch Google" }
    v, msg = action.eval { domain: "www.google.com" }
    assert.is_nil v
    assert.match "forcesafesearch.google.com", msg

  it "worker-only (nft=false)", ->
    action = (cname_factory cfg) { cname: "x.example" }
    assert.is_true action.capabilities.worker
    assert.is_false action.capabilities.nft

  it "on_response réécrit la réponse en un CNAME vers la cible", ->
    action = (cname_factory cfg) { cname: "forcesafesearch.google.com" }
    ctx = { dns_raw: make_query!, modified: false, skip_nft: false, reason: "r" }
    action.on_response ctx
    assert.is_true ctx.modified
    assert.is_true ctx.skip_nft
    assert.equals "response_cname", ctx.action_label
    parsed = dns_mod.parse ctx.dns_raw, 1, false
    assert.equals 1, parsed.header.ancount
    assert.equals dns_mod.types.CNAME, parsed.answers[1].rtype
    assert.equals "forcesafesearch.google.com", decode_cname parsed.answers[1].rdata

  it "fail-open : si build échoue, ctx.dns_raw inchangé et non modifié", ->
    action = (cname_factory cfg) { cname: "forcesafesearch.google.com" }
    -- dns_raw invalide → build_cname_response renvoie nil
    ctx = { dns_raw: "\xFF", modified: false, skip_nft: false, reason: "r" }
    action.on_response ctx
    assert.is_false ctx.modified
    assert.equals "\xFF", ctx.dns_raw

  it "ajoute A/AAAA résolus et laisse l'injection nft active", ->
    old_upstream = package.loaded["doh.upstream"]
    old_cname_mod = package.loaded["filter.actions.cname"]

    package.loaded["doh.upstream"] = {
      new_client: (ip, port, timeout_ms) -> { fd: 1, :ip, :port, :timeout_ms }
      query: (client, raw) ->
        req = dns_mod.parse raw, 1, false
        q = req.questions[1]
        answer = if q.qtype == dns_mod.types.A
          { rname: string.char(0xC0, 0x0C), rtype: dns_mod.types.A, rclass: 1, ttl: 120, rdata: string.char(203, 0, 113, 10) }
        else
          { rname: string.char(0xC0, 0x0C), rtype: dns_mod.types.AAAA, rclass: 1, ttl: 120, rdata: string.char(0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x10) }
        resp = dns_mod.new {
          header: dns_mod.new_header id: req.header.id, qr: true, rd: true, ra: true
          questions: {{ qname: q.qname, qtype: q.qtype, qclass: q.qclass }}
          answers: { answer }
        }
        tostring resp
      close: (client) -> nil
    }

    package.loaded["filter.actions.cname"] = nil
    ok, err = pcall ->
      local_factory = (require "filter.actions.cname").factory
      cfg_resolve = {
        doh: {
          upstream_ipv4: "1.1.1.3"
          upstream_port: 53
          upstream_timeout_ms: 2000
        }
      }
      action = (local_factory cfg_resolve) { cname: "forcesafesearch.google.com" }
      ctx = { dns_raw: make_query!, modified: false, skip_nft: false, reason: "r", resolver_ip: "1.1.1.3" }
      action.on_response ctx

      assert.is_true ctx.modified
      assert.is_false ctx.skip_nft
      assert.equals "response_cname_resolved", ctx.action_label
      parsed = dns_mod.parse ctx.dns_raw, 1, false
      assert.equals 3, parsed.header.ancount
      assert.equals dns_mod.types.CNAME, parsed.answers[1].rtype
      assert.equals dns_mod.types.A, parsed.answers[2].rtype
      assert.equals dns_mod.types.AAAA, parsed.answers[3].rtype

    package.loaded["filter.actions.cname"] = old_cname_mod
    package.loaded["doh.upstream"] = old_upstream
    assert.is_true ok, err

  it "cache négatif : un résolveur qui timeout n'est plus re-sollicité", ->
    old_upstream  = package.loaded["doh.upstream"]
    old_cname_mod = package.loaded["filter.actions.cname"]

    query_count = 0
    package.loaded["doh.upstream"] = {
      new_client: (ip, port, timeout_ms) -> { fd: 1, :ip, :port, :timeout_ms }
      query: (client, raw) ->
        query_count += 1
        nil, "recv() timed out"   -- simule un résolveur injoignable
      close: (client) -> nil
    }

    package.loaded["filter.actions.cname"] = nil
    ok, err = pcall ->
      local_factory = (require "filter.actions.cname").factory
      action = (local_factory {}) { cname: "forcesafesearch.google.com" }
      mkctx = -> { dns_raw: make_query!, modified: false, skip_nft: false, reason: "r", resolver_ip: "9.9.9.9" }

      -- 1er passage : tente A + AAAA (2 requêtes), toutes deux timeout.
      ctx1 = mkctx!
      action.on_response ctx1
      assert.equals 2, query_count
      -- La réécriture CNAME a quand même lieu (fail-open), sans A/AAAA.
      assert.is_true ctx1.modified
      assert.is_true ctx1.skip_nft

      -- 2e passage vers le MÊME résolveur : court-circuité par le cache négatif,
      -- aucune nouvelle requête upstream (le compteur ne bouge pas).
      action.on_response mkctx!
      assert.equals 2, query_count

    package.loaded["filter.actions.cname"] = old_cname_mod
    package.loaded["doh.upstream"] = old_upstream
    assert.is_true ok, err
