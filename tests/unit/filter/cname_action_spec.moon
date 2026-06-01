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

  it "eval autorise (true) pour que la réponse suive le pipeline on_response", ->
    action = (cname_factory cfg) { cname: "forcesafesearch.google.com", description: "SafeSearch Google" }
    v, msg = action.eval { domain: "www.google.com" }
    assert.is_true v
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
