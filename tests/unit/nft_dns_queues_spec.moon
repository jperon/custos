-- tests/unit/nft_dns_queues_spec.moon
-- Rendu des règles DNS (questions/réponses) dans le ruleset bridge quand les
-- files sont des plages : `queue num 4-5` fait répartir les paquets par flux
-- (hachage noyau), donc un worker réponses par file. Vérifie que la plage
-- configurée est bien recopiée telle quelle (et non ramenée à une file).

ffi_local = require "ffi"
fake_ctx  = ffi_local.new "char[1]"
package.loaded["ffi_defs"] = {
  ffi: ffi_local, libc: ffi_local.C, libnfq: {}
  libnft: {
    nft_ctx_new:              -> fake_ctx
    nft_run_cmd_from_buffer:  -> 0
    nft_ctx_get_error_buffer: -> nil
  }
}
package.loaded["log"] or= do
  nop = ->
  {
    log_debug: nop, log_warn: nop, log_error: nop, log_info: nop
    get_log_level_num: -> 0, set_action_prefix: nop
  }

package.loaded["filter.nft_compiler"]     or= { compile: -> nil, render: -> "", render_sets_only: -> "" }
package.loaded["filter.nft_dynamic_sets"] or= { generate_set_creation_commands: -> {} }
package.loaded["filter.rule"]             or= { compile_rules: -> { rules_metadata: {} } }

-- Config mutable rechargée à chaque test (substitute fait require "config").
make_cfg = (questions, responses) ->
  {
    nfqueue: { :questions, :responses, captive: "20", reject: "10-11",
               auth: "5", sni: "6", sip: nil, doh_vlan: nil }
    nft:     { ip_timeout: "2m", family: "bridge", table: "dns-filter-bridge",
               extra_rules: {} }
    runtime: { log_level: "INFO" }
    filter:  { rules: {} }
    doh:     { port: 8443, enabled: false }
    sni:     { placement: "residual" }
  }

load_substitute = (questions, responses) ->
  package.loaded["config"] = make_cfg questions, responses
  package.loaded["nft_rules"] = nil
  { :_test } = require "nft_rules"
  _test.substitute

-- Extrait dns-filter-bridge.nft : les deux règles DNS de la chaîne forward.
TEMPLATE = table.concat {
  '    meta l4proto {udp, tcp} th dport 53 log level debug prefix "custos question: " counter queue num {QUEUE_QUESTIONS} comment "DNS questions → NFQUEUE"'
  '    meta l4proto {udp, tcp} th sport 53 log level debug prefix "custos response: " counter queue num {QUEUE_RESPONSES} comment "DNS responses → NFQUEUE"'
}, "\n"

describe "nft_rules : files DNS", ->
  it "recopie la plage des réponses (\"4-5\") : distribution par flux", ->
    substitute = load_substitute "0-1", "4-5"
    out = substitute TEMPLATE
    assert.truthy out\match 'queue num 4%-5 comment "DNS responses'
    assert.truthy out\match 'queue num 0%-1 comment "DNS questions'
    assert.is_nil out\match "{QUEUE_RESPONSES}"

  it "recopie une file unique (\"4\") sans plage", ->
    substitute = load_substitute "0-1", "4"
    out = substitute TEMPLATE
    assert.truthy out\match 'queue num 4 comment "DNS responses'
    assert.is_nil out\match "queue num 4%-"

  it "les deux règles DNS restent ordonnées questions puis réponses", ->
    substitute = load_substitute "0-1", "4-5"
    out = substitute TEMPLATE
    q_pos = out\find "DNS questions"
    r_pos = out\find "DNS responses"
    assert.truthy q_pos
    assert.truthy r_pos
    assert.is_true q_pos < r_pos
