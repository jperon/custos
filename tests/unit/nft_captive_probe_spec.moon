-- tests/unit/nft_captive_probe_spec.moon
-- Câblage nft des sondes de portail captif (action dnsonly) : les sets
-- captive_probe_mac4/6 et les règles qui redirigent leur SYN/80 doivent être
-- placés AVANT `jump cv_rules_dispatch`. Sinon une règle d'allow dont le set
-- contient la même IP (CDN partagé) laisse passer la sonde vers le vrai
-- serveur : 204 → Firefox NOT_CAPTIVE, pas de bandeau (mesuré 2026-11-12).

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
package.loaded["nft_rules"] = nil

package.loaded["log"] or= do
  nop = ->
  {
    log_debug: nop, log_warn: nop, log_error: nop, log_info: nop
    get_log_level_num: -> 0, set_action_prefix: nop
  }

package.loaded["filter.nft_compiler"]     or= { compile: -> nil, render: -> "", render_sets_only: -> "" }
package.loaded["filter.nft_dynamic_sets"] or= { generate_set_creation_commands: -> {} }
package.loaded["filter.rule"]             or= { compile_rules: -> { rules_metadata: {} } }

make_cfg = ->
  {
    nfqueue: { questions: "0", responses: "1", captive: "20", reject: "3",
               auth: "5", sni: "6", sip: nil, doh_vlan: nil }
    nft:     { ip_timeout: "2m", family: "bridge", table: "dns-filter-bridge",
               extra_rules: {} }
    runtime: { log_level: "INFO" }
    filter:  { rules: {} }
    doh:     { port: 8443, enabled: false }
    sni:     { placement: "residual" }
  }

read_template = ->
  fh = assert io.open "nft-rules/dns-filter-bridge.nft", "r"
  content = fh\read "*a"
  fh\close!
  content

tmpl = read_template!

load_substitute = ->
  package.loaded["config"] = make_cfg!
  package.loaded["nft_rules"] = nil
  { :_test } = require "nft_rules"
  _test.substitute

describe "dns-filter-bridge.nft : sondes de portail captif", ->

  it "déclare les sets tuple (MAC . IP) avec timeout", ->
    assert.truthy tmpl\find "set captive_probe_mac4", 1, true
    assert.truthy tmpl\find "set captive_probe_mac6", 1, true
    assert.truthy tmpl\match "set captive_probe_mac4 %{[^}]-type%s+ether_addr%s*%.%s*ipv4_addr"
    assert.truthy tmpl\match "set captive_probe_mac6 %{[^}]-type%s+ether_addr%s*%.%s*ipv6_addr"

  it "redirige le SYN/80 des sondes avant le dispatch des règles", ->
    out = load_substitute! tmpl
    pos4  = out\find "ether saddr . ip daddr @captive_probe_mac4", 1, true
    pos6  = out\find "ether saddr . ip6 daddr @captive_probe_mac6", 1, true
    jump  = out\find "jump cv_rules_dispatch", 1, true
    assert.truthy pos4
    assert.truthy pos6
    assert.truthy jump
    assert.is_true pos4 < jump
    assert.is_true pos6 < jump
    assert.truthy out\match "captive_probe_mac4 tcp dport 80 tcp flags & %(fin | syn | rst | ack%) == syn counter queue num 20"
    assert.truthy out\match "captive_probe_mac6 tcp dport 80 tcp flags & %(fin | syn | rst | ack%) == syn counter queue num 20"

  it "exclut les clients authentifiés (pas de portail inutile)", ->
    out = load_substitute! tmpl
    assert.truthy out\match "ether saddr != @authenticated_macs ether saddr . ip daddr @captive_probe_mac4"
    assert.truthy out\match "ether saddr != @authenticated_macs ether saddr . ip6 daddr @captive_probe_mac6"

  it "ne laisse aucun placeholder {QUEUE_CAPTIVE} dans le rendu", ->
    out = load_substitute! tmpl
    assert.is_nil out\find "{QUEUE_CAPTIVE}", 1, true
