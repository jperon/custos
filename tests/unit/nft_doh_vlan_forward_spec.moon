-- tests/unit/nft_doh_vlan_forward_spec.moon
-- Tests du rendu des règles d'apprentissage VLAN DoH dans le hook forward
-- (placeholder {DOH_VLAN_FORWARD_RULES}, substitute de nft_rules).

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

-- Config mutable rechargée à chaque test (substitute fait require "config").
make_cfg = (doh_enabled, doh_vlan_q) ->
  {
    nfqueue: { questions: "0", responses: "1", captive: "2", reject: "3",
               auth: "5", sni: "6", sip: nil, doh_vlan: doh_vlan_q }
    nft:     { ip_timeout: "2m", family: "bridge", table: "dns-filter-bridge",
               extra_rules: {} }
    runtime: { log_level: "INFO" }
    filter:  { rules: {} }
    doh:     { port: 8443, enabled: doh_enabled }
    sni:     { placement: "residual" }
  }

load_substitute = (doh_enabled, doh_vlan_q) ->
  package.loaded["config"] = make_cfg doh_enabled, doh_vlan_q
  package.loaded["nft_rules"] = nil
  { :_test } = require "nft_rules"
  _test.substitute

-- Gabarit minimal reproduisant l'ordre du template (placeholder forward AVANT
-- la règle « UniFi mgmt local » qui accepte tcp/8443).
TEMPLATE = table.concat {
  "{DOH_VLAN_FORWARD_RULES}"
  "    tcp dport {6789, 8080, 8443, 8880, 8843} accept comment \"UniFi mgmt local v4\""
}, "\n"

describe "nft_rules : {DOH_VLAN_FORWARD_RULES}", ->
  it "rend les règles forward taguées v4/v6 quand DoH + doh_vlan", ->
    substitute = load_substitute true, "13"
    out = substitute TEMPLATE
    assert.truthy out\match "DoH VLAN learn %(forward tagged v4%)"
    assert.truthy out\match "DoH VLAN learn %(forward tagged v6%)"
    assert.truthy out\match "vlan id != 0 tcp dport 8443"
    assert.truthy out\match "queue num 13 bypass"
    assert.truthy out\match "@filter_ips4"
    assert.truthy out\match "@filter_ips6"

  it "place la règle d'apprentissage AVANT « UniFi mgmt local »", ->
    substitute = load_substitute true, "13"
    out = substitute TEMPLATE
    learn_pos = out\find "DoH VLAN learn"
    unifi_pos = out\find "UniFi mgmt local"
    assert.truthy learn_pos
    assert.truthy unifi_pos
    assert.is_true learn_pos < unifi_pos

  it "rend un commentaire vide si DoH désactivé", ->
    substitute = load_substitute false, "13"
    out = substitute TEMPLATE
    assert.is_nil out\match "DoH VLAN learn"
    assert.truthy out\match "forward%-learning disabled"

  it "rend un commentaire vide si nfqueue.doh_vlan absent", ->
    substitute = load_substitute true, nil
    out = substitute TEMPLATE
    assert.is_nil out\match "DoH VLAN learn"
    assert.truthy out\match "forward%-learning disabled"
