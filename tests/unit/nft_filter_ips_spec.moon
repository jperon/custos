-- tests/unit/nft_filter_ips_spec.moon
-- Tests pour la pré-population atomique de filter_ips4/6 dans nft_rules.
--
-- Régression visée : avant le fix, flush ruleset vidait les sets filter_ips4/6.
-- nft_extra_rules les repeuplait ensuite en décalé, laissant une fenêtre pendant
-- laquelle les SYN-ACK du serveur auth (sport 33443) étaient rejetés par la queue
-- reject → RST immédiat → portail captif inaccessible au démarrage.

-- Stubs requis avant require "nft_rules" ─────────────────────────────────

-- Override le stub libnft de busted_setup.lua : nft_ctx_new doit retourner
-- un pointeur non-nil, sinon nft_rules.moon lève une erreur au chargement.
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
package.loaded["nft_rules"] = nil   -- force rechargement avec le bon stub

package.loaded["log"] or= do
  nop = ->
  {
    log_debug: nop, log_warn: nop, log_error: nop, log_info: nop
    get_log_level_num: -> 0
    set_action_prefix: nop
  }

package.loaded["config"] or= do
  {
    nfqueue: { questions: "0", responses: "1", captive: "2", reject: "3",
               auth: "5", sni: "6", sip: nil }
    nft:     { ip_timeout: "2m", family: "bridge", table: "dns-filter-bridge",
               extra_rules: {} }
    runtime: { log_level: "INFO" }
    filter:  { rules: {} }
    doh:     { port: 8443 }
    auth:    { sni_verdict: { placement: "residual" } }
  }

-- Stubs des modules Lua exigeant libnft ──────────────────────────────────
package.loaded["filter.nft_compiler"]   or= { compile: -> nil, render: -> "", render_sets_only: -> "" }
package.loaded["filter.nft_dynamic_sets"] or= { generate_set_creation_commands: -> {} }
package.loaded["filter.rule"]           or= { compile_rules: -> { rules_metadata: {} } }

{ :_test } = require "nft_rules"
{ :collect_ips, :fmt_elements, :substitute } = _test

-- ── fmt_elements ─────────────────────────────────────────────────────────

describe "nft_rules._test.fmt_elements", ->

  it "retourne une chaîne vide pour une table vide", ->
    assert.equals "", fmt_elements {}

  it "formate un seul élément", ->
    result = fmt_elements { "192.168.1.1" }
    assert.equals "    elements = { 192.168.1.1 }\n", result

  it "formate plusieurs éléments séparés par des virgules", ->
    result = fmt_elements { "10.0.0.1", "10.0.0.2", "172.16.0.1" }
    assert.equals "    elements = { 10.0.0.1, 10.0.0.2, 172.16.0.1 }\n", result

  it "formate une adresse IPv6", ->
    result = fmt_elements { "2a11:6c7:1700:7801:b488:29ff:feba:eda8" }
    assert.equals "    elements = { 2a11:6c7:1700:7801:b488:29ff:feba:eda8 }\n", result

  it "produit une syntaxe nft valide (pas de virgule finale)", ->
    result = fmt_elements { "1.2.3.4", "5.6.7.8" }
    assert.is_nil result\match ",%s*}"

-- ── collect_ips ──────────────────────────────────────────────────────────

describe "nft_rules._test.collect_ips", ->

  -- Helper : mock io.popen pour retourner une sortie simulée de `ip addr show`.
  with_popen = (fake_output, fn) ->
    orig = io.popen
    io.popen = (cmd) ->
      lines = {}
      for line in (fake_output .. "\n")\gmatch "([^\n]*)\n"
        lines[#lines + 1] = line
      idx = 0
      {
        lines: ->
          ->
            idx += 1
            lines[idx]
        close: ->
      }
    ok, err = pcall fn
    io.popen = orig
    error err unless ok

  ip_addr_v4_output = [[
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: br: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 58:d6:1f:57:4f:94 brd ff:ff:ff:ff:ff:ff
    inet 10.35.1.254/24 brd 10.35.1.255 scope global br
       valid_lft forever preferred_lft forever
    inet 10.35.99.1/24 brd 10.35.99.255 scope global br.99
       valid_lft forever preferred_lft forever]]

  ip_addr_v6_output = [[
4: br: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 58:d6:1f:57:4f:94 brd ff:ff:ff:ff:ff:ff
    inet6 2a11:6c7:1700:7801:b488:29ff:feba:eda8/64 scope global dynamic mngtmpaddr
       valid_lft 86360sec preferred_lft 86360sec
    inet6 fe80::5ad6:1fff:fe57:4f94/64 scope link
       valid_lft forever preferred_lft forever]]

  it "extrait les adresses IPv4 depuis la sortie de ip -4 addr show", ->
    with_popen ip_addr_v4_output, ->
      ips = collect_ips "ip -4 addr show", "%s+inet%s+([%d%.]+)/", nil
      assert.equals 3, #ips        -- loopback + br + br.99
      assert.equals "127.0.0.1",   ips[1]
      assert.equals "10.35.1.254", ips[2]
      assert.equals "10.35.99.1",  ips[3]

  it "extrait les adresses IPv6 non-link-local depuis ip -6 addr show", ->
    with_popen ip_addr_v6_output, ->
      ips = collect_ips "ip -6 addr show", "%s+inet6%s+([%x:]+)/", "^fe80"
      assert.equals 1, #ips
      assert.equals "2a11:6c7:1700:7801:b488:29ff:feba:eda8", ips[1]

  it "exclut les adresses fe80:: (link-local)", ->
    with_popen ip_addr_v6_output, ->
      ips = collect_ips "ip -6 addr show", "%s+inet6%s+([%x:]+)/", "^fe80"
      for _, ip in ipairs ips
        assert.is_nil ip\match "^fe80"

  it "retourne une table vide si io.popen retourne nil", ->
    orig = io.popen
    io.popen = -> nil
    ips = collect_ips "ip -4 addr show", "%s+inet%s+([%d%.]+)/", nil
    io.popen = orig
    assert.equals 0, #ips

  it "retourne une table vide si la sortie ne contient aucune adresse", ->
    with_popen "nothing relevant here\nno addresses", ->
      ips = collect_ips "ip -4 addr show", "%s+inet%s+([%d%.]+)/", nil
      assert.equals 0, #ips

-- ── Intégration : substitution dans le template ──────────────────────────

describe "nft_rules : substitution de {FILTER_IPS4/6_ELEMENTS}", ->

  it "le résultat de fmt_elements s'insère syntaxiquement dans un bloc set nft", ->
    elements = fmt_elements { "10.0.0.1", "192.168.1.1" }
    set_block = "  set filter_ips4 {\n    type ipv4_addr\n" .. elements .. "  }"
    -- doit contenir `elements = {` exactement une fois
    count = 0
    for _ in set_block\gmatch "elements = {" do count += 1
    assert.equals 1, count
    -- et les deux IPs
    assert.truthy set_block\find "10.0.0.1"
    assert.truthy set_block\find "192.168.1.1"

  it "un set vide (pas d'IPs) ne contient pas de clause elements", ->
    elements = fmt_elements {}
    set_block = "  set filter_ips4 {\n    type ipv4_addr\n" .. elements .. "  }"
    assert.is_nil set_block\find "elements"

-- ── Placement SNI (auth.sni_verdict.placement) ───────────────────────────

describe "nft_rules : placement SNI integral/residual", ->
  -- config peut provenir d'un stub antérieur (chargé via `or=`) ne couvrant pas
  -- auth/doh : on garantit la structure minimale exigée par substitute.
  cfg = require "config"
  cfg.nfqueue = cfg.nfqueue or { questions: "0", responses: "1", captive: "2",
                                reject: "3", auth: "5", sni: "6", sip: nil }
  cfg.nfqueue.sni = "6"
  cfg.nft = cfg.nft or { ip_timeout: "2m", family: "bridge",
                         table: "dns-filter-bridge", extra_rules: {} }
  cfg.runtime = cfg.runtime or { log_level: "INFO" }
  cfg.filter = cfg.filter or { rules: {} }
  cfg.doh = cfg.doh or { port: 8443 }
  cfg.auth = cfg.auth or {}
  cfg.auth.sni_verdict = cfg.auth.sni_verdict or {}
  tmpl = "[PRE:{SNI_RULES_PRE}][POST:{SNI_RULES_POST}]"

  -- Extrait les deux zones [PRE:…] et [POST:…] (le contenu SNI ne contient pas de ']').
  split = (out) -> out\match "%[PRE:(.-)%]%[POST:(.-)%]"

  it "residual : règles SNI rendues APRÈS (POST), PRE vide", ->
    cfg.auth.sni_verdict.placement = "residual"
    pre, post = split substitute tmpl
    assert.is_nil pre\find "queue num 6"
    assert.truthy post\find "th dport 443"
    assert.truthy post\find "queue num 6"
    assert.truthy post\find "sni_quic"

  it "integral : règles SNI rendues AVANT (PRE), POST vide", ->
    cfg.auth.sni_verdict.placement = "integral"
    pre, post = split substitute tmpl
    assert.truthy pre\find "th dport 443"
    assert.truthy pre\find "queue num 6"
    assert.is_nil post\find "queue num 6"

  it "défaut (placement absent) : comportement residual", ->
    cfg.auth.sni_verdict.placement = nil
    pre, post = split substitute tmpl
    assert.is_nil pre\find "queue num 6"
    assert.truthy post\find "queue num 6"
    cfg.auth.sni_verdict.placement = "residual"
