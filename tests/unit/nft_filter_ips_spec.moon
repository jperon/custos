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
    sni:     { placement: "residual" }
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

-- ── Placement SNI (sni.placement) ───────────────────────────────────────

describe "nft_rules : placement SNI integral/residual", ->
  -- config peut provenir d'un stub antérieur (chargé via `or=`) ne couvrant pas
  -- sni/doh : on garantit la structure minimale exigée par substitute.
  cfg = require "config"
  cfg.nfqueue = cfg.nfqueue or { questions: "0", responses: "1", captive: "2",
                                reject: "3", auth: "5", sni: "6", sip: nil }
  cfg.nfqueue.sni = "6"
  cfg.nft = cfg.nft or { ip_timeout: "2m", family: "bridge",
                         table: "dns-filter-bridge", extra_rules: {} }
  cfg.runtime = cfg.runtime or { log_level: "INFO" }
  cfg.filter = cfg.filter or { rules: {} }
  cfg.doh = cfg.doh or { port: 8443 }
  cfg.sni = cfg.sni or {}
  tmpl = "[PRE:{SNI_RULES_PRE}][POST:{SNI_RULES_POST}]"

  -- Extrait les deux zones [PRE:…] et [POST:…] (le contenu SNI ne contient pas de ']').
  split = (out) -> out\match "%[PRE:(.-)%]%[POST:(.-)%]"

  it "residual : règles SNI rendues APRÈS (POST), PRE vide", ->
    cfg.sni.placement = "residual"
    pre, post = split substitute tmpl
    assert.is_nil pre\find "queue num 6"
    assert.truthy post\find "th dport 443"
    assert.truthy post\find "queue num 6"
    assert.truthy post\find "sni_quic"

  it "integral : règles SNI rendues AVANT (PRE), POST vide", ->
    cfg.sni.placement = "integral"
    pre, post = split substitute tmpl
    assert.truthy pre\find "th dport 443"
    assert.truthy pre\find "queue num 6"
    assert.is_nil post\find "queue num 6"

  it "défaut (placement absent) : comportement residual", ->
    cfg.sni.placement = nil
    pre, post = split substitute tmpl
    assert.is_nil pre\find "queue num 6"
    assert.truthy post\find "queue num 6"
    cfg.sni.placement = "residual"

-- ── Fast-path conntrack (cache de verdict en ct mark) ────────────────────
-- Régression : sous fort débit, chaque paquet d'un download établi retraversait
-- toute la chaîne forward (sets + cv_rules_dispatch) en softirq. La fast-path
-- rejoue le verdict mémorisé en ct mark. Le filtrage reste prioritaire :
-- l'ordre des règles garantit qu'aucun flux n'est court-circuité avant son
-- inspection (SNI integral, DNS, apprentissage MAC).
describe "dns-filter-bridge.nft : fast-path conntrack", ->
  read_template = ->
    fh = assert io.open "nft-rules/dns-filter-bridge.nft", "r"
    content = fh\read "*a"
    fh\close!
    content

  tmpl = read_template!

  -- cfg minimal exigé par substitute (partagé avec les blocs SNI ci-dessus).
  cfg = require "config"
  cfg.nfqueue = cfg.nfqueue or { questions: "0", responses: "1", captive: "2",
                                reject: "3", auth: "5", sni: "6", sip: nil }
  cfg.nfqueue.sni = "6"
  cfg.nft = cfg.nft or { ip_timeout: "2m", family: "bridge",
                         table: "dns-filter-bridge", extra_rules: {} }
  cfg.runtime = cfg.runtime or { log_level: "INFO" }
  cfg.filter = cfg.filter or { rules: {} }
  cfg.doh = cfg.doh or { port: 8443 }
  cfg.sni = cfg.sni or {}

  FAST = "ct state established,related ct mark != 0x0 meta mark set ct mark counter meta mark vmap @cv_action_vmap"

  -- Le template ne contient PLUS la règle inline : elle est injectée par
  -- nft_rules.moon à l'ancre HAUTE ({FAST_PATH_EARLY}) ou BASE
  -- ({FAST_PATH_LATE}) selon sni.placement.
  it "ne porte plus la règle inline (déplacée vers nft_rules.moon)", ->
    assert.is_nil tmpl\find FAST, 1, true
    assert.truthy tmpl\find "{FAST_PATH_EARLY}", 1, true
    assert.truthy tmpl\find "{FAST_PATH_LATE}", 1, true

  it "déclare la règle de mémorisation du verdict en ct mark", ->
    assert.truthy tmpl\find "meta mark != 0x0 ct mark set meta mark"

  -- Rendu residual : ancre HAUTE remplie, ancre BASE vide.
  describe "rendu residual (ancre HAUTE)", ->
    out = nil
    before_each ->
      cfg.sni.placement = "residual"
      out = substitute tmpl
    it "n'a aucun placeholder {FAST_PATH_*} résiduel", ->
      assert.is_nil out\find "{FAST_PATH_", 1, true
    it "rend la fast-path AVANT le bloc infra (court-circuit du bloc amont)", ->
      fp    = out\find FAST, 1, true
      infra = out\find "DHCPv4", 1, true
      assert.truthy fp
      assert.is_true fp < infra
    it "rend la fast-path AVANT le dispatch", ->
      assert.is_true (out\find FAST, 1, true) < (out\find "jump cv_rules_dispatch", 1, true)

  -- Rendu integral : ancre BASE remplie (après SNI 443), ancre HAUTE vide.
  describe "rendu integral (ancre BASE, SNI préservé)", ->
    out = nil
    before_each ->
      cfg.sni.placement = "integral"
      out = substitute tmpl
    it "n'a aucun placeholder {FAST_PATH_*} résiduel", ->
      assert.is_nil out\find "{FAST_PATH_", 1, true
    it "rend la fast-path APRÈS les règles SNI 443 (inspection préservée)", ->
      fp  = out\find FAST, 1, true
      sni = out\find "th dport {443", 1, true
      assert.truthy fp
      assert.truthy sni
      assert.is_true fp > sni
    it "n'apparaît qu'une seule fois (pas d'ancre HAUTE dupliquée)", ->
      first = out\find FAST, 1, true
      assert.is_nil out\find FAST, first + 1, true
    it "reste AVANT le dispatch", ->
      assert.is_true (out\find FAST, 1, true) < (out\find "jump cv_rules_dispatch", 1, true)
    after_each ->
      cfg.sni.placement = "residual"

  -- Régression : substitute() remplace les placeholders {XXX} GLOBALEMENT
  -- (gsub). Un placeholder dont l'expansion est MULTI-LIGNE / contient des
  -- règles, écrit dans un commentaire `#`, y serait expansé : le bloc de règles
  -- s'injecte au milieu de la ligne commentée et casse la syntaxe nft
  -- (« unexpected colon »). Les placeholders à valeur scalaire (QUEUE_*,
  -- NFT_IP_TIMEOUT, DOH_PORT) restent sans danger inline (en-tête de doc).
  dangerous = { "{SNI_RULES_PRE}", "{SNI_RULES_POST}", "{SIP_RULES}",
    "{COMPILED_FILTER_SETS}", "{COMPILED_FILTER_RULES}",
    "{FILTER_IPS4_ELEMENTS}", "{FILTER_IPS6_ELEMENTS}" }
  it "ne contient aucun placeholder multi-ligne dans une ligne de commentaire", ->
    for line in (tmpl .. "\n")\gmatch "([^\n]*)\n"
      stripped = line\match "^%s*(.-)%s*$"
      if stripped\sub(1, 1) == "#"
        for _, ph in ipairs dangerous
          assert.is_nil stripped\find(ph, 1, true),
            "commentaire avec placeholder multi-ligne #{ph} : #{stripped}"
