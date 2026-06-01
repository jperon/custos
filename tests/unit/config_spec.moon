-- tests/unit/config_spec.moon
-- Tests de config.moon : fusion default_rules + règles utilisateur.

ffi = require "ffi"
pcall ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]]

-- nil → path inexistant (force DEFAULTS purs, évite le fallback sur /etc/custos/config.moon sur la VM)
reload = (path) ->
  package.loaded["config"] = nil
  actual = path or "tmp/__no_config_for_test__.moon"
  ffi.C.setenv "CUSTOS_CONFIG_PATH", actual, 1
  require "config"

write_moon = (path, content) ->
  f = assert io.open path, "w"
  f\write content
  f\close!

describe "config.default_rules", ->

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  -- Defaults : 3 règles captives/DoH + 4 règles SafeSearch (Google/YouTube/Bing/DDG)
  -- car captive_portal ET safe_search sont true par défaut.
  it "sans config externe : default_rules = captives/DoH (3) + SafeSearch (4)", ->
    cfg = reload nil
    assert.equals 7, #cfg.filter.default_rules
    assert.equals 7, #cfg.filter.rules

  it "default_rules[1] utilise l'action nxdomain", ->
    cfg = reload nil
    assert.equals "nxdomain", cfg.filter.rules[1].actions[1]

  it "default_rules[2] utilise l'action allow avec from_user", ->
    cfg = reload nil
    r = cfg.filter.rules[2]
    assert.equals "allow", r.actions[1]
    assert.equals "_any", r.conditions.from_user

  it "default_rules[3] utilise l'action dnsonly", ->
    cfg = reload nil
    assert.equals "dnsonly", cfg.filter.rules[3].actions[1]

  it "les règles captives par défaut sont autonomes (to_domains en ligne, pas de liste externe)", ->
    cfg = reload nil
    for idx in *{2, 3}
      r = cfg.filter.rules[idx]
      assert.is_nil r.conditions.to_domainlist, "rule[#{idx}] ne doit pas dépendre d'une liste externe"
      assert.is_table r.conditions.to_domains

  it "support NCSI/MSFT : msftncsi.com et msftconnecttest.com couverts (dnsonly + allow authentifié)", ->
    cfg = reload nil
    for idx in *{2, 3}
      seen = {}
      seen[d] = true for d in *cfg.filter.rules[idx].conditions.to_domains
      assert.is_true seen["msftncsi.com"], "msftncsi.com manquant dans rule[#{idx}] (sonde DNS dns.msftncsi.com)"
      assert.is_true seen["msftconnecttest.com"], "msftconnecttest.com manquant dans rule[#{idx}] (sonde HTTP www.msftconnecttest.com)"

  it "les règles utilisateur sont ajoutées après les default_rules", ->
    path = "tmp/config_spec_userrules.moon"
    write_moon path, [[{ filter: { safe_search: false, rules: {
      { description: "Règle user", actions: {"allow"}, conditions: { to_domain: "example.com" } }
    } } }]]
    cfg = reload path
    os.remove path
    assert.equals 4, #cfg.filter.rules
    assert.equals "nxdomain", cfg.filter.rules[1].actions[1]
    assert.equals "Règle user", cfg.filter.rules[4].description

  it "captive_portal défaut true : les 2 règles captives sont présentes, sans marqueur interne", ->
    cfg = reload nil
    assert.is_true cfg.filter.captive_portal
    assert.equals 7, #cfg.filter.rules   -- 3 captives/DoH + 4 SafeSearch
    for idx in *{2, 3}
      assert.is_nil cfg.filter.rules[idx].captive, "le marqueur interne 'captive' ne doit pas fuiter"

  it "captive_portal: false retire les règles captives (DoH nxdomain conservée)", ->
    path = "tmp/config_spec_nocaptive.moon"
    write_moon path, [[{ filter: { captive_portal: false, safe_search: false } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.filter.captive_portal
    assert.equals 1, #cfg.filter.rules
    assert.equals "nxdomain", cfg.filter.rules[1].actions[1]
    assert.equals "use-application-dns.net", cfg.filter.rules[1].conditions.to_domain

  it "captive_portal: \"0\" (chaîne) est coercé en false", ->
    path = "tmp/config_spec_nocaptive_str.moon"
    write_moon path, [[{ filter: { captive_portal: "0", safe_search: false } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.filter.captive_portal
    assert.equals 1, #cfg.filter.rules

  it "default_rules: {} dans la config utilisateur désactive les defaults", ->
    path = "tmp/config_spec_nodefault.moon"
    write_moon path, [[{ filter: { default_rules: {}, safe_search: false, rules: {
      { description: "Only user", actions: {"allow"}, conditions: { to_domain: "x.com" } }
    } } }]]
    cfg = reload path
    os.remove path
    assert.equals 1, #cfg.filter.rules
    assert.equals "Only user", cfg.filter.rules[1].description

  it "sans config externe, filter.rules contient exactement les default_rules (pas de doublons)", ->
    cfg = reload nil
    for i, r in ipairs cfg.filter.rules
      assert.equals cfg.filter.default_rules[i].description, r.description

describe "config.safe_search", ->

  reload = (path) ->
    package.loaded["config"] = nil
    actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv "CUSTOS_CONFIG_PATH", actual, 1
    require "config"

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  -- Collecte les règles cname (action "cname") et la cible YouTube éventuelle.
  cname_rules = (cfg) ->
    rules, youtube = {}, nil
    for r in *(cfg.filter.rules or {})
      if r.actions and r.actions[1] == "cname"
        rules[#rules + 1] = r
        youtube = r.cname if r.description and r.description\match "YouTube"
    rules, youtube

  it "défaut : 4 règles cname (Google/YouTube/Bing/DDG), YouTube en mode modéré", ->
    cfg = reload nil
    assert.is_true cfg.filter.safe_search
    rules, youtube = cname_rules cfg
    assert.equals 4, #rules
    assert.equals "restrictmoderate.youtube.com", youtube

  it "Google réécrit vers forcesafesearch.google.com et couvre les sous-domaines", ->
    cfg = reload nil
    rules = cname_rules cfg
    google = nil
    google = r for r in *rules when r.description\match "Google"
    assert.is_not_nil google
    assert.equals "forcesafesearch.google.com", google.cname
    seen = {}
    seen[d] = true for d in *google.conditions.to_domains
    assert.is_true seen["google.com"]

  it "youtube_restrict=strict : cible restrict.youtube.com", ->
    path = "tmp/config_spec_yt_strict.moon"
    write_moon path, [[{ filter: { youtube_restrict: "strict" } }]]
    cfg = reload path
    os.remove path
    _, youtube = cname_rules cfg
    assert.equals "restrict.youtube.com", youtube

  it "youtube_restrict=false : YouTube omis (3 règles cname)", ->
    path = "tmp/config_spec_yt_off.moon"
    write_moon path, [[{ filter: { youtube_restrict: "false" } }]]
    cfg = reload path
    os.remove path
    rules, youtube = cname_rules cfg
    assert.equals 3, #rules
    assert.is_nil youtube

  it "safe_search=false : aucune règle cname", ->
    path = "tmp/config_spec_ss_off.moon"
    write_moon path, [[{ filter: { safe_search: false } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.filter.safe_search
    rules = cname_rules cfg
    assert.equals 0, #rules

  it "safe_search=\"0\" (chaîne) est coercé en false", ->
    path = "tmp/config_spec_ss_str.moon"
    write_moon path, [[{ filter: { safe_search: "0" } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.filter.safe_search
    rules = cname_rules cfg
    assert.equals 0, #rules
