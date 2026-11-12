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

  -- Defaults : 4 règles captives/DoH/TRR + 4 règles SafeSearch
  -- (Google/YouTube/Bing/DDG) car captive_portal ET safe_search sont true par
  -- défaut.
  it "sans config externe : default_rules = captives/DoH/TRR (4) + SafeSearch (4)", ->
    cfg = reload nil
    assert.equals 8, #cfg.filter.default_rules
    assert.equals 8, #cfg.filter.rules

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

  it "default_rules[4] est la confirmation TRR (dnsonly, example.com)", ->
    cfg = reload nil
    assert.equals "dnsonly", cfg.filter.rules[4].actions[1]
    assert.same {"example.com"}, cfg.filter.rules[4].conditions.to_domains
    assert.same {"example.com"}, cfg.filter.trr_confirmation

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
    assert.equals 5, #cfg.filter.rules
    assert.equals "nxdomain", cfg.filter.rules[1].actions[1]
    assert.equals "Règle user", cfg.filter.rules[5].description

  it "captive_portal défaut true : les 2 règles captives sont présentes, sans marqueur interne", ->
    cfg = reload nil
    assert.is_true cfg.filter.captive_portal
    assert.equals 8, #cfg.filter.rules   -- 4 captives/DoH/TRR + 4 SafeSearch
    for idx in *{2, 3}
      assert.is_nil cfg.filter.rules[idx].captive, "le marqueur interne 'captive' ne doit pas fuiter"

  it "captive_portal: false retire les règles captives (DoH nxdomain conservée)", ->
    path = "tmp/config_spec_nocaptive.moon"
    write_moon path, [[{ filter: { captive_portal: false, safe_search: false } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.filter.captive_portal
    assert.equals 2, #cfg.filter.rules   -- nxdomain + confirmation TRR
    assert.equals "nxdomain", cfg.filter.rules[1].actions[1]
    assert.equals "use-application-dns.net", cfg.filter.rules[1].conditions.to_domain

  it "captive_portal: \"0\" (chaîne) est coercé en false", ->
    path = "tmp/config_spec_nocaptive_str.moon"
    write_moon path, [[{ filter: { captive_portal: "0", safe_search: false } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.filter.captive_portal
    assert.equals 2, #cfg.filter.rules   -- nxdomain + confirmation TRR

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

describe "config.filter.lists_dir", ->

  it "vaut /etc/custos/lists par défaut (listes manuelles persistantes)", ->
    cfg = reload nil
    assert.equals "/etc/custos/lists", cfg.filter.lists_dir

  it "domainlists_dir reste /tmp/custos/lists (listes compilées téléchargées)", ->
    cfg = reload nil
    assert.equals "/tmp/custos/lists", cfg.filter.domainlists_dir

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

describe "config.auth.bridge_ifname", ->

  reload = (path) ->
    package.loaded["config"] = nil
    actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv "CUSTOS_CONFIG_PATH", actual, 1
    require "config"

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    ffi.C.unsetenv "BRIDGE_IFNAME"
    package.loaded["config"] = nil

  it "bridge_ifname est toujours défini après normalize (autodétection ou défaut)", ->
    cfg = reload nil
    assert.is_string cfg.auth.bridge_ifname
    assert.is_true #cfg.auth.bridge_ifname > 0

  it "bridge_ifname explicite dans config est conservé", ->
    path = "tmp/config_spec_bridge.moon"
    f = assert io.open path, "w"
    f\write [[{ auth: { bridge_ifname: "br-custom" } }]]
    f\close!
    cfg = reload path
    os.remove path
    assert.equals "br-custom", cfg.auth.bridge_ifname

  it "bridge_ifname corrompu (ex. \"Warning:\") est rejeté → autodétection", ->
    path = "tmp/config_spec_bridge_bad.moon"
    f = assert io.open path, "w"
    f\write [[{ auth: { bridge_ifname: "Warning:" } }]]
    f\close!
    cfg = reload path
    os.remove path
    assert.is_string cfg.auth.bridge_ifname
    assert.not_equals "Warning:", cfg.auth.bridge_ifname

  it "BRIDGE_IFNAME env prime sur l'autodétection", ->
    ffi.C.setenv "BRIDGE_IFNAME", "br-env", 1
    cfg = reload nil
    assert.equals "br-env", cfg.auth.bridge_ifname

  it "config explicite prime sur BRIDGE_IFNAME env", ->
    ffi.C.setenv "BRIDGE_IFNAME", "br-env", 1
    path = "tmp/config_spec_bridge_explicit.moon"
    f = assert io.open path, "w"
    f\write [[{ auth: { bridge_ifname: "br-explicit" } }]]
    f\close!
    cfg = reload path
    os.remove path
    assert.equals "br-explicit", cfg.auth.bridge_ifname

describe "config.auth.register_rate_*", ->

  reload = (path) ->
    package.loaded["config"] = nil
    actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv "CUSTOS_CONFIG_PATH", actual, 1
    require "config"

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  write_cfg = (path, content) ->
    f = assert io.open path, "w"
    f\write content
    f\close!

  it "défauts du schéma (3 / 300) après normalize", ->
    cfg = reload nil
    assert.equals 3, cfg.auth.register_rate_limit
    assert.equals 300, cfg.auth.register_rate_window

  it "valeurs explicites conservées (dont limite 0 = désactivée)", ->
    path = "tmp/config_spec_register_rate.moon"
    write_cfg path, [[{ auth: { register_rate_limit: 0, register_rate_window: 60 } }]]
    cfg = reload path
    os.remove path
    assert.equals 0, cfg.auth.register_rate_limit
    assert.equals 60, cfg.auth.register_rate_window

  it "valeurs textuelles converties en nombres", ->
    path = "tmp/config_spec_register_rate_str.moon"
    write_cfg path, [[{ auth: { register_rate_limit: "5", register_rate_window: "120" } }]]
    cfg = reload path
    os.remove path
    assert.equals 5, cfg.auth.register_rate_limit
    assert.equals 120, cfg.auth.register_rate_window

  it "fenêtre absente, nulle ou négative → défaut 300", ->
    for raw in *{ "nil", "0", "-10" }
      path = "tmp/config_spec_register_rate_win.moon"
      write_cfg path, "{ auth: { register_rate_window: #{raw} } }"
      cfg = reload path
      os.remove path
      assert.equals 300, cfg.auth.register_rate_window

describe "config.nfqueue.responses", ->
  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  -- Capture les log_warn (thunks) émis pendant le chargement de la config.
  capture_warns = (fn) ->
    old_log = package.loaded["log"]
    calls = {}
    package.loaded["log"] = {
      log_warn: (thunk) -> calls[#calls + 1] = thunk!
    }
    ok, err = pcall fn
    package.loaded["log"] = old_log
    assert.is_true ok, err
    calls

  it "une plage (\"14-15\") est conservée : un worker par file (fan-out IPC)", ->
    path = "tmp/config_spec_nfq_multi.moon"
    write_moon path, [[return { nfqueue: { responses: "14-15" } }]]
    holder = {}
    calls = capture_warns -> holder.cfg = reload path
    os.remove path
    assert.equals "14-15", holder.cfg.nfqueue.responses
    for c in *calls
      assert.are_not.equal "nfqueue_responses_single_queue_only", c.action
      assert.are_not.equal "nfqueue_responses_range_not_contiguous", c.action

  it "une liste non contiguë (\"4,6\") est ramenée à sa première file (nft)", ->
    path = "tmp/config_spec_nfq_list.moon"
    write_moon path, [[return { nfqueue: { responses: "4,6" } }]]
    holder = {}
    calls = capture_warns -> holder.cfg = reload path
    os.remove path
    assert.equals "4", holder.cfg.nfqueue.responses
    found = false
    for c in *calls
      found = true if c.action == "nfqueue_responses_range_not_contiguous"
    assert.is_true found

  it "une file seule (\"4\") est inchangée", ->
    path = "tmp/config_spec_nfq_single.moon"
    write_moon path, [[return { nfqueue: { responses: "4" } }]]
    cfg = reload path
    os.remove path
    assert.equals "4", cfg.nfqueue.responses

  it "questions: \"0-1\" reste inchangé (contrôle)", ->
    path = "tmp/config_spec_nfq_questions.moon"
    write_moon path, [[return { nfqueue: { questions: "0-1" } }]]
    cfg = reload path
    os.remove path
    assert.equals "0-1", cfg.nfqueue.questions

  -- Défaut issu de la campagne de réglage (docs/agents/perf.md §15.5) :
  -- deux workers réponses (2/2) ; la file 4 reste la dernière de la plage pour
  -- ne pas casser une configuration qui la référence explicitement.
  it "sans config externe : défaut \"3-4\" (deux workers réponses, file 4 conservée)", ->
    cfg = reload nil
    assert.equals "3-4", cfg.nfqueue.responses

  it "le défaut ne partage aucune file avec les autres rôles", ->
    cfg = reload nil
    lm = require "lib.lowmem"
    owner = {}
    for role in *{ "questions", "captive", "reject", "auth", "sni", "sip", "doh_vlan" }
      for q in *lm.parse_queues cfg.nfqueue[role]
        owner[q] = role
    for q in *lm.parse_queues cfg.nfqueue.responses
      assert.is_nil owner[q], "file #{q} du défaut réponses aussi utilisée par #{owner[q]}"
describe "config.nfqueue.maxlen", ->
  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  capture_warns = (fn) ->
    old_log = package.loaded["log"]
    calls = {}
    package.loaded["log"] = {
      log_warn: (thunk) -> calls[#calls + 1] = thunk!
    }
    ok, err = pcall fn
    package.loaded["log"] = old_log
    assert.is_true ok, err
    calls

  it "absent → nil (le profil 4096/1024 est résolu à l'ouverture de la file)", ->
    cfg = reload nil
    assert.is_nil cfg.nfqueue.maxlen

  it "0 (auto) → nil sans avertissement", ->
    path = "tmp/config_spec_nfq_maxlen_zero.moon"
    write_moon path, [[return { nfqueue: { maxlen: 0 } }]]
    holder = {}
    calls = capture_warns -> holder.cfg = reload path
    os.remove path
    assert.is_nil holder.cfg.nfqueue.maxlen
    assert.are.equal 0, #calls

  it "entier positif conservé, y compris sous forme textuelle", ->
    path = "tmp/config_spec_nfq_maxlen_str.moon"
    write_moon path, [[return { nfqueue: { maxlen: "2048" } }]]
    cfg = reload path
    os.remove path
    assert.equals 2048, cfg.nfqueue.maxlen

  it "négatif, non entier ou non numérique → nil + WARN nfqueue_maxlen_invalid", ->
    for raw in *{ "-1", "12.5", '"abc"' }
      path = "tmp/config_spec_nfq_maxlen_bad.moon"
      write_moon path, "{ nfqueue: { maxlen: #{raw} } }"
      holder = {}
      calls = capture_warns -> holder.cfg = reload path
      os.remove path
      assert.is_nil holder.cfg.nfqueue.maxlen, raw
      found = false
      for c in *calls
        found = true if c.action == "nfqueue_maxlen_invalid"
      assert.is_true found, "WARN nfqueue_maxlen_invalid attendu pour #{raw}"

describe "config.nfqueue.max_age_ms", ->
  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  capture_warns = (fn) ->
    old_log = package.loaded["log"]
    calls = {}
    package.loaded["log"] = {
      log_warn: (thunk) -> calls[#calls + 1] = thunk!
    }
    ok, err = pcall fn
    package.loaded["log"] = old_log
    assert.is_true ok, err
    calls

  it "absent → défaut 1500 ms", ->
    cfg = reload nil
    assert.equals 1500, cfg.nfqueue.max_age_ms

  it "0 (désactivé) conservé sans avertissement", ->
    path = "tmp/config_spec_nfq_max_age_zero.moon"
    write_moon path, [[return { nfqueue: { max_age_ms: 0 } }]]
    holder = {}
    calls = capture_warns -> holder.cfg = reload path
    os.remove path
    assert.equals 0, holder.cfg.nfqueue.max_age_ms
    assert.are.equal 0, #calls

  it "entier positif conservé, y compris sous forme textuelle", ->
    path = "tmp/config_spec_nfq_max_age_str.moon"
    write_moon path, [[return { nfqueue: { max_age_ms: "750" } }]]
    cfg = reload path
    os.remove path
    assert.equals 750, cfg.nfqueue.max_age_ms

  it "négatif, non entier ou non numérique → défaut + WARN nfqueue_max_age_invalid", ->
    for raw in *{ "-1", "12.5", '"abc"' }
      path = "tmp/config_spec_nfq_max_age_bad.moon"
      write_moon path, "{ nfqueue: { max_age_ms: #{raw} } }"
      holder = {}
      calls = capture_warns -> holder.cfg = reload path
      os.remove path
      assert.equals 1500, holder.cfg.nfqueue.max_age_ms, raw
      found = false
      for c in *calls
        found = true if c.action == "nfqueue_max_age_invalid"
      assert.is_true found, "WARN nfqueue_max_age_invalid attendu pour #{raw}"

describe "config.nfqueue chevauchement", ->
  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  -- Capture les log_error émis pendant le chargement de la config ; le module
  -- log n'est pas encore chargé quand config est requis en production, donc
  -- config_error retombe sur stderr — ici on installe un stub pour observer
  -- les champs structurés.
  capture_errors = (fn) ->
    old_log = package.loaded["log"]
    calls = {}
    package.loaded["log"] = {
      log_warn: (thunk) -> calls[#calls + 1] = thunk!
      log_error: (thunk) -> calls[#calls + 1] = thunk!
    }
    ok, err = pcall fn
    package.loaded["log"] = old_log
    ok, err, calls

  it "responses \"4-5\" chevauche auth \"5\" : ERROR (rôles + file) et refus de démarrer", ->
    path = "tmp/config_spec_nfq_overlap.moon"
    write_moon path, [[return { nfqueue: { responses: "4-5" } }]]
    ok, err, calls = capture_errors -> reload path
    os.remove path
    assert.is_false ok, "un chevauchement doit empêcher le chargement"
    msg = tostring err
    assert.truthy msg\find "5", 1, true
    assert.truthy msg\find "responses", 1, true
    assert.truthy msg\find "auth", 1, true
    found = false
    for c in *calls
      if c.action == "nfqueue_overlap"
        found = true
        assert.equals 5, c.queue
        assert.equals "responses", c.role
        assert.equals "auth", c.conflict
    assert.is_true found, "un log ERROR nfqueue_overlap est attendu"

  it "une plage libre (\"14-15\") ne chevauche aucun rôle : chargement OK", ->
    path = "tmp/config_spec_nfq_free.moon"
    write_moon path, [[return { nfqueue: { responses: "14-15" } }]]
    holder = {}
    ok, err, calls = capture_errors -> holder.cfg = reload path
    os.remove path
    assert.is_true ok, tostring err
    assert.equals "14-15", holder.cfg.nfqueue.responses

  it "une liste non contiguë est réduite avant la validation (pas de faux conflit avec sni 6)", ->
    path = "tmp/config_spec_nfq_normalized.moon"
    write_moon path, [[return { nfqueue: { responses: "4,6" } }]]
    ok, err, calls = capture_errors -> reload path
    os.remove path
    assert.is_true ok, tostring err
    for c in *calls
      assert.are_not.equal "nfqueue_overlap", c.action

describe "config.auth.cert_dir", ->

  reload = (path) ->
    package.loaded["config"] = nil
    actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv "CUSTOS_CONFIG_PATH", actual, 1
    require "config"

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  it "défaut : /tmp/custos/certs (tmpfs, hors flash)", ->
    cfg = reload nil
    assert.equals "/tmp/custos/certs", cfg.auth.cert_dir

  it "clé auth.cert_dir explicite conservée", ->
    path = "tmp/config_spec_cert_dir.moon"
    write_moon path, [[return { auth: { cert_dir: "/var/run/custos/certs" } }]]
    cfg = reload path
    os.remove path
    assert.equals "/var/run/custos/certs", cfg.auth.cert_dir
