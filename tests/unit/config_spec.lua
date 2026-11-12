local ffi = require("ffi")
pcall(ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]])
local reload
reload = function(path)
  package.loaded["config"] = nil
  local actual = path or "tmp/__no_config_for_test__.moon"
  ffi.C.setenv("CUSTOS_CONFIG_PATH", actual, 1)
  return require("config")
end
local write_moon
write_moon = function(path, content)
  local f = assert(io.open(path, "w"))
  f:write(content)
  return f:close()
end
describe("config.default_rules", function()
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  it("sans config externe : default_rules = captives/DoH/TRR (4) + SafeSearch (4)", function()
    local cfg = reload(nil)
    assert.equals(8, #cfg.filter.default_rules)
    return assert.equals(8, #cfg.filter.rules)
  end)
  it("default_rules[1] utilise l'action nxdomain", function()
    local cfg = reload(nil)
    return assert.equals("nxdomain", cfg.filter.rules[1].actions[1])
  end)
  it("default_rules[2] utilise l'action allow avec from_user", function()
    local cfg = reload(nil)
    local r = cfg.filter.rules[2]
    assert.equals("allow", r.actions[1])
    return assert.equals("_any", r.conditions.from_user)
  end)
  it("default_rules[3] utilise l'action dnsonly", function()
    local cfg = reload(nil)
    return assert.equals("dnsonly", cfg.filter.rules[3].actions[1])
  end)
  it("default_rules[4] est la confirmation TRR (dnsonly, example.com)", function()
    local cfg = reload(nil)
    assert.equals("dnsonly", cfg.filter.rules[4].actions[1])
    assert.same({
      "example.com"
    }, cfg.filter.rules[4].conditions.to_domains)
    return assert.same({
      "example.com"
    }, cfg.filter.trr_confirmation)
  end)
  it("les règles captives par défaut sont autonomes (to_domains en ligne, pas de liste externe)", function()
    local cfg = reload(nil)
    local _list_0 = {
      2,
      3
    }
    for _index_0 = 1, #_list_0 do
      local idx = _list_0[_index_0]
      local r = cfg.filter.rules[idx]
      assert.is_nil(r.conditions.to_domainlist, "rule[" .. tostring(idx) .. "] ne doit pas dépendre d'une liste externe")
      assert.is_table(r.conditions.to_domains)
    end
  end)
  it("support NCSI/MSFT : msftncsi.com et msftconnecttest.com couverts (dnsonly + allow authentifié)", function()
    local cfg = reload(nil)
    local _list_0 = {
      2,
      3
    }
    for _index_0 = 1, #_list_0 do
      local idx = _list_0[_index_0]
      local seen = { }
      local _list_1 = cfg.filter.rules[idx].conditions.to_domains
      for _index_1 = 1, #_list_1 do
        local d = _list_1[_index_1]
        seen[d] = true
      end
      assert.is_true(seen["msftncsi.com"], "msftncsi.com manquant dans rule[" .. tostring(idx) .. "] (sonde DNS dns.msftncsi.com)")
      assert.is_true(seen["msftconnecttest.com"], "msftconnecttest.com manquant dans rule[" .. tostring(idx) .. "] (sonde HTTP www.msftconnecttest.com)")
    end
  end)
  it("les règles utilisateur sont ajoutées après les default_rules", function()
    local path = "tmp/config_spec_userrules.moon"
    write_moon(path, [[{ filter: { safe_search: false, rules: {
      { description: "Règle user", actions: {"allow"}, conditions: { to_domain: "example.com" } }
    } } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.equals(5, #cfg.filter.rules)
    assert.equals("nxdomain", cfg.filter.rules[1].actions[1])
    return assert.equals("Règle user", cfg.filter.rules[5].description)
  end)
  it("captive_portal défaut true : les 2 règles captives sont présentes, sans marqueur interne", function()
    local cfg = reload(nil)
    assert.is_true(cfg.filter.captive_portal)
    assert.equals(8, #cfg.filter.rules)
    local _list_0 = {
      2,
      3
    }
    for _index_0 = 1, #_list_0 do
      local idx = _list_0[_index_0]
      assert.is_nil(cfg.filter.rules[idx].captive, "le marqueur interne 'captive' ne doit pas fuiter")
    end
  end)
  it("captive_portal: false retire les règles captives (DoH nxdomain conservée)", function()
    local path = "tmp/config_spec_nocaptive.moon"
    write_moon(path, [[{ filter: { captive_portal: false, safe_search: false } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.is_false(cfg.filter.captive_portal)
    assert.equals(2, #cfg.filter.rules)
    assert.equals("nxdomain", cfg.filter.rules[1].actions[1])
    return assert.equals("use-application-dns.net", cfg.filter.rules[1].conditions.to_domain)
  end)
  it("captive_portal: \"0\" (chaîne) est coercé en false", function()
    local path = "tmp/config_spec_nocaptive_str.moon"
    write_moon(path, [[{ filter: { captive_portal: "0", safe_search: false } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.is_false(cfg.filter.captive_portal)
    return assert.equals(2, #cfg.filter.rules)
  end)
  it("default_rules: {} dans la config utilisateur désactive les defaults", function()
    local path = "tmp/config_spec_nodefault.moon"
    write_moon(path, [[{ filter: { default_rules: {}, safe_search: false, rules: {
      { description: "Only user", actions: {"allow"}, conditions: { to_domain: "x.com" } }
    } } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.equals(1, #cfg.filter.rules)
    return assert.equals("Only user", cfg.filter.rules[1].description)
  end)
  return it("sans config externe, filter.rules contient exactement les default_rules (pas de doublons)", function()
    local cfg = reload(nil)
    for i, r in ipairs(cfg.filter.rules) do
      assert.equals(cfg.filter.default_rules[i].description, r.description)
    end
  end)
end)
describe("config.filter.lists_dir", function()
  it("vaut /etc/custos/lists par défaut (listes manuelles persistantes)", function()
    local cfg = reload(nil)
    return assert.equals("/etc/custos/lists", cfg.filter.lists_dir)
  end)
  return it("domainlists_dir reste /tmp/custos/lists (listes compilées téléchargées)", function()
    local cfg = reload(nil)
    return assert.equals("/tmp/custos/lists", cfg.filter.domainlists_dir)
  end)
end)
describe("config.safe_search", function()
  reload = function(path)
    package.loaded["config"] = nil
    local actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv("CUSTOS_CONFIG_PATH", actual, 1)
    return require("config")
  end
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  local cname_rules
  cname_rules = function(cfg)
    local rules, youtube = { }, nil
    local _list_0 = (cfg.filter.rules or { })
    for _index_0 = 1, #_list_0 do
      local r = _list_0[_index_0]
      if r.actions and r.actions[1] == "cname" then
        rules[#rules + 1] = r
        if r.description and r.description:match("YouTube") then
          youtube = r.cname
        end
      end
    end
    return rules, youtube
  end
  it("défaut : 4 règles cname (Google/YouTube/Bing/DDG), YouTube en mode modéré", function()
    local cfg = reload(nil)
    assert.is_true(cfg.filter.safe_search)
    local rules, youtube = cname_rules(cfg)
    assert.equals(4, #rules)
    return assert.equals("restrictmoderate.youtube.com", youtube)
  end)
  it("Google réécrit vers forcesafesearch.google.com et couvre les sous-domaines", function()
    local cfg = reload(nil)
    local rules = cname_rules(cfg)
    local google = nil
    for _index_0 = 1, #rules do
      local r = rules[_index_0]
      if r.description:match("Google") then
        google = r
      end
    end
    assert.is_not_nil(google)
    assert.equals("forcesafesearch.google.com", google.cname)
    local seen = { }
    local _list_0 = google.conditions.to_domains
    for _index_0 = 1, #_list_0 do
      local d = _list_0[_index_0]
      seen[d] = true
    end
    return assert.is_true(seen["google.com"])
  end)
  it("youtube_restrict=strict : cible restrict.youtube.com", function()
    local path = "tmp/config_spec_yt_strict.moon"
    write_moon(path, [[{ filter: { youtube_restrict: "strict" } }]])
    local cfg = reload(path)
    os.remove(path)
    local _, youtube = cname_rules(cfg)
    return assert.equals("restrict.youtube.com", youtube)
  end)
  it("youtube_restrict=false : YouTube omis (3 règles cname)", function()
    local path = "tmp/config_spec_yt_off.moon"
    write_moon(path, [[{ filter: { youtube_restrict: "false" } }]])
    local cfg = reload(path)
    os.remove(path)
    local rules, youtube = cname_rules(cfg)
    assert.equals(3, #rules)
    return assert.is_nil(youtube)
  end)
  it("safe_search=false : aucune règle cname", function()
    local path = "tmp/config_spec_ss_off.moon"
    write_moon(path, [[{ filter: { safe_search: false } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.is_false(cfg.filter.safe_search)
    local rules = cname_rules(cfg)
    return assert.equals(0, #rules)
  end)
  return it("safe_search=\"0\" (chaîne) est coercé en false", function()
    local path = "tmp/config_spec_ss_str.moon"
    write_moon(path, [[{ filter: { safe_search: "0" } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.is_false(cfg.filter.safe_search)
    local rules = cname_rules(cfg)
    return assert.equals(0, #rules)
  end)
end)
describe("config.auth.bridge_ifname", function()
  reload = function(path)
    package.loaded["config"] = nil
    local actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv("CUSTOS_CONFIG_PATH", actual, 1)
    return require("config")
  end
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    ffi.C.unsetenv("BRIDGE_IFNAME")
    package.loaded["config"] = nil
  end)
  it("bridge_ifname est toujours défini après normalize (autodétection ou défaut)", function()
    local cfg = reload(nil)
    assert.is_string(cfg.auth.bridge_ifname)
    return assert.is_true(#cfg.auth.bridge_ifname > 0)
  end)
  it("bridge_ifname explicite dans config est conservé", function()
    local path = "tmp/config_spec_bridge.moon"
    local f = assert(io.open(path, "w"))
    f:write([[{ auth: { bridge_ifname: "br-custom" } }]])
    f:close()
    local cfg = reload(path)
    os.remove(path)
    return assert.equals("br-custom", cfg.auth.bridge_ifname)
  end)
  it("bridge_ifname corrompu (ex. \"Warning:\") est rejeté → autodétection", function()
    local path = "tmp/config_spec_bridge_bad.moon"
    local f = assert(io.open(path, "w"))
    f:write([[{ auth: { bridge_ifname: "Warning:" } }]])
    f:close()
    local cfg = reload(path)
    os.remove(path)
    assert.is_string(cfg.auth.bridge_ifname)
    return assert.not_equals("Warning:", cfg.auth.bridge_ifname)
  end)
  it("BRIDGE_IFNAME env prime sur l'autodétection", function()
    ffi.C.setenv("BRIDGE_IFNAME", "br-env", 1)
    local cfg = reload(nil)
    return assert.equals("br-env", cfg.auth.bridge_ifname)
  end)
  return it("config explicite prime sur BRIDGE_IFNAME env", function()
    ffi.C.setenv("BRIDGE_IFNAME", "br-env", 1)
    local path = "tmp/config_spec_bridge_explicit.moon"
    local f = assert(io.open(path, "w"))
    f:write([[{ auth: { bridge_ifname: "br-explicit" } }]])
    f:close()
    local cfg = reload(path)
    os.remove(path)
    return assert.equals("br-explicit", cfg.auth.bridge_ifname)
  end)
end)
describe("config.auth.register_rate_*", function()
  reload = function(path)
    package.loaded["config"] = nil
    local actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv("CUSTOS_CONFIG_PATH", actual, 1)
    return require("config")
  end
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  local write_cfg
  write_cfg = function(path, content)
    local f = assert(io.open(path, "w"))
    f:write(content)
    return f:close()
  end
  it("défauts du schéma (3 / 300) après normalize", function()
    local cfg = reload(nil)
    assert.equals(3, cfg.auth.register_rate_limit)
    return assert.equals(300, cfg.auth.register_rate_window)
  end)
  it("valeurs explicites conservées (dont limite 0 = désactivée)", function()
    local path = "tmp/config_spec_register_rate.moon"
    write_cfg(path, [[{ auth: { register_rate_limit: 0, register_rate_window: 60 } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.equals(0, cfg.auth.register_rate_limit)
    return assert.equals(60, cfg.auth.register_rate_window)
  end)
  it("valeurs textuelles converties en nombres", function()
    local path = "tmp/config_spec_register_rate_str.moon"
    write_cfg(path, [[{ auth: { register_rate_limit: "5", register_rate_window: "120" } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.equals(5, cfg.auth.register_rate_limit)
    return assert.equals(120, cfg.auth.register_rate_window)
  end)
  return it("fenêtre absente, nulle ou négative → défaut 300", function()
    local _list_0 = {
      "nil",
      "0",
      "-10"
    }
    for _index_0 = 1, #_list_0 do
      local raw = _list_0[_index_0]
      local path = "tmp/config_spec_register_rate_win.moon"
      write_cfg(path, "{ auth: { register_rate_window: " .. tostring(raw) .. " } }")
      local cfg = reload(path)
      os.remove(path)
      assert.equals(300, cfg.auth.register_rate_window)
    end
  end)
end)
describe("config.nfqueue.responses", function()
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  local capture_warns
  capture_warns = function(fn)
    local old_log = package.loaded["log"]
    local calls = { }
    package.loaded["log"] = {
      log_warn = function(thunk)
        calls[#calls + 1] = thunk()
      end
    }
    local ok, err = pcall(fn)
    package.loaded["log"] = old_log
    assert.is_true(ok, err)
    return calls
  end
  it("une plage (\"14-15\") est conservée : un worker par file (fan-out IPC)", function()
    local path = "tmp/config_spec_nfq_multi.moon"
    write_moon(path, [[return { nfqueue: { responses: "14-15" } }]])
    local holder = { }
    local calls = capture_warns(function()
      holder.cfg = reload(path)
    end)
    os.remove(path)
    assert.equals("14-15", holder.cfg.nfqueue.responses)
    for _index_0 = 1, #calls do
      local c = calls[_index_0]
      assert.are_not.equal("nfqueue_responses_single_queue_only", c.action)
      assert.are_not.equal("nfqueue_responses_range_not_contiguous", c.action)
    end
  end)
  it("une liste non contiguë (\"4,6\") est ramenée à sa première file (nft)", function()
    local path = "tmp/config_spec_nfq_list.moon"
    write_moon(path, [[return { nfqueue: { responses: "4,6" } }]])
    local holder = { }
    local calls = capture_warns(function()
      holder.cfg = reload(path)
    end)
    os.remove(path)
    assert.equals("4", holder.cfg.nfqueue.responses)
    local found = false
    for _index_0 = 1, #calls do
      local c = calls[_index_0]
      if c.action == "nfqueue_responses_range_not_contiguous" then
        found = true
      end
    end
    return assert.is_true(found)
  end)
  it("une file seule (\"4\") est inchangée", function()
    local path = "tmp/config_spec_nfq_single.moon"
    write_moon(path, [[return { nfqueue: { responses: "4" } }]])
    local cfg = reload(path)
    os.remove(path)
    return assert.equals("4", cfg.nfqueue.responses)
  end)
  it("questions: \"0-1\" reste inchangé (contrôle)", function()
    local path = "tmp/config_spec_nfq_questions.moon"
    write_moon(path, [[return { nfqueue: { questions: "0-1" } }]])
    local cfg = reload(path)
    os.remove(path)
    return assert.equals("0-1", cfg.nfqueue.questions)
  end)
  it("sans config externe : défaut \"3-4\" (deux workers réponses, file 4 conservée)", function()
    local cfg = reload(nil)
    return assert.equals("3-4", cfg.nfqueue.responses)
  end)
  return it("le défaut ne partage aucune file avec les autres rôles", function()
    local cfg = reload(nil)
    local lm = require("lib.lowmem")
    local owner = { }
    local _list_0 = {
      "questions",
      "captive",
      "reject",
      "auth",
      "sni",
      "sip",
      "doh_vlan"
    }
    for _index_0 = 1, #_list_0 do
      local role = _list_0[_index_0]
      local _list_1 = lm.parse_queues(cfg.nfqueue[role])
      for _index_1 = 1, #_list_1 do
        local q = _list_1[_index_1]
        owner[q] = role
      end
    end
    local _list_1 = lm.parse_queues(cfg.nfqueue.responses)
    for _index_0 = 1, #_list_1 do
      local q = _list_1[_index_0]
      assert.is_nil(owner[q], "file " .. tostring(q) .. " du défaut réponses aussi utilisée par " .. tostring(owner[q]))
    end
  end)
end)
describe("config.nfqueue.maxlen", function()
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  local capture_warns
  capture_warns = function(fn)
    local old_log = package.loaded["log"]
    local calls = { }
    package.loaded["log"] = {
      log_warn = function(thunk)
        calls[#calls + 1] = thunk()
      end
    }
    local ok, err = pcall(fn)
    package.loaded["log"] = old_log
    assert.is_true(ok, err)
    return calls
  end
  it("absent → nil (le profil 4096/1024 est résolu à l'ouverture de la file)", function()
    local cfg = reload(nil)
    return assert.is_nil(cfg.nfqueue.maxlen)
  end)
  it("0 (auto) → nil sans avertissement", function()
    local path = "tmp/config_spec_nfq_maxlen_zero.moon"
    write_moon(path, [[return { nfqueue: { maxlen: 0 } }]])
    local holder = { }
    local calls = capture_warns(function()
      holder.cfg = reload(path)
    end)
    os.remove(path)
    assert.is_nil(holder.cfg.nfqueue.maxlen)
    return assert.are.equal(0, #calls)
  end)
  it("entier positif conservé, y compris sous forme textuelle", function()
    local path = "tmp/config_spec_nfq_maxlen_str.moon"
    write_moon(path, [[return { nfqueue: { maxlen: "2048" } }]])
    local cfg = reload(path)
    os.remove(path)
    return assert.equals(2048, cfg.nfqueue.maxlen)
  end)
  return it("négatif, non entier ou non numérique → nil + WARN nfqueue_maxlen_invalid", function()
    local _list_0 = {
      "-1",
      "12.5",
      '"abc"'
    }
    for _index_0 = 1, #_list_0 do
      local raw = _list_0[_index_0]
      local path = "tmp/config_spec_nfq_maxlen_bad.moon"
      write_moon(path, "{ nfqueue: { maxlen: " .. tostring(raw) .. " } }")
      local holder = { }
      local calls = capture_warns(function()
        holder.cfg = reload(path)
      end)
      os.remove(path)
      assert.is_nil(holder.cfg.nfqueue.maxlen, raw)
      local found = false
      for _index_1 = 1, #calls do
        local c = calls[_index_1]
        if c.action == "nfqueue_maxlen_invalid" then
          found = true
        end
      end
      assert.is_true(found, "WARN nfqueue_maxlen_invalid attendu pour " .. tostring(raw))
    end
  end)
end)
describe("config.nfqueue chevauchement", function()
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  local capture_errors
  capture_errors = function(fn)
    local old_log = package.loaded["log"]
    local calls = { }
    package.loaded["log"] = {
      log_warn = function(thunk)
        calls[#calls + 1] = thunk()
      end,
      log_error = function(thunk)
        calls[#calls + 1] = thunk()
      end
    }
    local ok, err = pcall(fn)
    package.loaded["log"] = old_log
    return ok, err, calls
  end
  it("responses \"4-5\" chevauche auth \"5\" : ERROR (rôles + file) et refus de démarrer", function()
    local path = "tmp/config_spec_nfq_overlap.moon"
    write_moon(path, [[return { nfqueue: { responses: "4-5" } }]])
    local ok, err, calls = capture_errors(function()
      return reload(path)
    end)
    os.remove(path)
    assert.is_false(ok, "un chevauchement doit empêcher le chargement")
    local msg = tostring(err)
    assert.truthy(msg:find("5", 1, true))
    assert.truthy(msg:find("responses", 1, true))
    assert.truthy(msg:find("auth", 1, true))
    local found = false
    for _index_0 = 1, #calls do
      local c = calls[_index_0]
      if c.action == "nfqueue_overlap" then
        found = true
        assert.equals(5, c.queue)
        assert.equals("responses", c.role)
        assert.equals("auth", c.conflict)
      end
    end
    return assert.is_true(found, "un log ERROR nfqueue_overlap est attendu")
  end)
  it("une plage libre (\"14-15\") ne chevauche aucun rôle : chargement OK", function()
    local path = "tmp/config_spec_nfq_free.moon"
    write_moon(path, [[return { nfqueue: { responses: "14-15" } }]])
    local holder = { }
    local ok, err, calls = capture_errors(function()
      holder.cfg = reload(path)
    end)
    os.remove(path)
    assert.is_true(ok, tostring(err))
    return assert.equals("14-15", holder.cfg.nfqueue.responses)
  end)
  return it("une liste non contiguë est réduite avant la validation (pas de faux conflit avec sni 6)", function()
    local path = "tmp/config_spec_nfq_normalized.moon"
    write_moon(path, [[return { nfqueue: { responses: "4,6" } }]])
    local ok, err, calls = capture_errors(function()
      return reload(path)
    end)
    os.remove(path)
    assert.is_true(ok, tostring(err))
    for _index_0 = 1, #calls do
      local c = calls[_index_0]
      assert.are_not.equal("nfqueue_overlap", c.action)
    end
  end)
end)
return describe("config.auth.cert_dir", function()
  reload = function(path)
    package.loaded["config"] = nil
    local actual = path or "tmp/__no_config_for_test__.moon"
    ffi.C.setenv("CUSTOS_CONFIG_PATH", actual, 1)
    return require("config")
  end
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  it("défaut : /tmp/custos/certs (tmpfs, hors flash)", function()
    local cfg = reload(nil)
    return assert.equals("/tmp/custos/certs", cfg.auth.cert_dir)
  end)
  return it("clé auth.cert_dir explicite conservée", function()
    local path = "tmp/config_spec_cert_dir.moon"
    write_moon(path, [[return { auth: { cert_dir: "/var/run/custos/certs" } }]])
    local cfg = reload(path)
    os.remove(path)
    return assert.equals("/var/run/custos/certs", cfg.auth.cert_dir)
  end)
end)
