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
return describe("config.default_rules", function()
  after_each(function()
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
    package.loaded["config"] = nil
  end)
  it("sans config externe : 3 default_rules présentes dans filter.rules", function()
    local cfg = reload(nil)
    assert.equals(3, #cfg.filter.default_rules)
    return assert.equals(3, #cfg.filter.rules)
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
    write_moon(path, [[{ filter: { rules: {
      { description: "Règle user", actions: {"allow"}, conditions: { to_domain: "example.com" } }
    } } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.equals(4, #cfg.filter.rules)
    assert.equals("nxdomain", cfg.filter.rules[1].actions[1])
    return assert.equals("Règle user", cfg.filter.rules[4].description)
  end)
  it("captive_portal défaut true : les 2 règles captives sont présentes, sans marqueur interne", function()
    local cfg = reload(nil)
    assert.is_true(cfg.filter.captive_portal)
    assert.equals(3, #cfg.filter.rules)
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
    write_moon(path, [[{ filter: { captive_portal: false } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.is_false(cfg.filter.captive_portal)
    assert.equals(1, #cfg.filter.rules)
    assert.equals("nxdomain", cfg.filter.rules[1].actions[1])
    return assert.equals("use-application-dns.net", cfg.filter.rules[1].conditions.to_domain)
  end)
  it("captive_portal: \"0\" (chaîne) est coercé en false", function()
    local path = "tmp/config_spec_nocaptive_str.moon"
    write_moon(path, [[{ filter: { captive_portal: "0" } }]])
    local cfg = reload(path)
    os.remove(path)
    assert.is_false(cfg.filter.captive_portal)
    return assert.equals(1, #cfg.filter.rules)
  end)
  it("default_rules: {} dans la config utilisateur désactive les defaults", function()
    local path = "tmp/config_spec_nodefault.moon"
    write_moon(path, [[{ filter: { default_rules: {}, rules: {
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
