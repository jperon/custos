local ffi = require("ffi")
pcall(ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]])
local reload
reload = function(path)
  package.loaded["config"] = nil
  if path then
    ffi.C.setenv("CUSTOS_CONFIG_PATH", path, 1)
  else
    ffi.C.unsetenv("CUSTOS_CONFIG_PATH")
  end
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
