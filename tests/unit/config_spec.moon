-- tests/unit/config_spec.moon
-- Tests de config.moon : fusion default_rules + règles utilisateur.

ffi = require "ffi"
pcall ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]]

reload = (path) ->
  package.loaded["config"] = nil
  if path
    ffi.C.setenv "CUSTOS_CONFIG_PATH", path, 1
  else
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
  require "config"

write_moon = (path, content) ->
  f = assert io.open path, "w"
  f\write content
  f\close!

describe "config.default_rules", ->

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  it "sans config externe : 3 default_rules présentes dans filter.rules", ->
    cfg = reload nil
    assert.equals 3, #cfg.filter.default_rules
    assert.equals 3, #cfg.filter.rules

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

  it "les règles utilisateur sont ajoutées après les default_rules", ->
    path = "tmp/config_spec_userrules.moon"
    write_moon path, [[{ filter: { rules: {
      { description: "Règle user", actions: {"allow"}, conditions: { to_domain: "example.com" } }
    } } }]]
    cfg = reload path
    os.remove path
    assert.equals 4, #cfg.filter.rules
    assert.equals "nxdomain", cfg.filter.rules[1].actions[1]
    assert.equals "Règle user", cfg.filter.rules[4].description

  it "default_rules: {} dans la config utilisateur désactive les defaults", ->
    path = "tmp/config_spec_nodefault.moon"
    write_moon path, [[{ filter: { default_rules: {}, rules: {
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
