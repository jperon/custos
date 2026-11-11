-- tests/unit/filter/captive_probes_spec.moon
-- Sondes de portail captif Firefox : l'ancienne sonde
-- (detectportal.firefox.com) et celle des Firefox ≥ 155
-- (firefox-portal-detection.com) doivent recevoir exactement la même décision.

-- Stubs avant tout require de module de production
package.loaded["ipc"] or= { register_modifier: -> nil }
package.loaded["ip_whitelist"] or= { init: -> nil, cleanup: -> nil }
package.loaded["dns_ede"] or= {
  strip_dns_rr:     (raw, _t) -> raw
  add_ede_modified: (raw, _r) -> raw
  clear_ad_bit:     (raw) -> raw
}
package.loaded["auth.user_sessions"] = { get_session: -> nil }
package.loaded["mac_learner_ipc"] = { get_mac: -> nil }

-- Session courante contrôlée par les tests (nil = client anonyme).
_sessions = { current: nil }
package.loaded["auth.sessions"] = {
  session_for_mac:   (mac, src_ip, path) -> _sessions.current
  enrich_session_ip: -> nil
  bind_session_mac:  -> nil
  user_for_mac:      -> nil
}

ffi = require "ffi"
pcall ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]]

load_defaults = ->
  package.loaded["config"] = nil
  ffi.C.setenv "CUSTOS_CONFIG_PATH", "tmp/__no_config_for_test__.moon", 1
  cfg = require "config"
  ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
  cfg

compile_defaults = ->
  package.loaded["filter.conditions.from_user"] = nil
  package.loaded["filter.rule"] = nil
  rule = require "filter.rule"
  rule.compile_rules load_defaults!.filter

describe "sondes de portail captif Firefox", ->
  FIREFOX_LEGACY = "detectportal.firefox.com"
  FIREFOX_204 = "firefox-portal-detection.com"

  after_each ->
    _sessions.current = nil

  it "les deux noms figurent dans les règles captives par défaut (allow + dnsonly)", ->
    cfg = load_defaults!
    for idx in *{2, 3}
      seen = {}
      seen[d] = true for d in *cfg.filter.rules[idx].conditions.to_domains
      for name in *{FIREFOX_LEGACY, FIREFOX_204}
        assert.is_true seen[name], "#{name} manquant dans rule[#{idx}]"

  it "client anonyme : même décision dnsonly pour les deux noms", ->
    compiled = compile_defaults!
    _sessions.current = nil
    metas = {}
    for name in *{FIREFOX_LEGACY, FIREFOX_204}
      metas[name] = require("filter.rule").decide_meta compiled,
        { domain: name, src_ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01" }
    assert.is_true metas[FIREFOX_LEGACY].verdict
    assert.equals "DNS only", metas[FIREFOX_LEGACY].reason\match "^DNS only"
    assert.equals metas[FIREFOX_LEGACY].verdict, metas[FIREFOX_204].verdict
    assert.equals metas[FIREFOX_LEGACY].rule_id, metas[FIREFOX_204].rule_id
    assert.equals metas[FIREFOX_LEGACY].description, metas[FIREFOX_204].description

  it "client authentifié : même décision allow pour les deux noms", ->
    compiled = compile_defaults!
    _sessions.current = { user: "alice", mac: "aa:bb:cc:dd:ee:01" }
    metas = {}
    for name in *{FIREFOX_LEGACY, FIREFOX_204}
      metas[name] = require("filter.rule").decide_meta compiled,
        { domain: name, src_ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01" }
    assert.is_true metas[FIREFOX_LEGACY].verdict
    assert.equals "Allowed by rule", metas[FIREFOX_LEGACY].reason\match "^Allowed by rule"
    assert.equals metas[FIREFOX_LEGACY].verdict, metas[FIREFOX_204].verdict
    assert.equals metas[FIREFOX_LEGACY].rule_id, metas[FIREFOX_204].rule_id
    assert.equals metas[FIREFOX_LEGACY].description, metas[FIREFOX_204].description
