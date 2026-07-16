-- tests/unit/filter/init_spec.moon
-- Busted spec pour filter.init (façade publique : load, decide, decide_meta,
-- get_auth_cfg, get_sni_cfg, get_rule_on_response, run_on_response, get_rules).
--
-- Gap de couverture identifié lors de l'audit du 2026-07-16 : aucun spec
-- n'appelait ce module directement (tous passaient par filter.rule, la couche
-- sous-jacente) — en réalité parce que filter.init require transitivement
-- ip_whitelist, dont le module-level `libnft.nft_ctx_new 0` plante immédiatement
-- sous le stub FFI de busted_setup.lua (`libnft = {}`, ffi_defs.moon). D'où le
-- stub package.loaded["ip_whitelist"] ci-dessous, dans le même esprit que les
-- stubs ipc/dns_ede/auth.sessions déjà en place dans rule_spec.moon.

-- Stubs avant tout require de module de production
package.loaded["ip_whitelist"] or= { init: -> nil, cleanup: -> nil }
package.loaded["ipc"] or= { register_modifier: -> nil }
package.loaded["dns_ede"] or= {
  strip_dns_rr:     (raw, _t) -> raw
  add_ede_modified: (raw, _r) -> raw
  clear_ad_bit:     (raw) -> raw
}
package.loaded["auth.sessions"] or= {
  session_for_mac:  -> nil
  enrich_session_ip: -> nil
  bind_session_mac:  -> nil
  user_for_mac:     -> nil
}
package.loaded["auth.user_sessions"] or= { get_session: -> nil }
package.loaded["mac_learner_ipc"] or= { get_mac: -> nil }

config = require "config"

-- Instance fraîche de filter.init : le module maintient un état persistant
-- (rules/auth_cfg_cache/sni_cfg_cache/decision_cfg) entre appels à load() ;
-- recharger le module remet cet état à zéro, pour des tests indépendants de
-- l'ordre d'exécution (même pattern que fresh_ipc dans ipc_spec.moon).
fresh_filter = ->
  package.loaded["filter.init"] = nil
  require "filter.init"

base_filter_cfg = (overrides={}) ->
  cfg = {
    nets: {}
    macs: {}
    times: {}
    users: {}
    rules: {
      { rule_id: "block", actions: { "deny" }, conditions: { to_domain: "blocked.example" } }
      { rule_id: "allow", actions: { "allow" } }
    }
  }
  for k, v in pairs overrides
    cfg[k] = v
  cfg

describe "filter.init", ->

  describe "avant load()", ->
    it "decide retourne false + 'filter not loaded'", ->
      f = fresh_filter!
      verdict, reason = f.decide { domain: "example.com" }
      assert.is_false verdict
      assert.equals "filter not loaded", reason

    it "decide_meta retourne une table verdict=false", ->
      f = fresh_filter!
      meta = f.decide_meta { domain: "example.com" }
      assert.is_false meta.verdict
      assert.equals "filter not loaded", meta.reason
      assert.is_nil meta.rule_id

    it "get_auth_cfg renvoie {} par défaut", ->
      f = fresh_filter!
      assert.same {}, f.get_auth_cfg!

    it "get_sni_cfg renvoie {} par défaut", ->
      f = fresh_filter!
      assert.same {}, f.get_sni_cfg!

    it "get_rules renvoie nil", ->
      f = fresh_filter!
      assert.is_nil f.get_rules!

  describe "load() + decide()", ->
    it "applique les règles chargées depuis config.filter", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      f.load!
      verdict, reason = f.decide { domain: "blocked.example" }
      assert.is_false verdict
      assert.is_not_nil reason

    it "verdict true pour un domaine non bloqué (règle allow par défaut)", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      f.load!
      verdict = f.decide { domain: "example.com" }
      assert.is_true verdict

  describe "load() + decide_meta()", ->
    it "expose rule_id/reason/verdict structurés", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      f.load!
      meta = f.decide_meta { domain: "blocked.example" }
      assert.is_false meta.verdict
      assert.equals "r_block", meta.rule_id

  describe "get_auth_cfg / get_sni_cfg après load()", ->
    it "expose config.auth", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      config.auth = { redirect_url: "https://portal.example/", captive_ip4: "10.0.0.1" }
      f.load!
      auth_cfg = f.get_auth_cfg!
      assert.equals "https://portal.example/", auth_cfg.redirect_url
      config.auth = nil

    it "expose config.filter.sni si présent", ->
      f = fresh_filter!
      config.filter = base_filter_cfg { sni: { verdict_ttl_s: 42 } }
      f.load!
      assert.equals 42, f.get_sni_cfg!.verdict_ttl_s

  describe "get_rules après load()", ->
    it "renvoie le jeu de règles compilé (non nil, non vide)", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      f.load!
      rules = f.get_rules!
      assert.is_not_nil rules
      assert.is_true #rules > 0

  describe "fallback allowed_domains (aucune règle configurée)", ->
    it "génère allow(allowed_domains) + deny(default) et decide fonctionne", ->
      f = fresh_filter!
      config.filter = {
        nets: {}
        macs: {}
        times: {}
        users: {}
        rules: {}
        allowed_domains: { "github.com" }
      }
      f.load!
      assert.is_true  (f.decide { domain: "github.com" })
      assert.is_false (f.decide { domain: "evil.example" })

  describe "get_rule_on_response / run_on_response", ->
    it "get_rule_on_response renvoie une liste vide pour un rule_id inconnu", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      f.load!
      assert.same {}, f.get_rule_on_response "r_does_not_exist"

    it "get_rule_on_response renvoie les callbacks on_response pour une règle dns_strip", ->
      f = fresh_filter!
      config.filter = base_filter_cfg {
        rules: {
          { rule_id: "strip", actions: { "dns_strip", "allow" }, dns_strip: { rr_type: "AAAA" }, conditions: { to_domain: "ex.test" } }
        }
      }
      f.load!
      on_resp = f.get_rule_on_response "r_strip"
      assert.is_true #on_resp > 0

    it "run_on_response délègue à filter.rule.run_on_response (rule_id inconnu → dns_raw inchangé)", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      f.load!
      ctx = f.run_on_response "r_does_not_exist", "RAWDNS", "some reason"
      assert.equals "RAWDNS", ctx.dns_raw

  describe "reload (load() appelé deux fois)", ->
    it "la seconde config remplace entièrement la première", ->
      f = fresh_filter!
      config.filter = base_filter_cfg!
      f.load!
      assert.is_false (f.decide { domain: "blocked.example" })

      config.filter = {
        nets: {}
        macs: {}
        times: {}
        users: {}
        rules: { { rule_id: "allow_all", actions: { "allow" } } }
      }
      f.load!
      assert.is_true (f.decide { domain: "blocked.example" })
