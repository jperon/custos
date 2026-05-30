-- tests/unit/filter/rule_spec.moon
-- Busted spec pour filter.rule : compile_rule, compile_rules, decide, decide_meta.
-- Charge depuis lua/ (pas de surcharge src/) pour alimenter luacov.

-- Stubs avant tout require de module de production
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

describe "filter.rule", ->
  rule_mod = require "filter.rule"

  cfg = {
    nft: { ip_timeout: "2m" }
    macs: {}
  }

  -- ── compile_rule — actions ──────────────────────────────────────

  describe "compile_rule / actions", ->
    it "allow → verdict true, rule_id prefix r_", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        rule_id:     "my_allow"
        description: "Allow test"
        actions:     { "allow" }
      }, 1
      v, msg, rid, tout, desc = eval_fn {}
      assert.is_true v
      assert.is_not_nil msg
      assert.equals "r_my_allow", rid
      assert.equals "2m", tout
      assert.equals "Allow test", desc
      assert.is_false meta.worker_only
      assert.equals 1, #meta.actions
      assert.equals "allow", meta.actions[1].name
      assert.is_true meta.actions[1].capabilities.nft

    it "deny → verdict false", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        actions: { "deny" }
      }, 1
      v, _ = eval_fn {}
      assert.is_false v
      assert.is_false meta.worker_only
      assert.equals "deny", meta.actions[1].name

    it "dnsonly → verdict true, worker_only=true", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        description: "DNS only"
        actions:     { "dnsonly" }
      }, 1
      v, _ = eval_fn {}
      assert.is_true v
      assert.is_true meta.worker_only
      assert.is_false meta.actions[1].capabilities.nft

    it "mail → verdict nil (effet de bord pur)", ->
      eval_fn, _ = rule_mod.compile_rule cfg, {
        actions: { "mail" }
      }, 1
      v, _ = eval_fn {}
      assert.is_nil v

    it "dns_strip (A) + allow → on_response collecté (2 callbacks)", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        description: "Strip A + allow"
        actions:     { "dns_strip", "allow" }
        dns_strip:   { rr_type: "A" }
      }, 1
      assert.equals 2, #meta.on_response
      v, _ = eval_fn {}
      assert.is_true v

    it "dns_strip (AAAA) + allow → on_response collecté (2 callbacks)", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        description: "Strip AAAA + allow"
        actions:     { "dns_strip", "allow" }
        dns_strip:   { rr_type: "AAAA" }
      }, 1
      assert.equals 2, #meta.on_response
      v, _ = eval_fn {}
      assert.is_true v

    it "worker_only propagé depuis les actions (dnsonly + from_vlan)", ->
      _, meta = rule_mod.compile_rule cfg, {
        actions:    { "dnsonly" }
        conditions: { from_vlan: 5 }
      }, 1
      assert.is_true meta.worker_only

    it "nft_timeout de la règle surpasse le global", ->
      _, meta = rule_mod.compile_rule cfg, {
        actions:     { "allow" }
        nft_timeout: "10m"
      }, 1
      assert.equals "10m", meta.timeout

    it "rule_id implicite depuis idx", ->
      _, meta = rule_mod.compile_rule cfg, {
        actions: { "allow" }
      }, 7
      assert.equals "r_7", meta.rule_id

    it "conditions non-table → error", ->
      assert.has_error ->
        rule_mod.compile_rule cfg, {
          actions:    { "allow" }
          conditions: "pas_une_table"
        }, 1

    it "nxdomain : block_modifiers collectés dans la règle", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        description: "NXDOMAIN test"
        actions:     { "nxdomain" }
      }, 1
      -- nxdomain expose block_modifiers (modifiers.nxdomain) → fusionnés
      assert.equals "nxdomain", meta.actions[1].name
      v, _ = eval_fn {}
      assert.is_false v

  -- ── compile_rule — conditions ─────────────────────────────────

  describe "compile_rule / conditions", ->
    it "from_vlan : évaluation match et non-match", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        actions:    { "allow" }
        conditions: { from_vlan: 100 }
      }, 1
      assert.is_false meta.worker_only
      assert.equals "from_vlan", meta.conditions[1].name

      v, _ = eval_fn { vlan: 100 }
      assert.is_true v
      v2, _ = eval_fn { vlan: 200 }
      assert.is_nil v2  -- condition non satisfaite

    it "from_net : évaluation match et non-match", ->
      eval_fn, _ = rule_mod.compile_rule cfg, {
        actions:    { "allow" }
        conditions: { from_net: "192.168.0.0/16" }
      }, 1
      v, _ = eval_fn { src_ip: "192.168.1.42" }
      assert.is_true v
      v2, _ = eval_fn { src_ip: "10.0.0.1" }
      assert.is_nil v2

    it "from_mac : évaluation insensible à la casse", ->
      eval_fn, _ = rule_mod.compile_rule cfg, {
        actions:    { "allow" }
        conditions: { from_mac: "aa:bb:cc:dd:ee:ff" }
      }, 1
      v, _ = eval_fn { mac: "AA:BB:CC:DD:EE:FF" }
      assert.is_true v
      v2, _ = eval_fn { mac: "11:22:33:44:55:66" }
      assert.is_nil v2

    it "to_domain : worker_only=true, creates_dynamic_scope=true", ->
      eval_fn, meta = rule_mod.compile_rule cfg, {
        actions:    { "allow" }
        conditions: { to_domain: "github.com" }
      }, 1
      assert.is_true meta.worker_only
      assert.is_true meta.creates_dynamic_scope
      v, _ = eval_fn { domain: "github.com" }
      assert.is_true v
      v2, _ = eval_fn { domain: "evil.com" }
      assert.is_nil v2

    it "conditions multiples : ET logique implicite", ->
      eval_fn, _ = rule_mod.compile_rule cfg, {
        actions:    { "allow" }
        conditions: { from_net: "192.168.0.0/16", from_vlan: 10 }
      }, 1
      v, _  = eval_fn { src_ip: "192.168.1.1", vlan: 10 }
      assert.is_true v
      v2, _ = eval_fn { src_ip: "192.168.1.1", vlan: 99 }
      assert.is_nil v2
      v3, _ = eval_fn { src_ip: "10.0.0.1", vlan: 10 }
      assert.is_nil v3

    it "any_of : OU logique entre sous-conditions", ->
      eval_fn, _ = rule_mod.compile_rule cfg, {
        actions:    { "allow" }
        conditions: {
          any_of: {
            { from_vlan: 1 }
            { from_vlan: 2 }
          }
        }
      }, 1
      v, _ = eval_fn { vlan: 1 }
      assert.is_true v
      v2, _ = eval_fn { vlan: 2 }
      assert.is_true v2
      v3, _ = eval_fn { vlan: 99 }
      assert.is_nil v3

    it "sans conditions : toujours vrai (règle par défaut)", ->
      eval_fn, _ = rule_mod.compile_rule cfg, {
        actions: { "deny" }
      }, 1
      v, _ = eval_fn {}
      assert.is_false v
      v2, _ = eval_fn { domain: "anything.com", src_ip: "1.2.3.4" }
      assert.is_false v2

  -- ── compile_rules ────────────────────────────────────────────

  describe "compile_rules", ->
    it "compile une liste de règles", ->
      compiled = rule_mod.compile_rules {
        nft: { ip_timeout: "2m" }
        macs: {}
        rules: {
          { rule_id: "allow_lan", actions: { "allow" }, conditions: { from_net: "10.0.0.0/8" } }
          { rule_id: "deny_default", actions: { "deny" } }
        }
      }
      assert.equals 2, #compiled
      assert.equals 2, #compiled.rules_metadata
      assert.equals "r_allow_lan",     compiled.rules_metadata[1].rule_id
      assert.equals "r_deny_default",  compiled.rules_metadata[2].rule_id

    it "liste vide → pas de règle", ->
      compiled = rule_mod.compile_rules { rules: {} }
      assert.equals 0, #compiled
      assert.equals 0, #compiled.rules_metadata

    it "ids en conflit → déduplication avec suffixe", ->
      compiled = rule_mod.compile_rules {
        rules: {
          { rule_id: "allow_lan", actions: { "allow" } }
          { rule_id: "allow_lan", actions: { "deny" } }
        }
      }
      assert.equals "r_allow_lan",   compiled.rules_metadata[1].rule_id
      assert.equals "r_allow_lan_2", compiled.rules_metadata[2].rule_id

  -- ── decide ────────────────────────────────────────────────────

  describe "decide", ->
    it "première règle qui matche remporte (first_match_wins)", ->
      rules = rule_mod.compile_rules {
        nft: { ip_timeout: "2m" }
        macs: {}
        decision: { first_match_wins: true }
        rules: {
          { rule_id: "allow_vlan1", actions: { "allow" }, conditions: { from_vlan: 1 } }
          { rule_id: "deny_all",    actions: { "deny" } }
        }
      }
      v, _, desc = rule_mod.decide rules, { vlan: 1 }
      assert.is_true v

    it "default deny si aucune règle ne matche", ->
      rules = rule_mod.compile_rules {
        nft: { ip_timeout: "2m" }
        macs: {}
        rules: {
          { actions: { "allow" }, conditions: { from_vlan: 1 } }
        }
      }
      v, msg, _ = rule_mod.decide rules, { vlan: 99 }
      assert.is_false v
      assert.is_not_nil msg

    it "continue_to_next_rule : la dernière règle gagne", ->
      rules = rule_mod.compile_rules {
        nft: { ip_timeout: "2m" }
        macs: {}
        decision: { continue_to_next_rule: true, first_match_wins: false }
        rules: {
          { rule_id: "r1", actions: { "allow" }, conditions: { from_vlan: 1 } }
          { rule_id: "r2", actions: { "deny"  }, conditions: { from_vlan: 1 } }
        }
      }
      v, _, _ = rule_mod.decide rules, { vlan: 1 }
      assert.is_false v  -- r2 (deny) est la dernière à avoir matché

  -- ── decide_meta ────────────────────────────────────────────────

  describe "decide_meta", ->
    it "retourne table structurée avec verdict/reason/rule_id/timeout", ->
      rules = rule_mod.compile_rules {
        nft: { ip_timeout: "2m" }
        macs: {}
        rules: { { rule_id: "accept_all", actions: { "allow" } } }
      }
      meta = rule_mod.decide_meta rules, {}
      assert.is_true meta.verdict
      assert.is_not_nil meta.reason
      assert.equals "r_accept_all", meta.rule_id
      assert.equals "2m", meta.timeout
      assert.is_not_nil meta.description

    it "verdict false si liste de règles vide", ->
      rules = rule_mod.compile_rules { rules: {} }
      meta = rule_mod.decide_meta rules, {}
      assert.is_false meta.verdict

  -- ── on_response : noyau commun (worker_responses + doh) ──────────
  describe "on_response_for", ->
    it "retrouve les callbacks de la règle par rule_id", ->
      rules = rule_mod.compile_rules {
        macs: {}
        rules: {
          { rule_id: "strip", actions: { "dns_strip", "allow" }, dns_strip: { rr_type: "AAAA" } }
        }
      }
      cbs = rule_mod.on_response_for rules, "r_strip"
      assert.equals 2, #cbs

    it "retourne {} si rule_id inconnu", ->
      rules = rule_mod.compile_rules { macs: {}, rules: { { rule_id: "a", actions: { "allow" } } } }
      assert.same {}, rule_mod.on_response_for rules, "r_inexistant"

    it "retourne {} si rules ou rule_id nil", ->
      assert.same {}, rule_mod.on_response_for nil, "r_x"
      assert.same {}, rule_mod.on_response_for {}, nil

  describe "apply_on_response", ->
    it "liste vide → inject_nft true, dns_raw inchangé", ->
      ctx = rule_mod.apply_on_response {}, "RAW", "reason"
      assert.equals "RAW", ctx.dns_raw
      assert.is_true ctx.inject_nft
      assert.is_false ctx.modified

    it "skip_nft seul (strip sans allow) → inject_nft false", ->
      cb = (c) -> c.skip_nft = true
      ctx = rule_mod.apply_on_response { cb }, "RAW", ""
      assert.is_true ctx.skip_nft
      assert.is_false ctx.inject_nft

    it "explicit_allow supplante skip_nft → inject_nft true", ->
      strip = (c) -> c.skip_nft = true
      allow = (c) -> c.explicit_allow = true
      ctx = rule_mod.apply_on_response { strip, allow }, "RAW", ""
      assert.is_true ctx.inject_nft

    it "callback peut modifier dns_raw et action_label", ->
      cb = (c) ->
        c.dns_raw = "PATCHED"
        c.modified = true
        c.action_label = "response_strip_AAAA"
      ctx = rule_mod.apply_on_response { cb }, "RAW", ""
      assert.equals "PATCHED", ctx.dns_raw
      assert.is_true ctx.modified
      assert.equals "response_strip_AAAA", ctx.action_label

  describe "run_on_response", ->
    it "dispatch complet par rule_id (dns_strip + allow → inject_nft true)", ->
      rules = rule_mod.compile_rules {
        macs: {}
        rules: {
          { rule_id: "strip", actions: { "dns_strip", "allow" }, dns_strip: { rr_type: "AAAA" } }
        }
      }
      ctx = rule_mod.run_on_response rules, "r_strip", "RAW", "bugfix"
      -- strip pose skip_nft, allow pose explicit_allow → injection maintenue
      assert.is_true ctx.skip_nft
      assert.is_true ctx.inject_nft
