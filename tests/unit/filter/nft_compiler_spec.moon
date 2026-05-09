-- tests/unit/filter/nft_compiler_spec.moon

describe "filter.nft_compiler", ->
  compiler = require "filter.nft_compiler"

  it "compile rule metadata for dns+time+subnet+proto/ports", ->
    cfg = {
      nets: {
        lan: {"192.168.0.0/16"}
      }
      rules: {
        {
          rule_id: "dns_workhours"
          description: "DNS only business hours"
          actions: {"dnsonly"}
          conditions: {
            { to_domain: "example.org" }
            { in_time: "business_hours" }
            { from_netlist: "lan" }
          }
          network: {
            proto: {"udp", "tcp", "gre"}
            ports: {"443", "53", "not-a-port", "1000-2000"}
          }
        }
      }
    }

    plan = compiler.compile cfg
    assert.is_true plan.first_match_wins
    assert.equals 1, #plan.rules

    r = plan.rules[1]
    assert.equals "dns_workhours", r.rule_id
    assert.equals "dnsonly", r.action
    assert.is_true r.dns_scope
    assert.same {"to_domain:example.org"}, r.dns_refs
    assert.same {"business_hours"}, r.time_ranges
    assert.same {"192.168.0.0/16"}, r.source_ipv4
    assert.same {"tcp", "udp"}, r.protocols
    assert.same {"1000-2000", "443", "53"}, r.ports
    assert.equals r, plan.rules_by_id.dns_workhours

  it "ensures unique stable rule_id values", ->
    cfg = {
      rules: {
        { rule_id: "allow_lan", actions: {"allow"} }
        { rule_id: "allow_lan", actions: {"deny"} }
      }
    }

    plan = compiler.compile cfg
    assert.equals "allow_lan", plan.rules[1].rule_id
    assert.equals "allow_lan_2", plan.rules[2].rule_id
    assert.equals plan.rules[1], plan.rules_by_id.allow_lan
    assert.equals plan.rules[2], plan.rules_by_id.allow_lan_2

  it "renders dispatch with first_match_wins guard when enabled", ->
    cfg = {
      decision: { first_match_wins: true }
      rules: {
        { rule_id: "r1", actions: {"allow"} }
        { rule_id: "r2", actions: {"deny"} }
      }
    }
    plan = compiler.compile cfg
    out = compiler.render plan

    assert.is_not_nil out\find "chain cv_rules_dispatch", 1, true
    assert.is_not_nil out\find "meta mark != 0x0 return comment \"first_match_wins\"", 1, true

  it "does not render first_match_wins guard when disabled", ->
    cfg = {
      decision: { first_match_wins: false }
      rules: {
        { rule_id: "r1", actions: {"allow"} }
        { rule_id: "r2", actions: {"deny"} }
      }
    }
    plan = compiler.compile cfg
    out = compiler.render plan

    assert.is_nil out\find "meta mark != 0x0 return comment \"first_match_wins\"", 1, true

  it "renders nft fragments for sets/chains/map", ->
    cfg = {
      rules: {
        {
          rule_id: "r_frag"
          actions: {"deny"}
          conditions: {
            { from_net: "10.0.0.0/8" }
          }
          network: {
            proto: {"tcp"}
            ports: {"443"}
          }
        }
      }
    }
    plan = compiler.compile cfg
    out = compiler.render plan

    assert.is_not_nil out\find "map cv_rule_action_vmap", 1, true
    assert.is_not_nil out\find "set cv_rule_r_frag_src4", 1, true
    assert.is_not_nil out\find "set cv_rule_r_frag_dports", 1, true
    assert.is_not_nil out\find "chain cv_rule_r_frag", 1, true
    assert.is_not_nil out\find "meta l4proto { tcp } th dport @cv_rule_r_frag_dports", 1, true

