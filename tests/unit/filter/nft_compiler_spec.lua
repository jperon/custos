return describe("filter.nft_compiler", function()
  local compiler = require("filter.nft_compiler")
  local rule_mod = require("filter.rule")
  it("compile rule metadata for dns+time+subnet+proto/ports", function()
    local cfg = {
      nets = {
        lan = {
          "192.168.0.0/16"
        }
      },
      nft = {
        ip_timeout = "2m"
      },
      rules = {
        {
          rule_id = "dns_workhours",
          description = "DNS only business hours",
          actions = {
            "dnsonly"
          },
          conditions = {
            to_domain = "example.org",
            in_time = "business_hours",
            from_net_list = "lan"
          },
          network = {
            proto = {
              "udp",
              "tcp",
              "gre"
            },
            ports = {
              "443",
              "53",
              "not-a-port",
              "1000-2000"
            }
          }
        }
      }
    }
    local compiled = rule_mod.compile_rules(cfg)
    local plan = compiler.compile(cfg, compiled.rules_metadata)
    assert.is_true(plan.first_match_wins)
    assert.equals(1, #plan.rules)
    local r = plan.rules[1]
    assert.equals("r_dns_workhours", r.rule_id)
    assert.equals("dnsonly", r.action)
    assert.same({
      "tcp",
      "udp"
    }, r.protocols)
    assert.same({
      "1000-2000",
      "443",
      "53"
    }, r.ports)
    return assert.equals(r, plan.rules_by_id.r_dns_workhours)
  end)
  it("ensures unique stable rule_id values", function()
    local cfg = {
      rules = {
        {
          rule_id = "allow_lan",
          actions = {
            "allow"
          }
        },
        {
          rule_id = "allow_lan",
          actions = {
            "deny"
          }
        }
      }
    }
    local plan = compiler.compile(cfg)
    assert.equals("r_allow_lan", plan.rules[1].rule_id)
    assert.equals("r_allow_lan_2", plan.rules[2].rule_id)
    assert.equals(plan.rules[1], plan.rules_by_id.r_allow_lan)
    return assert.equals(plan.rules[2], plan.rules_by_id.r_allow_lan_2)
  end)
  it("collect_referenced_netlists ignores missing netlists and merges legacy + metadata refs", function()
    local cfg = {
      nets = {
        office = {
          "192.168.10.0/24"
        }
      },
      filter = {
        netlists = {
          lan = {
            "10.0.0.0/8"
          }
        }
      },
      rules = {
        {
          rule_id = "legacy",
          conditions = {
            from_net_lists = {
              "office",
              "missing"
            },
            to_net_list = "lan"
          }
        }
      }
    }
    local compiled = rule_mod.compile_rules(cfg)
    local plan = compiler.compile(cfg, compiled.rules_metadata)
    local refs = compiler.collect_referenced_netlists(cfg, plan)
    assert.same({
      "lan",
      "office"
    }, refs)
    local out = compiler.render_sets_only(cfg, plan)
    assert.is_not_nil(out:find("set nets_lan", 1, true))
    assert.is_not_nil(out:find("set nets_office", 1, true))
    return assert.is_nil(out:find("set nets_missing", 1, true))
  end)
  it("does not render first_match_wins guard when disabled", function()
    local cfg = {
      decision = {
        first_match_wins = false
      },
      rules = {
        {
          rule_id = "r1",
          actions = {
            "allow"
          }
        },
        {
          rule_id = "r2",
          actions = {
            "deny"
          }
        }
      }
    }
    local plan = compiler.compile(cfg)
    local out = compiler.render(plan)
    return assert.is_nil(out:find("meta mark != 0x0 return comment \"first_match_wins\"", 1, true))
  end)
  return it("renders nft fragments for sets/chains/map", function()
    local cfg = {
      nft = {
        ip_timeout = "2m"
      },
      rules = {
        {
          rule_id = "frag",
          actions = {
            "deny"
          },
          conditions = {
            from_net = "10.0.0.0/8"
          },
          network = {
            proto = {
              "tcp"
            },
            ports = {
              "443"
            }
          }
        }
      }
    }
    local compiled = rule_mod.compile_rules(cfg)
    local plan = compiler.compile(cfg, compiled.rules_metadata)
    local out = compiler.render(plan)
    assert.is_not_nil(out:find("set cv_r_frag_dports", 1, true))
    assert.is_not_nil(out:find("chain cv_r_frag", 1, true))
    assert.is_not_nil(out:find("meta l4proto { tcp } th dport @cv_r_frag_dports", 1, true))
    return assert.is_not_nil(out:find("counter drop", 1, true))
  end)
end)
