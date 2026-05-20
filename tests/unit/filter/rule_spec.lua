local _update_0 = "ipc"
package.loaded[_update_0] = package.loaded[_update_0] or {
  register_modifier = function()
    return nil
  end
}
local _update_1 = "dns_ede"
package.loaded[_update_1] = package.loaded[_update_1] or {
  strip_dns_rr = function(raw, _t)
    return raw
  end,
  add_ede_modified = function(raw, _r)
    return raw
  end,
  clear_ad_bit = function(raw)
    return raw
  end
}
local _update_2 = "auth.sessions"
package.loaded[_update_2] = package.loaded[_update_2] or {
  session_for_mac = function()
    return nil
  end,
  enrich_session_ip = function()
    return nil
  end,
  bind_session_mac = function()
    return nil
  end,
  user_for_mac = function()
    return nil
  end
}
local _update_3 = "auth.user_sessions"
package.loaded[_update_3] = package.loaded[_update_3] or {
  get_session = function()
    return nil
  end
}
local _update_4 = "mac_learner_ipc"
package.loaded[_update_4] = package.loaded[_update_4] or {
  get_mac = function()
    return nil
  end
}
return describe("filter.rule", function()
  local rule_mod = require("filter.rule")
  local cfg = {
    nft = {
      ip_timeout = "2m"
    },
    macs = { }
  }
  describe("compile_rule / actions", function()
    it("allow → verdict true, rule_id prefix r_", function()
      local eval_fn, meta = rule_mod.compile_rule(cfg, {
        rule_id = "my_allow",
        description = "Allow test",
        actions = {
          "allow"
        }
      }, 1)
      local v, msg, rid, tout, desc = eval_fn({ })
      assert.is_true(v)
      assert.is_not_nil(msg)
      assert.equals("r_my_allow", rid)
      assert.equals("2m", tout)
      assert.equals("Allow test", desc)
      assert.is_false(meta.worker_only)
      assert.equals(1, #meta.actions)
      assert.equals("allow", meta.actions[1].name)
      return assert.is_true(meta.actions[1].capabilities.nft)
    end)
    it("deny → verdict false", function()
      local eval_fn, meta = rule_mod.compile_rule(cfg, {
        actions = {
          "deny"
        }
      }, 1)
      local v, _ = eval_fn({ })
      assert.is_false(v)
      assert.is_false(meta.worker_only)
      return assert.equals("deny", meta.actions[1].name)
    end)
    it("dnsonly → verdict true, worker_only=true", function()
      local eval_fn, meta = rule_mod.compile_rule(cfg, {
        description = "DNS only",
        actions = {
          "dnsonly"
        }
      }, 1)
      local v, _ = eval_fn({ })
      assert.is_true(v)
      assert.is_true(meta.worker_only)
      return assert.is_false(meta.actions[1].capabilities.nft)
    end)
    it("mail → verdict nil (effet de bord pur)", function()
      local eval_fn, _ = rule_mod.compile_rule(cfg, {
        actions = {
          "mail"
        }
      }, 1)
      local v
      v, _ = eval_fn({ })
      return assert.is_nil(v)
    end)
    it("strip_A + allow → on_response collecté (2 callbacks)", function()
      local eval_fn, meta = rule_mod.compile_rule(cfg, {
        description = "Strip A + allow",
        actions = {
          "strip_A",
          "allow"
        }
      }, 1)
      assert.equals(2, #meta.on_response)
      local v, _ = eval_fn({ })
      return assert.is_true(v)
    end)
    it("strip_AAAA + allow → on_response collecté (2 callbacks)", function()
      local eval_fn, meta = rule_mod.compile_rule(cfg, {
        description = "Strip AAAA + allow",
        actions = {
          "strip_AAAA",
          "allow"
        }
      }, 1)
      assert.equals(2, #meta.on_response)
      local v, _ = eval_fn({ })
      return assert.is_true(v)
    end)
    it("worker_only propagé depuis les actions (dnsonly + from_vlan)", function()
      local _, meta = rule_mod.compile_rule(cfg, {
        actions = {
          "dnsonly"
        },
        conditions = {
          from_vlan = 5
        }
      }, 1)
      return assert.is_true(meta.worker_only)
    end)
    it("nft_timeout de la règle surpasse le global", function()
      local _, meta = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        },
        nft_timeout = "10m"
      }, 1)
      return assert.equals("10m", meta.timeout)
    end)
    return it("rule_id implicite depuis idx", function()
      local _, meta = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        }
      }, 7)
      return assert.equals("r_7", meta.rule_id)
    end)
  end)
  describe("compile_rule / conditions", function()
    it("from_vlan : évaluation match et non-match", function()
      local eval_fn, meta = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        },
        conditions = {
          from_vlan = 100
        }
      }, 1)
      assert.is_false(meta.worker_only)
      assert.equals("from_vlan", meta.conditions[1].name)
      local v, _ = eval_fn({
        vlan = 100
      })
      assert.is_true(v)
      local v2
      v2, _ = eval_fn({
        vlan = 200
      })
      return assert.is_nil(v2)
    end)
    it("from_net : évaluation match et non-match", function()
      local eval_fn, _ = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        },
        conditions = {
          from_net = "192.168.0.0/16"
        }
      }, 1)
      local v
      v, _ = eval_fn({
        src_ip = "192.168.1.42"
      })
      assert.is_true(v)
      local v2
      v2, _ = eval_fn({
        src_ip = "10.0.0.1"
      })
      return assert.is_nil(v2)
    end)
    it("from_mac : évaluation insensible à la casse", function()
      local eval_fn, _ = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        },
        conditions = {
          from_mac = "aa:bb:cc:dd:ee:ff"
        }
      }, 1)
      local v
      v, _ = eval_fn({
        mac = "AA:BB:CC:DD:EE:FF"
      })
      assert.is_true(v)
      local v2
      v2, _ = eval_fn({
        mac = "11:22:33:44:55:66"
      })
      return assert.is_nil(v2)
    end)
    it("to_domain : worker_only=true, creates_dynamic_scope=true", function()
      local eval_fn, meta = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        },
        conditions = {
          to_domain = "github.com"
        }
      }, 1)
      assert.is_true(meta.worker_only)
      assert.is_true(meta.creates_dynamic_scope)
      local v, _ = eval_fn({
        domain = "github.com"
      })
      assert.is_true(v)
      local v2
      v2, _ = eval_fn({
        domain = "evil.com"
      })
      return assert.is_nil(v2)
    end)
    it("conditions multiples : ET logique implicite", function()
      local eval_fn, _ = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        },
        conditions = {
          from_net = "192.168.0.0/16",
          from_vlan = 10
        }
      }, 1)
      local v
      v, _ = eval_fn({
        src_ip = "192.168.1.1",
        vlan = 10
      })
      assert.is_true(v)
      local v2
      v2, _ = eval_fn({
        src_ip = "192.168.1.1",
        vlan = 99
      })
      assert.is_nil(v2)
      local v3
      v3, _ = eval_fn({
        src_ip = "10.0.0.1",
        vlan = 10
      })
      return assert.is_nil(v3)
    end)
    it("any_of : OU logique entre sous-conditions", function()
      local eval_fn, _ = rule_mod.compile_rule(cfg, {
        actions = {
          "allow"
        },
        conditions = {
          any_of = {
            {
              from_vlan = 1
            },
            {
              from_vlan = 2
            }
          }
        }
      }, 1)
      local v
      v, _ = eval_fn({
        vlan = 1
      })
      assert.is_true(v)
      local v2
      v2, _ = eval_fn({
        vlan = 2
      })
      assert.is_true(v2)
      local v3
      v3, _ = eval_fn({
        vlan = 99
      })
      return assert.is_nil(v3)
    end)
    return it("sans conditions : toujours vrai (règle par défaut)", function()
      local eval_fn, _ = rule_mod.compile_rule(cfg, {
        actions = {
          "deny"
        }
      }, 1)
      local v
      v, _ = eval_fn({ })
      assert.is_false(v)
      local v2
      v2, _ = eval_fn({
        domain = "anything.com",
        src_ip = "1.2.3.4"
      })
      return assert.is_false(v2)
    end)
  end)
  describe("compile_rules", function()
    it("compile une liste de règles", function()
      local compiled = rule_mod.compile_rules({
        nft = {
          ip_timeout = "2m"
        },
        macs = { },
        rules = {
          {
            rule_id = "allow_lan",
            actions = {
              "allow"
            },
            conditions = {
              from_net = "10.0.0.0/8"
            }
          },
          {
            rule_id = "deny_default",
            actions = {
              "deny"
            }
          }
        }
      })
      assert.equals(2, #compiled)
      assert.equals(2, #compiled.rules_metadata)
      assert.equals("r_allow_lan", compiled.rules_metadata[1].rule_id)
      return assert.equals("r_deny_default", compiled.rules_metadata[2].rule_id)
    end)
    it("liste vide → pas de règle", function()
      local compiled = rule_mod.compile_rules({
        rules = { }
      })
      assert.equals(0, #compiled)
      return assert.equals(0, #compiled.rules_metadata)
    end)
    return it("ids en conflit → déduplication avec suffixe", function()
      local compiled = rule_mod.compile_rules({
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
      })
      assert.equals("r_allow_lan", compiled.rules_metadata[1].rule_id)
      return assert.equals("r_allow_lan_2", compiled.rules_metadata[2].rule_id)
    end)
  end)
  describe("decide", function()
    it("première règle qui matche remporte (first_match_wins)", function()
      local rules = rule_mod.compile_rules({
        nft = {
          ip_timeout = "2m"
        },
        macs = { },
        decision = {
          first_match_wins = true
        },
        rules = {
          {
            rule_id = "allow_vlan1",
            actions = {
              "allow"
            },
            conditions = {
              from_vlan = 1
            }
          },
          {
            rule_id = "deny_all",
            actions = {
              "deny"
            }
          }
        }
      })
      local v, _, desc = rule_mod.decide(rules, {
        vlan = 1
      })
      return assert.is_true(v)
    end)
    it("default deny si aucune règle ne matche", function()
      local rules = rule_mod.compile_rules({
        nft = {
          ip_timeout = "2m"
        },
        macs = { },
        rules = {
          {
            actions = {
              "allow"
            },
            conditions = {
              from_vlan = 1
            }
          }
        }
      })
      local v, msg, _ = rule_mod.decide(rules, {
        vlan = 99
      })
      assert.is_false(v)
      return assert.is_not_nil(msg)
    end)
    return it("continue_to_next_rule : la dernière règle gagne", function()
      local rules = rule_mod.compile_rules({
        nft = {
          ip_timeout = "2m"
        },
        macs = { },
        decision = {
          continue_to_next_rule = true,
          first_match_wins = false
        },
        rules = {
          {
            rule_id = "r1",
            actions = {
              "allow"
            },
            conditions = {
              from_vlan = 1
            }
          },
          {
            rule_id = "r2",
            actions = {
              "deny"
            },
            conditions = {
              from_vlan = 1
            }
          }
        }
      })
      local v, _
      v, _, _ = rule_mod.decide(rules, {
        vlan = 1
      })
      return assert.is_false(v)
    end)
  end)
  return describe("decide_meta", function()
    it("retourne table structurée avec verdict/reason/rule_id/timeout", function()
      local rules = rule_mod.compile_rules({
        nft = {
          ip_timeout = "2m"
        },
        macs = { },
        rules = {
          {
            rule_id = "accept_all",
            actions = {
              "allow"
            }
          }
        }
      })
      local meta = rule_mod.decide_meta(rules, { })
      assert.is_true(meta.verdict)
      assert.is_not_nil(meta.reason)
      assert.equals("r_accept_all", meta.rule_id)
      assert.equals("2m", meta.timeout)
      return assert.is_not_nil(meta.description)
    end)
    return it("verdict false si liste de règles vide", function()
      local rules = rule_mod.compile_rules({
        rules = { }
      })
      local meta = rule_mod.decide_meta(rules, { })
      return assert.is_false(meta.verdict)
    end)
  end)
end)
