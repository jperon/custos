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
local _auth_sessions_stub = {
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
package.loaded["auth.sessions"] = _auth_sessions_stub
package.loaded["auth.user_sessions"] = {
  get_session = function()
    return nil
  end
}
package.loaded["mac_learner_ipc"] = {
  get_mac = function()
    return nil
  end
}
describe("filter.conditions.any_of", function()
  local any_of_factory = require("filter.conditions.any_of")
  local cfg = {
    nft = {
      ip_timeout = "2m"
    }
  }
  it("OU logique : retourne true si la première sous-condition passe", function()
    local cond = (any_of_factory(cfg))({
      {
        from_vlan = 1
      },
      {
        from_vlan = 2
      }
    })
    local v, _ = cond.eval({
      vlan = 1
    })
    return assert.is_true(v)
  end)
  it("OU logique : retourne true si la deuxième sous-condition passe", function()
    local cond = (any_of_factory(cfg))({
      {
        from_vlan = 1
      },
      {
        from_vlan = 2
      }
    })
    local v, _ = cond.eval({
      vlan = 2
    })
    return assert.is_true(v)
  end)
  it("retourne false si aucune sous-condition ne passe", function()
    local cond = (any_of_factory(cfg))({
      {
        from_vlan = 1
      },
      {
        from_vlan = 2
      }
    })
    local v, msg = cond.eval({
      vlan = 99
    })
    assert.is_false(v)
    return assert.is_not_nil(msg)
  end)
  it("table vide → false", function()
    local cond = (any_of_factory(cfg))({ })
    local v, _ = cond.eval({
      vlan = 1
    })
    return assert.is_false(v)
  end)
  it("nil → false", function()
    local cond = (any_of_factory(cfg))(nil)
    local v, _ = cond.eval({ })
    return assert.is_false(v)
  end)
  it("capabilities : worker=true, nft=false", function()
    local cond = (any_of_factory(cfg))({
      {
        from_vlan = 1
      }
    })
    assert.is_true(cond.capabilities.worker)
    return assert.is_false(cond.capabilities.nft)
  end)
  it("creates_dynamic_scope hérité si sous-condition a dns scope", function()
    local cond = (any_of_factory(cfg))({
      {
        to_domain = "example.com"
      }
    })
    return assert.is_true(cond.creates_dynamic_scope)
  end)
  return it("creates_dynamic_scope false si pas de sous-condition dns", function()
    local cond = (any_of_factory(cfg))({
      {
        from_vlan = 1
      }
    })
    return assert.is_false((not not cond.creates_dynamic_scope))
  end)
end)
describe("filter.conditions.to_net", function()
  local to_net_factory = require("filter.conditions.to_net")
  local cfg = { }
  it("_any → true si dst_ip présente", function()
    local cond = (to_net_factory(cfg))("_any")
    local v, _ = cond.eval({
      dst_ip = "8.8.8.8"
    })
    return assert.is_true(v)
  end)
  it("_any → false si dst_ip absente", function()
    local cond = (to_net_factory(cfg))("_any")
    local v, _ = cond.eval({ })
    return assert.is_false(v)
  end)
  it("_none → true si dst_ip absente", function()
    local cond = (to_net_factory(cfg))("_none")
    local v, _ = cond.eval({ })
    return assert.is_true(v)
  end)
  it("_none → false si dst_ip présente", function()
    local cond = (to_net_factory(cfg))("_none")
    local v, _ = cond.eval({
      dst_ip = "8.8.8.8"
    })
    return assert.is_false(v)
  end)
  it("IPv4 CIDR : match", function()
    local cond = (to_net_factory(cfg))("8.8.8.0/24")
    local v, _ = cond.eval({
      dst_ip = "8.8.8.8"
    })
    return assert.is_true(v)
  end)
  it("IPv4 CIDR : non-match", function()
    local cond = (to_net_factory(cfg))("8.8.8.0/24")
    local v, _ = cond.eval({
      dst_ip = "1.1.1.1"
    })
    return assert.is_false(v)
  end)
  it("IPv4 CIDR : dst_ip absente → false", function()
    local cond = (to_net_factory(cfg))("10.0.0.0/8")
    local v, _ = cond.eval({ })
    return assert.is_false(v)
  end)
  it("CIDR invalide → false toujours", function()
    local cond = (to_net_factory(cfg))("not_a_cidr/99")
    local v, _ = cond.eval({
      dst_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("IPv4 CIDR compile_nft family ip", function()
    local cond = (to_net_factory(cfg))("10.0.0.0/8")
    local expr, err = cond.compile_nft("ip")
    assert.equals("ip daddr 10.0.0.0/8", expr)
    return assert.is_nil(err)
  end)
  it("IPv4 CIDR compile_nft family ip6 → erreur", function()
    local cond = (to_net_factory(cfg))("10.0.0.0/8")
    local expr, err = cond.compile_nft("ip6")
    assert.is_nil(expr)
    return assert.is_not_nil(err)
  end)
  it("IPv6 CIDR compile_nft family inet6", function()
    local cond = (to_net_factory(cfg))("2001:db8::/32")
    local expr, err = cond.compile_nft("inet6")
    assert.equals("ip6 daddr 2001:db8::/32", expr)
    return assert.is_nil(err)
  end)
  return it("IPv6 CIDR compile_nft family ip → erreur cross-family", function()
    local cond = (to_net_factory(cfg))("2001:db8::/32")
    local expr, err = cond.compile_nft("ip")
    assert.is_nil(expr)
    return assert.is_not_nil(err)
  end)
end)
describe("filter.conditions.from_subnet", function()
  local from_subnet_factory = require("filter.conditions.from_subnet")
  local cfg = { }
  it("syntaxe string : match", function()
    local cond = (from_subnet_factory(cfg))("192.168.0.0/16")
    local v, _ = cond.eval({
      src_ip = "192.168.1.42"
    })
    return assert.is_true(v)
  end)
  it("syntaxe string : non-match", function()
    local cond = (from_subnet_factory(cfg))("192.168.0.0/16")
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("syntaxe table {net:...} : match", function()
    local cond = (from_subnet_factory(cfg))({
      net = "10.0.0.0/8"
    })
    local v, _ = cond.eval({
      src_ip = "10.5.3.1"
    })
    return assert.is_true(v)
  end)
  it("syntaxe table {net:...} : non-match", function()
    local cond = (from_subnet_factory(cfg))({
      net = "10.0.0.0/8"
    })
    local v, _ = cond.eval({
      src_ip = "192.168.1.1"
    })
    return assert.is_false(v)
  end)
  it("nil spec → false", function()
    local cond = (from_subnet_factory(cfg))(nil)
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("table sans net → false", function()
    local cond = (from_subnet_factory(cfg))({
      something = "else"
    })
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("CIDR invalide → false", function()
    local cond = (from_subnet_factory(cfg))("invalid/cidr")
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("src_ip absente → false", function()
    local cond = (from_subnet_factory(cfg))("10.0.0.0/8")
    local v, _ = cond.eval({ })
    return assert.is_false(v)
  end)
  it("compile_nft IPv4 family ip", function()
    local cond = (from_subnet_factory(cfg))("10.0.0.0/8")
    local expr, err = cond.compile_nft("ip")
    assert.equals("ip saddr 10.0.0.0/8", expr)
    return assert.is_nil(err)
  end)
  it("compile_nft IPv4 family ip6 → erreur cross-family", function()
    local cond = (from_subnet_factory(cfg))("10.0.0.0/8")
    local expr, err = cond.compile_nft("ip6")
    assert.is_nil(expr)
    return assert.is_not_nil(err)
  end)
  return it("compile_nft IPv6 family inet6", function()
    local cond = (from_subnet_factory(cfg))("2001:db8::/32")
    local expr, err = cond.compile_nft("inet6")
    assert.equals("ip6 saddr 2001:db8::/32", expr)
    return assert.is_nil(err)
  end)
end)
describe("filter.conditions.stolen_computer", function()
  local stolen_factory = require("filter.conditions.stolen_computer")
  local cfg = { }
  it("MAC dans la blacklist → true", function()
    local cond = (stolen_factory(cfg))({
      "aa:bb:cc:dd:ee:ff",
      "11:22:33:44:55:66"
    })
    local v, msg = cond.eval({
      mac = "AA:BB:CC:DD:EE:FF"
    })
    assert.is_true(v)
    return assert.is_not_nil(msg)
  end)
  it("MAC absente de la blacklist → false", function()
    local cond = (stolen_factory(cfg))({
      "aa:bb:cc:dd:ee:ff"
    })
    local v, _ = cond.eval({
      mac = "00:11:22:33:44:55"
    })
    return assert.is_false(v)
  end)
  it("req.mac absent → false", function()
    local cond = (stolen_factory(cfg))({
      "aa:bb:cc:dd:ee:ff"
    })
    local v, _ = cond.eval({ })
    return assert.is_false(v)
  end)
  it("table invalide (non-table) → false", function()
    local cond = (stolen_factory(cfg))("not_a_table")
    local v, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    return assert.is_false(v)
  end)
  it("compile_nft génère expression multi-MAC", function()
    local cond = (stolen_factory(cfg))({
      "aa:bb:cc:dd:ee:ff",
      "11:22:33:44:55:66"
    })
    local expr, err = cond.compile_nft("bridge")
    assert.is_not_nil(expr)
    assert.is_nil(err)
    assert.is_not_nil(expr:find("ether saddr", 1, true))
    assert.is_not_nil(expr:find("aa:bb:cc:dd:ee:ff", 1, true))
    return assert.is_not_nil(expr:find("11:22:33:44:55:66", 1, true))
  end)
  return it("capabilities : worker=true, nft=true", function()
    local cond = (stolen_factory(cfg))({
      "aa:bb:cc:dd:ee:ff"
    })
    assert.is_true(cond.capabilities.worker)
    return assert.is_true(cond.capabilities.nft)
  end)
end)
return describe("filter.conditions.from_user", function()
  local from_user_factory = require("filter.conditions.from_user")
  local cfg = {
    auth = {
      sessions_file = "/nonexistent/sessions.lua"
    },
    nft = { }
  }
  setup(function()
    package.loaded["auth.sessions"] = _auth_sessions_stub
  end)
  it("_none → true si pas de session", function()
    _auth_sessions_stub.session_for_mac = function()
      return nil
    end
    local cond = (from_user_factory(cfg))("_none")
    local v, _ = cond.eval({
      src_ip = "10.0.0.1",
      mac = "aa:bb:cc:dd:ee:ff"
    })
    return assert.is_true(v)
  end)
  it("_any → false si pas de session", function()
    _auth_sessions_stub.session_for_mac = function()
      return nil
    end
    local cond = (from_user_factory(cfg))("_any")
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("_any → true si session active", function()
    _auth_sessions_stub.session_for_mac = function()
      return {
        user = "alice",
        mac = "aa:bb:cc:dd:ee:ff"
      }
    end
    local cond = (from_user_factory(cfg))("_any")
    local v, _ = cond.eval({
      src_ip = "10.0.0.1",
      mac = "aa:bb:cc:dd:ee:ff"
    })
    assert.is_true(v)
    _auth_sessions_stub.session_for_mac = function()
      return nil
    end
  end)
  it("utilisateur spécifique → false si pas de session", function()
    _auth_sessions_stub.session_for_mac = function()
      return nil
    end
    local cond = (from_user_factory(cfg))("alice")
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("utilisateur spécifique → true si session correspond", function()
    _auth_sessions_stub.session_for_mac = function()
      return {
        user = "alice",
        mac = "aa:bb:cc:dd:ee:ff"
      }
    end
    local cond = (from_user_factory(cfg))("alice")
    local v, _ = cond.eval({
      src_ip = "10.0.0.1",
      mac = "aa:bb:cc:dd:ee:ff"
    })
    assert.is_true(v)
    _auth_sessions_stub.session_for_mac = function()
      return nil
    end
  end)
  it("source tls : get_session nil → false", function()
    package.loaded["auth.user_sessions"] = {
      get_session = function()
        return nil
      end
    }
    local cond = (from_user_factory(cfg))({
      user = "bob",
      source = "tls"
    })
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("source tls : session présente → true", function()
    package.loaded["auth.user_sessions"] = {
      get_session = function(user)
        if user == "bob" then
          return {
            src_ip = "10.0.0.1",
            mac = "aa:bb:cc:dd:ee:ff"
          }
        end
        return nil
      end
    }
    local cond = (from_user_factory(cfg))({
      user = "bob",
      source = "tls"
    })
    local v, _ = cond.eval({
      src_ip = "10.0.0.1"
    })
    assert.is_true(v)
    package.loaded["auth.user_sessions"] = {
      get_session = function()
        return nil
      end
    }
  end)
  it("user nil → false", function()
    local cond = (from_user_factory(cfg))({
      source = "tls"
    })
    local v, _ = cond.eval({ })
    return assert.is_false(v)
  end)
  return it("capabilities : requires_auth=true", function()
    local cond = (from_user_factory(cfg))("_any")
    assert.is_true(cond.capabilities.requires_auth)
    return assert.is_false(cond.capabilities.nft)
  end)
end)
