local ffi_local = require("ffi")
local fake_ctx = ffi_local.new("char[1]")
package.loaded["ffi_defs"] = {
  ffi = ffi_local,
  libc = ffi_local.C,
  libnfq = { },
  libnft = {
    nft_ctx_new = function()
      return fake_ctx
    end,
    nft_run_cmd_from_buffer = function()
      return 0
    end,
    nft_ctx_get_error_buffer = function()
      return nil
    end
  }
}
package.loaded["nft_rules"] = nil
local _update_0 = "log"
package.loaded[_update_0] = package.loaded[_update_0] or (function()
  local nop
  nop = function() end
  return {
    log_debug = nop,
    log_warn = nop,
    log_error = nop,
    log_info = nop,
    get_log_level_num = function()
      return 0
    end,
    set_action_prefix = nop
  }
end)()
local _update_1 = "config"
package.loaded[_update_1] = package.loaded[_update_1] or (function()
  return {
    nfqueue = {
      questions = "0",
      responses = "1",
      captive = "2",
      reject = "3",
      auth = "5",
      sni = "6",
      sip = nil
    },
    nft = {
      ip_timeout = "2m",
      family = "bridge",
      table = "dns-filter-bridge",
      extra_rules = { }
    },
    runtime = {
      log_level = "INFO"
    },
    filter = {
      rules = { }
    },
    doh = {
      port = 8443
    },
    sni = {
      placement = "residual"
    }
  }
end)()
local _update_2 = "filter.nft_compiler"
package.loaded[_update_2] = package.loaded[_update_2] or {
  compile = function()
    return nil, {
      render = function()
        return "", {
          render_sets_only = function()
            return ""
          end
        }
      end
    }
  end
}
local _update_3 = "filter.nft_dynamic_sets"
package.loaded[_update_3] = package.loaded[_update_3] or {
  generate_set_creation_commands = function()
    return { }
  end
}
local _update_4 = "filter.rule"
package.loaded[_update_4] = package.loaded[_update_4] or {
  compile_rules = function()
    return {
      rules_metadata = { }
    }
  end
}
local _test
_test = require("nft_rules")._test
local collect_ips, fmt_elements, substitute
collect_ips, fmt_elements, substitute = _test.collect_ips, _test.fmt_elements, _test.substitute
describe("nft_rules._test.fmt_elements", function()
  it("retourne une chaîne vide pour une table vide", function()
    return assert.equals("", fmt_elements({ }))
  end)
  it("formate un seul élément", function()
    local result = fmt_elements({
      "192.168.1.1"
    })
    return assert.equals("    elements = { 192.168.1.1 }\n", result)
  end)
  it("formate plusieurs éléments séparés par des virgules", function()
    local result = fmt_elements({
      "10.0.0.1",
      "10.0.0.2",
      "172.16.0.1"
    })
    return assert.equals("    elements = { 10.0.0.1, 10.0.0.2, 172.16.0.1 }\n", result)
  end)
  it("formate une adresse IPv6", function()
    local result = fmt_elements({
      "2a11:6c7:1700:7801:b488:29ff:feba:eda8"
    })
    return assert.equals("    elements = { 2a11:6c7:1700:7801:b488:29ff:feba:eda8 }\n", result)
  end)
  return it("produit une syntaxe nft valide (pas de virgule finale)", function()
    local result = fmt_elements({
      "1.2.3.4",
      "5.6.7.8"
    })
    return assert.is_nil(result:match(",%s*}"))
  end)
end)
describe("nft_rules._test.collect_ips", function()
  local with_popen
  with_popen = function(fake_output, fn)
    local orig = io.popen
    io.popen = function(cmd)
      local lines = { }
      for line in (fake_output .. "\n"):gmatch("([^\n]*)\n") do
        lines[#lines + 1] = line
      end
      local idx = 0
      return {
        lines = function()
          return function()
            idx = idx + 1
            return lines[idx]
          end
        end,
        close = function() end
      }
    end
    local ok, err = pcall(fn)
    io.popen = orig
    if not (ok) then
      return error(err)
    end
  end
  local ip_addr_v4_output = [[1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: br: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 58:d6:1f:57:4f:94 brd ff:ff:ff:ff:ff:ff
    inet 10.35.1.254/24 brd 10.35.1.255 scope global br
       valid_lft forever preferred_lft forever
    inet 10.35.99.1/24 brd 10.35.99.255 scope global br.99
       valid_lft forever preferred_lft forever]]
  local ip_addr_v6_output = [[4: br: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 58:d6:1f:57:4f:94 brd ff:ff:ff:ff:ff:ff
    inet6 2a11:6c7:1700:7801:b488:29ff:feba:eda8/64 scope global dynamic mngtmpaddr
       valid_lft 86360sec preferred_lft 86360sec
    inet6 fe80::5ad6:1fff:fe57:4f94/64 scope link
       valid_lft forever preferred_lft forever]]
  it("extrait les adresses IPv4 depuis la sortie de ip -4 addr show", function()
    return with_popen(ip_addr_v4_output, function()
      local ips = collect_ips("ip -4 addr show", "%s+inet%s+([%d%.]+)/", nil)
      assert.equals(3, #ips)
      assert.equals("127.0.0.1", ips[1])
      assert.equals("10.35.1.254", ips[2])
      return assert.equals("10.35.99.1", ips[3])
    end)
  end)
  it("extrait les adresses IPv6 non-link-local depuis ip -6 addr show", function()
    return with_popen(ip_addr_v6_output, function()
      local ips = collect_ips("ip -6 addr show", "%s+inet6%s+([%x:]+)/", "^fe80")
      assert.equals(1, #ips)
      return assert.equals("2a11:6c7:1700:7801:b488:29ff:feba:eda8", ips[1])
    end)
  end)
  it("exclut les adresses fe80:: (link-local)", function()
    return with_popen(ip_addr_v6_output, function()
      local ips = collect_ips("ip -6 addr show", "%s+inet6%s+([%x:]+)/", "^fe80")
      for _, ip in ipairs(ips) do
        assert.is_nil(ip:match("^fe80"))
      end
    end)
  end)
  it("retourne une table vide si io.popen retourne nil", function()
    local orig = io.popen
    io.popen = function()
      return nil
    end
    local ips = collect_ips("ip -4 addr show", "%s+inet%s+([%d%.]+)/", nil)
    io.popen = orig
    return assert.equals(0, #ips)
  end)
  return it("retourne une table vide si la sortie ne contient aucune adresse", function()
    return with_popen("nothing relevant here\nno addresses", function()
      local ips = collect_ips("ip -4 addr show", "%s+inet%s+([%d%.]+)/", nil)
      return assert.equals(0, #ips)
    end)
  end)
end)
describe("nft_rules : substitution de {FILTER_IPS4/6_ELEMENTS}", function()
  it("le résultat de fmt_elements s'insère syntaxiquement dans un bloc set nft", function()
    local elements = fmt_elements({
      "10.0.0.1",
      "192.168.1.1"
    })
    local set_block = "  set filter_ips4 {\n    type ipv4_addr\n" .. elements .. "  }"
    local count = 0
    for _ in set_block:gmatch("elements = {") do
      count = count + 1
    end
    assert.equals(1, count)
    assert.truthy(set_block:find("10.0.0.1"))
    return assert.truthy(set_block:find("192.168.1.1"))
  end)
  return it("un set vide (pas d'IPs) ne contient pas de clause elements", function()
    local elements = fmt_elements({ })
    local set_block = "  set filter_ips4 {\n    type ipv4_addr\n" .. elements .. "  }"
    return assert.is_nil(set_block:find("elements"))
  end)
end)
describe("nft_rules : placement SNI integral/residual", function()
  local cfg = require("config")
  cfg.nfqueue = cfg.nfqueue or {
    questions = "0",
    responses = "1",
    captive = "2",
    reject = "3",
    auth = "5",
    sni = "6",
    sip = nil
  }
  cfg.nfqueue.sni = "6"
  cfg.nft = cfg.nft or {
    ip_timeout = "2m",
    family = "bridge",
    table = "dns-filter-bridge",
    extra_rules = { }
  }
  cfg.runtime = cfg.runtime or {
    log_level = "INFO"
  }
  cfg.filter = cfg.filter or {
    rules = { }
  }
  cfg.doh = cfg.doh or {
    port = 8443
  }
  cfg.sni = cfg.sni or { }
  local tmpl = "[PRE:{SNI_RULES_PRE}][POST:{SNI_RULES_POST}]"
  local split
  split = function(out)
    return out:match("%[PRE:(.-)%]%[POST:(.-)%]")
  end
  it("residual : règles SNI rendues APRÈS (POST), PRE vide", function()
    cfg.sni.placement = "residual"
    local pre, post = split(substitute(tmpl))
    assert.is_nil(pre:find("queue num 6"))
    assert.truthy(post:find("th dport 443"))
    assert.truthy(post:find("queue num 6"))
    return assert.truthy(post:find("sni_quic"))
  end)
  it("integral : règles SNI rendues AVANT (PRE), POST vide", function()
    cfg.sni.placement = "integral"
    local pre, post = split(substitute(tmpl))
    assert.truthy(pre:find("th dport 443"))
    assert.truthy(pre:find("queue num 6"))
    return assert.is_nil(post:find("queue num 6"))
  end)
  return it("défaut (placement absent) : comportement residual", function()
    cfg.sni.placement = nil
    local pre, post = split(substitute(tmpl))
    assert.is_nil(pre:find("queue num 6"))
    assert.truthy(post:find("queue num 6"))
    cfg.sni.placement = "residual"
  end)
end)
return describe("dns-filter-bridge.nft : fast-path conntrack", function()
  local read_template
  read_template = function()
    local fh = assert(io.open("nft-rules/dns-filter-bridge.nft", "r"))
    local content = fh:read("*a")
    fh:close()
    return content
  end
  local tmpl = read_template()
  local cfg = require("config")
  cfg.nfqueue = cfg.nfqueue or {
    questions = "0",
    responses = "1",
    captive = "2",
    reject = "3",
    auth = "5",
    sni = "6",
    sip = nil
  }
  cfg.nfqueue.sni = "6"
  cfg.nft = cfg.nft or {
    ip_timeout = "2m",
    family = "bridge",
    table = "dns-filter-bridge",
    extra_rules = { }
  }
  cfg.runtime = cfg.runtime or {
    log_level = "INFO"
  }
  cfg.filter = cfg.filter or {
    rules = { }
  }
  cfg.doh = cfg.doh or {
    port = 8443
  }
  cfg.sni = cfg.sni or { }
  local FAST = "ct state established,related ct mark != 0x0 meta mark set ct mark counter meta mark vmap @cv_action_vmap"
  it("ne porte plus la règle inline (déplacée vers nft_rules.moon)", function()
    assert.is_nil(tmpl:find(FAST, 1, true))
    assert.truthy(tmpl:find("{FAST_PATH_EARLY}", 1, true))
    return assert.truthy(tmpl:find("{FAST_PATH_LATE}", 1, true))
  end)
  it("déclare la règle de mémorisation du verdict en ct mark", function()
    return assert.truthy(tmpl:find("meta mark != 0x0 ct mark set meta mark"))
  end)
  describe("rendu residual (ancre HAUTE)", function()
    local out = nil
    before_each(function()
      cfg.sni.placement = "residual"
      out = substitute(tmpl)
    end)
    it("n'a aucun placeholder {FAST_PATH_*} résiduel", function()
      return assert.is_nil(out:find("{FAST_PATH_", 1, true))
    end)
    it("rend la fast-path AVANT le bloc infra (court-circuit du bloc amont)", function()
      local fp = out:find(FAST, 1, true)
      local infra = out:find("DHCPv4", 1, true)
      assert.truthy(fp)
      return assert.is_true(fp < infra)
    end)
    return it("rend la fast-path AVANT le dispatch", function()
      return assert.is_true((out:find(FAST, 1, true)) < (out:find("jump cv_rules_dispatch", 1, true)))
    end)
  end)
  describe("rendu integral (ancre BASE, SNI préservé)", function()
    local out = nil
    before_each(function()
      cfg.sni.placement = "integral"
      out = substitute(tmpl)
    end)
    it("n'a aucun placeholder {FAST_PATH_*} résiduel", function()
      return assert.is_nil(out:find("{FAST_PATH_", 1, true))
    end)
    it("rend la fast-path APRÈS les règles SNI 443 (inspection préservée)", function()
      local fp = out:find(FAST, 1, true)
      local sni = out:find("th dport {443", 1, true)
      assert.truthy(fp)
      assert.truthy(sni)
      return assert.is_true(fp > sni)
    end)
    it("n'apparaît qu'une seule fois (pas d'ancre HAUTE dupliquée)", function()
      local first = out:find(FAST, 1, true)
      return assert.is_nil(out:find(FAST, first + 1, true))
    end)
    it("reste AVANT le dispatch", function()
      return assert.is_true((out:find(FAST, 1, true)) < (out:find("jump cv_rules_dispatch", 1, true)))
    end)
    return after_each(function()
      cfg.sni.placement = "residual"
    end)
  end)
  local dangerous = {
    "{SNI_RULES_PRE}",
    "{SNI_RULES_POST}",
    "{SIP_RULES}",
    "{COMPILED_FILTER_SETS}",
    "{COMPILED_FILTER_RULES}",
    "{FILTER_IPS4_ELEMENTS}",
    "{FILTER_IPS6_ELEMENTS}"
  }
  return it("ne contient aucun placeholder multi-ligne dans une ligne de commentaire", function()
    for line in (tmpl .. "\n"):gmatch("([^\n]*)\n") do
      local stripped = line:match("^%s*(.-)%s*$")
      if stripped:sub(1, 1) == "#" then
        for _, ph in ipairs(dangerous) do
          assert.is_nil(stripped:find(ph, 1, true), "commentaire avec placeholder multi-ligne " .. tostring(ph) .. " : " .. tostring(stripped))
        end
      end
    end
  end)
end)
