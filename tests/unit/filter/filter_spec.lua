local ffi = require("ffi")
describe("filter.lib.bsearch", function()
  local bsearch
  bsearch = require("filter.lib.bsearch").bsearch
  it("trouve en début", function()
    local arr = ffi.new("uint64_t[3]", {
      100ULL,
      200ULL,
      300ULL
    })
    return assert.is_true((bsearch(arr, 3, 100ULL)))
  end)
  it("trouve en milieu", function()
    local arr = ffi.new("uint64_t[3]", {
      100ULL,
      200ULL,
      300ULL
    })
    return assert.is_true((bsearch(arr, 3, 200ULL)))
  end)
  it("trouve en fin", function()
    local arr = ffi.new("uint64_t[3]", {
      100ULL,
      200ULL,
      300ULL
    })
    return assert.is_true((bsearch(arr, 3, 300ULL)))
  end)
  it("retourne faux si absent", function()
    local arr = ffi.new("uint64_t[3]", {
      100ULL,
      200ULL,
      300ULL
    })
    return assert.is_false((bsearch(arr, 3, 150ULL)))
  end)
  return it("gère tableau vide", function()
    local arr = ffi.new("uint64_t[0]")
    return assert.is_false((bsearch(arr, 0, 42ULL)))
  end)
end)
describe("filter.lib.ipcalc", function()
  local ipcalc = require("filter.lib.ipcalc")
  it("IPv4 dans sous-réseau /16", function()
    local n = ipcalc.Net("192.168.0.0/16")
    assert.is_not_nil(n)
    return assert.is_true((n:contains("192.168.1.42")))
  end)
  it("IPv4 hors sous-réseau", function()
    local n = ipcalc.Net("192.168.0.0/16")
    return assert.is_false((n:contains("10.0.0.1")))
  end)
  it("masque /16 fonctionne", function()
    local n = ipcalc.Net("10.0.0.0/8")
    assert.is_true((n:contains("10.255.255.1")))
    return assert.is_false((n:contains("11.0.0.1")))
  end)
  it("IPv6 dans sous-réseau", function()
    local n = ipcalc.Net("2001:db8::/32")
    return assert.is_true((n:contains("2001:db8::1")))
  end)
  it("IPv6 hors sous-réseau", function()
    local n = ipcalc.Net("2001:db8::/32")
    return assert.is_false((n:contains("2001:db9::1")))
  end)
  return it("CIDR invalide → nil", function()
    local n = ipcalc.Net("not_an_ip/24")
    return assert.is_nil(n)
  end)
end)
describe("filter.conditions.to_domain", function()
  local to_domain = require("filter.conditions.to_domain")
  it("correspondance exacte", function()
    local f = (to_domain({ }))("github.com")
    local v, r = f({
      domain = "github.com"
    })
    assert.is_true(v)
    return assert.equals("Exact match", r)
  end)
  it("sous-domaine autorisé", function()
    local f = (to_domain({ }))("github.com")
    local v = f({
      domain = "api.github.com"
    })
    return assert.is_true(v)
  end)
  it("domaine différent bloqué", function()
    local f = (to_domain({ }))("github.com")
    local v = f({
      domain = "notgithub.com"
    })
    return assert.is_false(v)
  end)
  return it("domaine vide → faux", function()
    local f = (to_domain({ }))("github.com")
    local v = f({
      domain = nil
    })
    return assert.is_false(v)
  end)
end)
describe("filter.conditions.to_domains", function()
  local to_domains = require("filter.conditions.to_domains")
  it("OR logique", function()
    local f = (to_domains({ }))({
      "github.com",
      "debian.org"
    })
    assert.is_true((f({
      domain = "github.com"
    })))
    assert.is_true((f({
      domain = "packages.debian.org"
    })))
    return assert.is_false((f({
      domain = "evil.com"
    })))
  end)
  return it("liste vide → faux", function()
    local f = (to_domains({ }))({ })
    return assert.is_false((f({
      domain = "github.com"
    })))
  end)
end)
describe("filter.conditions.to_domainlist", function()
  local to_domainlist = require("filter.conditions.to_domainlist")
  local TMPDIR = "./tmp"
  local TMPBIN = TMPDIR .. "/test_filter_domainlist.bin"
  before_each(function()
    local ok, xxhash = pcall(require, "ffi_xxhash")
    if ok then
      local test_domains = {
        "github.com",
        "debian.org",
        "cloudflare.com"
      }
      local hashes
      do
        local _accum_0 = { }
        local _len_0 = 1
        for _index_0 = 1, #test_domains do
          local d = test_domains[_index_0]
          _accum_0[_len_0] = xxhash.xxh64(d)
          _len_0 = _len_0 + 1
        end
        hashes = _accum_0
      end
      table.sort(hashes, function(a, b)
        return a < b
      end)
      local arr = ffi.new("uint64_t[?]", #hashes)
      for i, h in ipairs(hashes) do
        arr[i - 1] = h
      end
      local fd = io.open(TMPBIN, "wb")
      fd:write(ffi.string(arr, #hashes * 8))
      return fd:close()
    end
  end)
  after_each(function()
    if io.open(TMPBIN, "r") then
      return os.remove(TMPBIN)
    end
  end)
  it("domaine présent (fichier .bin)", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("test_filter_domainlist")
    return assert.is_true((f({
      domain = "github.com"
    })))
  end)
  it("sous-domaine présent", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("test_filter_domainlist")
    return assert.is_true((f({
      domain = "api.github.com"
    })))
  end)
  it("domaine absent", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("test_filter_domainlist")
    return assert.is_false((f({
      domain = "evil.com"
    })))
  end)
  return it("domainlists_dir absent → faux", function()
    local cfg = { }
    local f = (to_domainlist(cfg))("nonexistent")
    return assert.is_false((f({
      domain = "github.com"
    })))
  end)
end)
describe("filter.conditions.to_domainlists", function()
  local to_domainlists = require("filter.conditions.to_domainlists")
  local TMPDIR = "./tmp"
  before_each(function()
    local ok, xxhash = pcall(require, "ffi_xxhash")
    if ok then
      for name, domains in pairs({
        test_filter_domainlist1 = {
          "github.com",
          "debian.org"
        },
        test_filter_domainlist2 = {
          "malware.bad",
          "tracker.bad"
        }
      }) do
        local hashes
        do
          local _accum_0 = { }
          local _len_0 = 1
          for _index_0 = 1, #domains do
            local d = domains[_index_0]
            _accum_0[_len_0] = xxhash.xxh64(d)
            _len_0 = _len_0 + 1
          end
          hashes = _accum_0
        end
        table.sort(hashes, function(a, b)
          return a < b
        end)
        local arr = ffi.new("uint64_t[?]", #hashes)
        for i, h in ipairs(hashes) do
          arr[i - 1] = h
        end
        local path = TMPDIR .. "/" .. name .. ".bin"
        local fd = io.open(path, "wb")
        fd:write(ffi.string(arr, #hashes * 8))
        fd:close()
      end
    end
  end)
  after_each(function()
    local _list_0 = {
      "test_filter_domainlist1",
      "test_filter_domainlist2"
    }
    for _index_0 = 1, #_list_0 do
      local name = _list_0[_index_0]
      os.remove((TMPDIR .. "/" .. name .. ".bin"))
    end
  end)
  it("OR sur plusieurs listes", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlists(cfg))({
      "test_filter_domainlist1",
      "test_filter_domainlist2"
    })
    assert.is_true((f({
      domain = "github.com"
    })))
    assert.is_true((f({
      domain = "malware.bad"
    })))
    return assert.is_false((f({
      domain = "safe.com"
    })))
  end)
  return it("liste vide → faux", function()
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlists(cfg))({ })
    return assert.is_false((f({
      domain = "github.com"
    })))
  end)
end)
describe("filter.conditions.from_mac", function()
  local from_mac = require("filter.conditions.from_mac")
  it("MAC correspondant", function()
    local f = (from_mac({ }))("aa:bb:cc:dd:ee:ff")
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
  it("MAC différent", function()
    local f = (from_mac({ }))("aa:bb:cc:dd:ee:ff")
    return assert.is_false((f({
      mac = "00:00:00:00:00:00"
    })))
  end)
  it("MAC nil → faux", function()
    local f = (from_mac({ }))("aa:bb:cc:dd:ee:ff")
    return assert.is_false((f({
      mac = nil
    })))
  end)
  return it("insensible à la casse", function()
    local f = (from_mac({ }))("AA:BB:CC:DD:EE:FF")
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
end)
describe("filter.conditions.from_macs", function()
  local from_macs = require("filter.conditions.from_macs")
  it("MAC dans liste", function()
    local f = (from_macs({ }))({
      "aa:bb:cc:dd:ee:ff",
      "11:22:33:44:55:66"
    })
    assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
    return assert.is_true((f({
      mac = "11:22:33:44:55:66"
    })))
  end)
  it("MAC absente", function()
    local f = (from_macs({ }))({
      "aa:bb:cc:dd:ee:ff",
      "11:22:33:44:55:66"
    })
    return assert.is_false((f({
      mac = "de:ad:be:ef:00:01"
    })))
  end)
  return it("liste vide → faux", function()
    local f = (from_macs({ }))({ })
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
end)
describe("filter.conditions.from_maclist", function()
  local from_maclist = require("filter.conditions.from_maclist")
  local MACLIST_CFG = {
    maclists = {
      trusted = {
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66"
      },
      printers = {
        "de:ad:be:ef:00:01"
      }
    }
  }
  it("MAC dans groupe", function()
    local f = (from_maclist(MACLIST_CFG))("trusted")
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
  it("MAC hors groupe", function()
    local f = (from_maclist(MACLIST_CFG))("trusted")
    return assert.is_false((f({
      mac = "de:ad:be:ef:00:01"
    })))
  end)
  return it("groupe inconnu → faux", function()
    local f = (from_maclist(MACLIST_CFG))("unknown")
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
end)
describe("filter.conditions.from_maclists", function()
  local from_maclists = require("filter.conditions.from_maclists")
  local MACLIST_CFG = {
    maclists = {
      trusted = {
        "aa:bb:cc:dd:ee:ff"
      },
      printers = {
        "de:ad:be:ef:00:01"
      }
    }
  }
  it("OR sur plusieurs groupes", function()
    local f = (from_maclists(MACLIST_CFG))({
      "trusted",
      "printers"
    })
    assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
    assert.is_true((f({
      mac = "de:ad:be:ef:00:01"
    })))
    return assert.is_false((f({
      mac = "00:00:00:00:00:00"
    })))
  end)
  return it("liste vide → faux", function()
    local f = (from_maclists(MACLIST_CFG))({ })
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
end)
describe("filter.conditions.from_net", function()
  local from_net = require("filter.conditions.from_net")
  it("IP dans CIDR", function()
    local f = (from_net({ }))("192.168.0.0/16")
    return assert.is_true((f({
      src_ip = "192.168.1.42"
    })))
  end)
  it("IP hors CIDR", function()
    local f = (from_net({ }))("192.168.0.0/16")
    return assert.is_false((f({
      src_ip = "10.0.0.1"
    })))
  end)
  return it("CIDR invalide → faux", function()
    local f = (from_net({ }))("invalid/24")
    return assert.is_false((f({
      src_ip = "192.168.1.1"
    })))
  end)
end)
describe("filter.conditions.from_nets", function()
  local from_nets = require("filter.conditions.from_nets")
  it("IP dans l'un des CIDRs", function()
    local f = (from_nets({ }))({
      "192.168.0.0/16",
      "10.0.0.0/8"
    })
    assert.is_true((f({
      src_ip = "192.168.1.1"
    })))
    return assert.is_true((f({
      src_ip = "10.5.0.1"
    })))
  end)
  it("IP hors de tous les CIDRs", function()
    local f = (from_nets({ }))({
      "192.168.0.0/16",
      "10.0.0.0/8"
    })
    return assert.is_false((f({
      src_ip = "8.8.8.8"
    })))
  end)
  return it("liste vide → faux", function()
    local f = (from_nets({ }))({ })
    return assert.is_false((f({
      src_ip = "192.168.1.1"
    })))
  end)
end)
describe("filter.conditions.from_netlist", function()
  local from_netlist = require("filter.conditions.from_netlist")
  local NETLIST_CFG = {
    nets = {
      lan = {
        "192.168.0.0/16",
        "10.0.0.0/8"
      },
      dmz = {
        "172.16.0.0/12"
      }
    }
  }
  it("IP dans netlist", function()
    local f = (from_netlist(NETLIST_CFG))("lan")
    assert.is_true((f({
      src_ip = "192.168.1.42"
    })))
    return assert.is_true((f({
      src_ip = "10.5.0.1"
    })))
  end)
  it("IP hors netlist", function()
    local f = (from_netlist(NETLIST_CFG))("lan")
    return assert.is_false((f({
      src_ip = "8.8.8.8"
    })))
  end)
  return it("netlist inconnue → faux", function()
    local f = (from_netlist(NETLIST_CFG))("unknown")
    return assert.is_false((f({
      src_ip = "192.168.1.1"
    })))
  end)
end)
describe("filter.conditions.from_netlists", function()
  local from_netlists = require("filter.conditions.from_netlists")
  local NETLIST_CFG = {
    nets = {
      lan = {
        "192.168.0.0/16"
      },
      dmz = {
        "172.16.0.0/12"
      }
    }
  }
  it("OR sur plusieurs netlists", function()
    local f = (from_netlists(NETLIST_CFG))({
      "lan",
      "dmz"
    })
    assert.is_true((f({
      src_ip = "192.168.0.1"
    })))
    assert.is_true((f({
      src_ip = "172.16.1.1"
    })))
    return assert.is_false((f({
      src_ip = "1.2.3.4"
    })))
  end)
  return it("liste vide → faux", function()
    local f = (from_netlists(NETLIST_CFG))({ })
    return assert.is_false((f({
      src_ip = "192.168.1.1"
    })))
  end)
end)
describe("filter.conditions.from_user", function()
  local from_user = require("filter.conditions.from_user")
  local SESSION_FILE = "./tmp/test_from_user.lua"
  local USER_CFG = {
    auth = {
      sessions_file = SESSION_FILE
    }
  }
  local FAR_FUTURE = os.time() + 86400 * 365
  before_each(function()
    local sessions_mod = require("auth.sessions")
    local write_session_file
    write_session_file = function(entries)
      local fh = io.open(SESSION_FILE, "w")
      fh:write("return {\n")
      for _index_0 = 1, #entries do
        local entry = entries[_index_0]
        local ips_str = ""
        if entry[4] or entry[5] then
          ips_str = ", ips = { " .. (entry[4] and ("ipv4 = \"" .. entry[4] .. "\"") or "") .. (entry[5] and (", ipv6 = \"" .. entry[5] .. "\"") or "") .. " }"
        end
        fh:write(string.format('  ["%s"] = { user = "%s", expires = %d%s },\n', entry[1], entry[2], entry[3], ips_str))
      end
      fh:write("}\n")
      return fh:close()
    end
    if io.open(SESSION_FILE, "r") then
      os.remove(SESSION_FILE)
    end
    write_session_file({
      {
        "aa:bb:cc:dd:ee:ff",
        "alice",
        FAR_FUTURE
      }
    })
    return sessions_mod.reset_cache()
  end)
  after_each(function()
    if io.open(SESSION_FILE, "r") then
      return os.remove(SESSION_FILE)
    end
  end)
  it("session active bon user", function()
    local f = (from_user(USER_CFG))("alice")
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  it("session active mauvais user", function()
    local f = (from_user(USER_CFG))("bob")
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  return it("session expirée", function()
    local sessions_mod = require("auth.sessions")
    local write_session_file
    write_session_file = function(entries)
      local fh = io.open(SESSION_FILE, "w")
      fh:write("return {\n")
      for _index_0 = 1, #entries do
        local entry = entries[_index_0]
        fh:write(string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3]))
      end
      fh:write("}\n")
      return fh:close()
    end
    if io.open(SESSION_FILE, "r") then
      os.remove(SESSION_FILE)
    end
    write_session_file({
      {
        "aa:bb:cc:dd:ee:ff",
        "alice",
        1
      }
    })
    sessions_mod.reset_cache()
    local f = (from_user(USER_CFG))("alice")
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
end)
describe("filter.conditions.from_users", function()
  local from_users = require("filter.conditions.from_users")
  local SESSION_FILE = "./tmp/test_from_users.lua"
  local USER_CFG = {
    auth = {
      sessions_file = SESSION_FILE
    }
  }
  local FAR_FUTURE = os.time() + 86400 * 365
  before_each(function()
    local sessions_mod = require("auth.sessions")
    local write_session_file
    write_session_file = function(entries)
      local fh = io.open(SESSION_FILE, "w")
      fh:write("return {\n")
      for _index_0 = 1, #entries do
        local entry = entries[_index_0]
        fh:write(string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3]))
      end
      fh:write("}\n")
      return fh:close()
    end
    if io.open(SESSION_FILE, "r") then
      os.remove(SESSION_FILE)
    end
    write_session_file({
      {
        "aa:bb:cc:dd:ee:ff",
        "alice",
        FAR_FUTURE
      }
    })
    return sessions_mod.reset_cache()
  end)
  after_each(function()
    if io.open(SESSION_FILE, "r") then
      return os.remove(SESSION_FILE)
    end
  end)
  it("premier utilisateur match", function()
    local f = (from_users(USER_CFG))({
      "alice",
      "bob"
    })
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  it("aucun match", function()
    local f = (from_users(USER_CFG))({
      "bob",
      "charlie"
    })
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  return it("liste vide → faux", function()
    local f = (from_users(USER_CFG))({ })
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
end)
describe("filter.conditions.from_userlist", function()
  local from_userlist = require("filter.conditions.from_userlist")
  local SESSION_FILE = "./tmp/test_from_userlist.lua"
  local USER_CFG = {
    auth = {
      sessions_file = SESSION_FILE
    },
    userlists = {
      admins = {
        "alice",
        "bob"
      },
      guests = {
        "charlie"
      }
    }
  }
  local FAR_FUTURE = os.time() + 86400 * 365
  before_each(function()
    local sessions_mod = require("auth.sessions")
    local write_session_file
    write_session_file = function(entries)
      local fh = io.open(SESSION_FILE, "w")
      fh:write("return {\n")
      for _index_0 = 1, #entries do
        local entry = entries[_index_0]
        fh:write(string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3]))
      end
      fh:write("}\n")
      return fh:close()
    end
    if io.open(SESSION_FILE, "r") then
      os.remove(SESSION_FILE)
    end
    write_session_file({
      {
        "aa:bb:cc:dd:ee:ff",
        "alice",
        FAR_FUTURE
      }
    })
    return sessions_mod.reset_cache()
  end)
  after_each(function()
    if io.open(SESSION_FILE, "r") then
      return os.remove(SESSION_FILE)
    end
  end)
  it("utilisateur dans groupe", function()
    local f = (from_userlist(USER_CFG))("admins")
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  it("utilisateur hors groupe", function()
    local f = (from_userlist(USER_CFG))("guests")
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  return it("groupe inconnu → faux", function()
    local f = (from_userlist(USER_CFG))("unknown")
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
end)
describe("filter.conditions.from_userlists", function()
  local from_userlists = require("filter.conditions.from_userlists")
  local SESSION_FILE = "./tmp/test_from_userlists.lua"
  local USER_CFG = {
    auth = {
      sessions_file = SESSION_FILE
    },
    userlists = {
      admins = {
        "alice"
      },
      guests = {
        "charlie"
      }
    }
  }
  local FAR_FUTURE = os.time() + 86400 * 365
  before_each(function()
    local sessions_mod = require("auth.sessions")
    local write_session_file
    write_session_file = function(entries)
      local fh = io.open(SESSION_FILE, "w")
      fh:write("return {\n")
      for _index_0 = 1, #entries do
        local entry = entries[_index_0]
        fh:write(string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3]))
      end
      fh:write("}\n")
      return fh:close()
    end
    if io.open(SESSION_FILE, "r") then
      os.remove(SESSION_FILE)
    end
    write_session_file({
      {
        "aa:bb:cc:dd:ee:ff",
        "alice",
        FAR_FUTURE
      }
    })
    return sessions_mod.reset_cache()
  end)
  after_each(function()
    if io.open(SESSION_FILE, "r") then
      return os.remove(SESSION_FILE)
    end
  end)
  it("premier groupe match", function()
    local f = (from_userlists(USER_CFG))({
      "admins",
      "guests"
    })
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  it("deuxième groupe match", function()
    local sessions_mod = require("auth.sessions")
    local write_session_file
    write_session_file = function(entries)
      local fh = io.open(SESSION_FILE, "w")
      fh:write("return {\n")
      for _index_0 = 1, #entries do
        local entry = entries[_index_0]
        fh:write(string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3]))
      end
      fh:write("}\n")
      return fh:close()
    end
    if io.open(SESSION_FILE, "r") then
      os.remove(SESSION_FILE)
    end
    write_session_file({
      {
        "aa:bb:cc:dd:ee:ff",
        "charlie",
        FAR_FUTURE
      }
    })
    sessions_mod.reset_cache()
    local f = (from_userlists(USER_CFG))({
      "admins",
      "guests"
    })
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  return it("liste vide → faux", function()
    local f = (from_userlists(USER_CFG))({ })
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
end)
describe("filter.conditions.stolen_computer", function()
  local stolen_computer = require("filter.conditions.stolen_computer")
  it("MAC blacklistée", function()
    local f = (stolen_computer({ }))({
      "de:ad:be:ef:00:01"
    })
    local v, r = f({
      mac = "de:ad:be:ef:00:01"
    })
    assert.is_true(v)
    return assert.equals("Stolen computer: de:ad:be:ef:00:01", r)
  end)
  it("MAC non blacklistée", function()
    local f = (stolen_computer({ }))({
      "de:ad:be:ef:00:01"
    })
    local v, r = f({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    return assert.is_false(v)
  end)
  return it("liste vide → faux", function()
    local f = (stolen_computer({ }))({ })
    return assert.is_false((f({
      mac = "de:ad:be:ef:00:01"
    })))
  end)
end)
describe("filter.conditions.in_time", function()
  local in_time = require("filter.conditions.in_time")
  it("heure dans plage", function()
    local cfg = {
      times = {
        business = {
          "09:00",
          "18:00"
        }
      }
    }
    local f = (in_time(cfg))("business")
    local ts = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 15,
      min = 0,
      sec = 0
    })
    local v, r = f({
      ts = ts
    })
    return assert.is_true(v)
  end)
  it("heure hors plage", function()
    local cfg = {
      times = {
        business = {
          "09:00",
          "18:00"
        }
      }
    }
    local f = (in_time(cfg))("business")
    local ts = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 20,
      min = 0,
      sec = 0
    })
    local v, r = f({
      ts = ts
    })
    return assert.is_false(v)
  end)
  return it("fenêtre inconnue → faux", function()
    local cfg = {
      times = { }
    }
    local f = (in_time(cfg))("unknown")
    local v, r = f({
      ts = os.time()
    })
    assert.is_false(v)
    return assert.equals("Time window 'unknown' not defined", r)
  end)
end)
describe("filter.conditions.in_times", function()
  local in_times = require("filter.conditions.in_times")
  it("OR sur plusieurs fenêtres", function()
    local cfg = {
      times = {
        morning = {
          "06:00",
          "12:00"
        },
        evening = {
          "18:00",
          "22:00"
        }
      }
    }
    local f = (in_times(cfg))({
      "morning",
      "evening"
    })
    local ts1 = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 8,
      min = 0,
      sec = 0
    })
    assert.is_true((f({
      ts = ts1
    })))
    local ts2 = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 20,
      min = 0,
      sec = 0
    })
    assert.is_true((f({
      ts = ts2
    })))
    local ts3 = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 15,
      min = 0,
      sec = 0
    })
    return assert.is_false((f({
      ts = ts3
    })))
  end)
  return it("liste vide → faux", function()
    local cfg = {
      times = {
        business = {
          "09:00",
          "18:00"
        }
      }
    }
    local f = (in_times(cfg))({ })
    return assert.is_false((f({
      ts = os.time()
    })))
  end)
end)
describe("filter.rule", function()
  local m_rule = require("filter.rule")
  it("compile_rules + decide : règle allow", function()
    local cfg = {
      rules = {
        {
          description = "Autoriser local",
          conditions = {
            {
              to_domain = "local"
            }
          },
          actions = {
            "allow"
          }
        }
      }
    }
    local rules = m_rule.compile_rules(cfg)
    local v, msg, desc = m_rule.decide(rules, {
      domain = "test.local",
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "192.168.1.1",
      ts = os.time()
    })
    assert.is_true(v)
    return assert.equals("Autoriser local", desc)
  end)
  it("compile_rules + decide : règle deny", function()
    local cfg = {
      rules = {
        {
          description = "Bloquer evil",
          conditions = {
            {
              to_domain = "evil.com"
            }
          },
          actions = {
            "deny"
          }
        }
      }
    }
    local rules = m_rule.compile_rules(cfg)
    local v, msg, desc = m_rule.decide(rules, {
      domain = "evil.com",
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "192.168.1.1",
      ts = os.time()
    })
    assert.is_false(v)
    return assert.equals("Bloquer evil", desc)
  end)
  return it("compile_rules + decide : règles multiples", function()
    local cfg = {
      rules = {
        {
          description = "Autoriser LAN",
          conditions = {
            {
              from_net = "192.168.0.0/16"
            }
          },
          actions = {
            "allow"
          }
        },
        {
          description = "Bloquer tout",
          conditions = { },
          actions = {
            "deny"
          }
        }
      }
    }
    local rules = m_rule.compile_rules(cfg)
    local v1, _, desc1 = m_rule.decide(rules, {
      domain = "example.com",
      src_ip = "192.168.1.1",
      ts = os.time()
    })
    assert.is_true(v1)
    assert.equals("Autoriser LAN", desc1)
    local v2, desc2
    v2, _, desc2 = m_rule.decide(rules, {
      domain = "example.com",
      src_ip = "8.8.8.8",
      ts = os.time()
    })
    assert.is_false(v2)
    return assert.equals("Bloquer tout", desc2)
  end)
end)
describe("filter.actions.dnsonly", function()
  local dnsonly_action = require("filter.actions.dnsonly")
  it("retourne \"dnsonly\"", function()
    local factory = dnsonly_action({ })
    local rule_fn = factory({
      description = "test-dnsonly"
    })
    local v, msg = rule_fn({
      domain = "example.com",
      src_ip = "1.2.3.4",
      mac = "aa:bb:cc:dd:ee:ff",
      ts = os.time()
    })
    assert.equals("dnsonly", v)
    assert.is_not_nil(msg)
    return assert(msg:find("DNS only", 1, true))
  end)
  return it("verdict distinct de true/false", function()
    local factory = dnsonly_action({ })
    local rule_fn = factory({
      description = "test"
    })
    local v, _ = rule_fn({ })
    assert.equals("string", type(v))
    assert.is_not_true(v)
    return assert.is_not_false(v)
  end)
end)
describe("filter.lib.parse_domains", function()
  local parse, parse_simple, parse_hosts, parse_adblock, is_valid
  do
    local _obj_0 = require("filter.lib.parse_domains")
    parse, parse_simple, parse_hosts, parse_adblock, is_valid = _obj_0.parse, _obj_0.parse_simple, _obj_0.parse_hosts, _obj_0.parse_adblock, _obj_0.is_valid
  end
  local has
  has = function(tbl, val)
    for _index_0 = 1, #tbl do
      local v = tbl[_index_0]
      if v == val then
        return true
      end
    end
    return false
  end
  it("parse_simple", function()
    local text = [[# Commentaire
example.com
ads.example.com
DOUBLECLICK.NET
# autre commentaire
]]
    local result = parse_simple(text)
    assert.equals(3, #result)
    assert.is_true((has(result, "example.com")))
    assert.is_true((has(result, "ads.example.com")))
    return assert.is_true((has(result, "doubleclick.net")))
  end)
  it("parse_hosts", function()
    local text = [[127.0.0.1 localhost
0.0.0.0 ads.example.com
0.0.0.0 0.0.0.0
127.0.0.1 tracking.example.org
0.0.0.0 DOUBLECLICK.NET
]]
    local result = parse_hosts(text)
    assert.equals(3, #result)
    assert.is_true((has(result, "ads.example.com")))
    assert.is_true((has(result, "tracking.example.org")))
    return assert.is_true((has(result, "doubleclick.net")))
  end)
  it("parse_adblock", function()
    local text = [[! Commentaire adblock
||ads.example.com^
||tracker.example.org^$third-party
@@||whitelist.example.com^
||DOUBLECLICK.NET^
]]
    local result = parse_adblock(text)
    assert.equals(3, #result)
    assert.is_true((has(result, "ads.example.com")))
    assert.is_true((has(result, "tracker.example.org")))
    return assert.is_true((has(result, "doubleclick.net")))
  end)
  it("parse dispatch", function()
    local result1 = parse("simple", "example.com\n# comment\n")
    assert.equals(1, #result1)
    assert.equals("example.com", result1[1])
    local result2 = parse("unknown", "example.com\n")
    return assert.equals(1, #result2)
  end)
  return it("is_valid", function()
    assert.is_true((is_valid("example.com")))
    assert.is_true((is_valid("sub.example.com")))
    assert.is_false((is_valid("")))
    assert.is_false((is_valid("1.2.3.4")))
    assert.is_false((is_valid("::1")))
    assert.is_false((is_valid("localhost")))
    return assert.is_false((is_valid((string.rep("a", 254)))))
  end)
end)
return describe("filter.lib.load_config", function()
  local load_config
  load_config = require("filter.lib.load_config").load_config
  local TMP_YAML = "./tmp/test_filter_config.yml"
  before_each(function()
    if io.open(TMP_YAML, "r") then
      return os.remove(TMP_YAML)
    end
  end)
  after_each(function()
    if io.open(TMP_YAML, "r") then
      return os.remove(TMP_YAML)
    end
  end)
  it("chargement valide", function()
    local yaml = [[domainlists_dir: /etc/custos/lists
nets:
  lan:
  - 192.168.0.0/16
times:
  business: ["8:00", "18:00"]
rules:
- description: Test rule
  actions: [allow]
  conditions:
  - to_domain: example.com
]]
    local fd = io.open(TMP_YAML, "w")
    fd:write(yaml)
    fd:close()
    local cfg, err = load_config(TMP_YAML)
    assert.is_not_nil(cfg)
    assert.is_nil(err)
    assert.equals("/etc/custos/lists", cfg.domainlists_dir)
    assert.equals("192.168.0.0/16", cfg.nets.lan[1])
    assert.equals("8:00", cfg.times.business[1])
    return assert.equals(1, #cfg.rules)
  end)
  it("fichier absent → nil + erreur", function()
    local cfg, err = load_config("/nonexistent.yml")
    assert.is_nil(cfg)
    assert.is_not_nil(err)
    return assert.is_string(err)
  end)
  it("YAML invalide → nil + erreur", function()
    local fd = io.open(TMP_YAML, "w")
    fd:write("invalid: yaml: [")
    fd:close()
    local cfg, err = load_config(TMP_YAML)
    assert.is_nil(cfg)
    return assert.is_not_nil(err)
  end)
  it("sections manquantes → tables vides", function()
    local yaml = "rules: []\n"
    local fd = io.open(TMP_YAML, "w")
    fd:write(yaml)
    fd:close()
    local cfg, _ = load_config(TMP_YAML)
    assert.equals("table", type(cfg.nets))
    assert.equals("table", type(cfg.times))
    return assert.equals("table", type(cfg.sources))
  end)
  return it("auth defaults", function()
    local yaml = "rules: []\n"
    local fd = io.open(TMP_YAML, "w")
    fd:write(yaml)
    fd:close()
    local cfg, _ = load_config(TMP_YAML)
    assert.equals(33443, cfg.auth.port)
    assert.equals(33080, cfg.auth.captive_port)
    assert.equals("::", cfg.auth.host)
    assert.equals(30, cfg.auth.heartbeat_interval)
    return assert.equals(120, cfg.auth.idle_timeout)
  end)
end)
