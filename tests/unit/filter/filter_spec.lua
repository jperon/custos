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
  it("CIDR invalide → nil", function()
    local n = ipcalc.Net("not_an_ip/24")
    return assert.is_nil(n)
  end)
  it("contains avec IP invalide → false", function()
    local n = ipcalc.Net("192.168.0.0/16")
    return assert.is_false((n:contains("not_an_ip")))
  end)
  it("contains avec IP vide → false", function()
    local n = ipcalc.Net("192.168.0.0/16")
    return assert.is_false((n:contains("")))
  end)
  return it("/31 boundary (dernier bit)", function()
    local n = ipcalc.Net("10.0.0.2/31")
    assert.is_true((n:contains("10.0.0.2")))
    assert.is_true((n:contains("10.0.0.3")))
    return assert.is_false((n:contains("10.0.0.4")))
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
  it("domaine vide → faux", function()
    local f = (to_domain({ }))("github.com")
    local v = f({
      domain = nil
    })
    return assert.is_false(v)
  end)
  it("_any → true si domaine présent", function()
    local f = (to_domain({ }))("_any")
    local v = f({
      domain = "github.com"
    })
    return assert.is_true(v)
  end)
  it("_any → false si domaine absent", function()
    local f = (to_domain({ }))("_any")
    local v = f({
      domain = nil
    })
    return assert.is_false(v)
  end)
  it("_none → true si domaine absent", function()
    local f = (to_domain({ }))("_none")
    local v = f({
      domain = nil
    })
    return assert.is_true(v)
  end)
  return it("_none → false si domaine présent", function()
    local f = (to_domain({ }))("_none")
    local v = f({
      domain = "github.com"
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
  it("domainlists_dir absent → faux", function()
    local cfg = { }
    local f = (to_domainlist(cfg))("nonexistent")
    return assert.is_false((f({
      domain = "github.com"
    })))
  end)
  it("fichier .bin absent → faux (load échoue)", function()
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("does_not_exist_xyz")
    local v, r = f({
      domain = "github.com"
    })
    assert.is_false(v)
    return assert.is_not_nil(r)
  end)
  it("fichier .bin vide (0 octets) → faux", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local empty_bin = TMPDIR .. "/empty_domainlist.bin"
    local fd = io.open(empty_bin, "wb")
    fd:close()
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("empty_domainlist")
    local v, r = f({
      domain = "github.com"
    })
    assert.is_false(v)
    return os.remove(empty_bin)
  end)
  it("nom de liste invalide (commence par /) → faux", function()
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("/etc/passwd")
    local v, r = f({
      domain = "github.com"
    })
    assert.is_false(v)
    return assert.is_not_nil((r:find("invalide", 1, true)))
  end)
  it("domaine absent dans req → faux", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("test_filter_domainlist")
    local v, r = f({
      domain = nil
    })
    assert.is_false(v)
    return assert.is_not_nil((r:find("Missing", 1, true)))
  end)
  it("fichier texte .domains → domaines chargés et matchés", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local domains_path = TMPDIR .. "/test_text_domainlist.domains"
    local fd = io.open(domains_path, "w")
    fd:write("# commentaire\ngithub.com\ndebian.org\n")
    fd:close()
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("test_text_domainlist")
    assert.is_true((f({
      domain = "github.com"
    })))
    assert.is_true((f({
      domain = "api.debian.org"
    })))
    assert.is_false((f({
      domain = "evil.com"
    })))
    return os.remove(domains_path)
  end)
  return it("fichier .domains vide → faux", function()
    local ok = pcall(require, "ffi_xxhash")
    if not (ok) then
      pending("ffi_xxhash non disponible")
    end
    local empty_domains = TMPDIR .. "/empty_text_domainlist.domains"
    local fd = io.open(empty_domains, "w")
    fd:write("")
    fd:close()
    local cfg = {
      domainlists_dir = TMPDIR
    }
    local f = (to_domainlist(cfg))("empty_text_domainlist")
    local v, r = f({
      domain = "github.com"
    })
    assert.is_false(v)
    return os.remove(empty_domains)
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
  it("insensible à la casse", function()
    local f = (from_mac({ }))("AA:BB:CC:DD:EE:FF")
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
  it("_any → true si MAC présente", function()
    local f = (from_mac({ }))("_any")
    return assert.is_true((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
  it("_any → false si MAC absente", function()
    local f = (from_mac({ }))("_any")
    return assert.is_false((f({
      mac = nil
    })))
  end)
  it("_none → true si MAC absente", function()
    local f = (from_mac({ }))("_none")
    return assert.is_true((f({
      mac = nil
    })))
  end)
  return it("_none → false si MAC présente", function()
    local f = (from_mac({ }))("_none")
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })))
  end)
end)
describe("filter.conditions.from_macs (auto-généré)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_macs")
  it("MAC dans liste", function()
    local cond = factory({ })({
      "aa:bb:cc:dd:ee:ff",
      "11:22:33:44:55:66"
    })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    assert.is_true(ok)
    ok, _ = cond.eval({
      mac = "11:22:33:44:55:66"
    })
    return assert.is_true(ok)
  end)
  it("MAC absente", function()
    local cond = factory({ })({
      "aa:bb:cc:dd:ee:ff",
      "11:22:33:44:55:66"
    })
    local ok, _ = cond.eval({
      mac = "de:ad:be:ef:00:01"
    })
    return assert.is_false(ok)
  end)
  return it("liste vide → faux", function()
    local cond = factory({ })({ })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    return assert.is_false(ok)
  end)
end)
describe("filter.conditions.from_mac_list (auto-généré, fichier)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_mac_list")
  local LIST_DIR = "/tmp/custos_test_mac_list"
  local CFG = {
    lists_dir = LIST_DIR
  }
  before_each(function()
    os.execute("mkdir -p " .. tostring(LIST_DIR) .. "/mac")
    local fh = io.open(tostring(LIST_DIR) .. "/mac/trusted.txt", "w")
    fh:write("aa:bb:cc:dd:ee:ff\n11:22:33:44:55:66\n# commentaire\n\n")
    return fh:close()
  end)
  after_each(function()
    return os.execute("rm -rf " .. tostring(LIST_DIR))
  end)
  it("MAC dans fichier liste", function()
    local cond = factory(CFG)("trusted")
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    return assert.is_true(ok)
  end)
  it("MAC absente du fichier", function()
    local cond = factory(CFG)("trusted")
    local ok, _ = cond.eval({
      mac = "de:ad:be:ef:00:01"
    })
    return assert.is_false(ok)
  end)
  return it("liste inconnue → faux", function()
    local cond = factory(CFG)("unknown")
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    return assert.is_false(ok)
  end)
end)
describe("filter.conditions.from_mac_lists (auto-généré, fichiers)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_mac_lists")
  local LIST_DIR = "/tmp/custos_test_mac_lists"
  local CFG = {
    lists_dir = LIST_DIR
  }
  before_each(function()
    os.execute("mkdir -p " .. tostring(LIST_DIR) .. "/mac")
    local fh = io.open(tostring(LIST_DIR) .. "/mac/trusted.txt", "w")
    fh:write("aa:bb:cc:dd:ee:ff\n")
    fh:close()
    fh = io.open(tostring(LIST_DIR) .. "/mac/printers.txt", "w")
    fh:write("de:ad:be:ef:00:01\n")
    return fh:close()
  end)
  after_each(function()
    return os.execute("rm -rf " .. tostring(LIST_DIR))
  end)
  it("OR sur plusieurs fichiers listes", function()
    local cond = factory(CFG)({
      "trusted",
      "printers"
    })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    assert.is_true(ok)
    ok, _ = cond.eval({
      mac = "de:ad:be:ef:00:01"
    })
    assert.is_true(ok)
    ok, _ = cond.eval({
      mac = "00:00:00:00:00:00"
    })
    return assert.is_false(ok)
  end)
  return it("liste vide → faux", function()
    local cond = factory(CFG)({ })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff"
    })
    return assert.is_false(ok)
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
  it("CIDR invalide → faux", function()
    local f = (from_net({ }))("invalid/24")
    return assert.is_false((f({
      src_ip = "192.168.1.1"
    })))
  end)
  it("_any → true si src_ip présente", function()
    local f = (from_net({ }))("_any")
    local v = f({
      src_ip = "10.0.0.1"
    })
    return assert.is_true(v)
  end)
  it("_any → false si src_ip absente", function()
    local f = (from_net({ }))("_any")
    local v = f({
      src_ip = nil
    })
    return assert.is_false(v)
  end)
  it("_none → true si src_ip absente", function()
    local f = (from_net({ }))("_none")
    local v = f({
      src_ip = nil
    })
    return assert.is_true(v)
  end)
  it("_none → false si src_ip présente", function()
    local f = (from_net({ }))("_none")
    local v = f({
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  return it("src_ip absente sur CIDR valide → faux", function()
    local f = (from_net({ }))("192.168.0.0/16")
    local v = f({
      src_ip = nil
    })
    return assert.is_false(v)
  end)
end)
describe("filter.conditions.from_nets (auto-généré)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_nets")
  it("IP dans l'un des CIDRs", function()
    local cond = factory({ })({
      "192.168.0.0/16",
      "10.0.0.0/8"
    })
    local ok, _ = cond.eval({
      src_ip = "192.168.1.1"
    })
    assert.is_true(ok)
    ok, _ = cond.eval({
      src_ip = "10.5.0.1"
    })
    return assert.is_true(ok)
  end)
  it("IP hors de tous les CIDRs", function()
    local cond = factory({ })({
      "192.168.0.0/16",
      "10.0.0.0/8"
    })
    local ok, _ = cond.eval({
      src_ip = "8.8.8.8"
    })
    return assert.is_false(ok)
  end)
  return it("liste vide → faux", function()
    local cond = factory({ })({ })
    local ok, _ = cond.eval({
      src_ip = "192.168.1.1"
    })
    return assert.is_false(ok)
  end)
end)
describe("filter.conditions.from_net_list (auto-généré, fichier)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_net_list")
  local LIST_DIR = "/tmp/custos_test_net_list"
  local CFG = {
    lists_dir = LIST_DIR
  }
  before_each(function()
    os.execute("mkdir -p " .. tostring(LIST_DIR) .. "/net")
    local fh = io.open(tostring(LIST_DIR) .. "/net/lan.txt", "w")
    fh:write("192.168.0.0/16\n10.0.0.0/8\n# commentaire\n\n")
    return fh:close()
  end)
  after_each(function()
    return os.execute("rm -rf " .. tostring(LIST_DIR))
  end)
  it("IP dans fichier netlist", function()
    local cond = factory(CFG)("lan")
    local ok, _ = cond.eval({
      src_ip = "192.168.1.42"
    })
    assert.is_true(ok)
    ok, _ = cond.eval({
      src_ip = "10.5.0.1"
    })
    return assert.is_true(ok)
  end)
  it("IP hors fichier netlist", function()
    local cond = factory(CFG)("lan")
    local ok, _ = cond.eval({
      src_ip = "8.8.8.8"
    })
    return assert.is_false(ok)
  end)
  return it("liste inconnue → faux", function()
    local cond = factory(CFG)("unknown")
    local ok, _ = cond.eval({
      src_ip = "192.168.1.1"
    })
    return assert.is_false(ok)
  end)
end)
describe("filter.conditions.from_net_lists (auto-généré, fichiers)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_net_lists")
  local LIST_DIR = "/tmp/custos_test_net_lists"
  local CFG = {
    lists_dir = LIST_DIR
  }
  before_each(function()
    os.execute("mkdir -p " .. tostring(LIST_DIR) .. "/net")
    local fh = io.open(tostring(LIST_DIR) .. "/net/lan.txt", "w")
    fh:write("192.168.0.0/16\n")
    fh:close()
    fh = io.open(tostring(LIST_DIR) .. "/net/dmz.txt", "w")
    fh:write("172.16.0.0/12\n")
    return fh:close()
  end)
  after_each(function()
    return os.execute("rm -rf " .. tostring(LIST_DIR))
  end)
  it("OR sur plusieurs fichiers netlists", function()
    local cond = factory(CFG)({
      "lan",
      "dmz"
    })
    local ok, _ = cond.eval({
      src_ip = "192.168.0.1"
    })
    assert.is_true(ok)
    ok, _ = cond.eval({
      src_ip = "172.16.1.1"
    })
    assert.is_true(ok)
    ok, _ = cond.eval({
      src_ip = "1.2.3.4"
    })
    return assert.is_false(ok)
  end)
  return it("liste vide → faux", function()
    local cond = factory(CFG)({ })
    local ok, _ = cond.eval({
      src_ip = "192.168.1.1"
    })
    return assert.is_false(ok)
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
    package.loaded["auth.sessions"] = nil
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
    sessions_mod.reset_cache()
    package.loaded["filter.conditions.from_user"] = nil
    from_user = require("filter.conditions.from_user")
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
  it("session expirée", function()
    package.loaded["auth.sessions"] = nil
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
        os.time() - 1
      }
    })
    sessions_mod.reset_cache()
    local f = (from_user(USER_CFG))("alice")
    return assert.is_false((f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })))
  end)
  it("_any → true si session active", function()
    local f = (from_user(USER_CFG))("_any")
    local v = f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_true(v)
  end)
  it("_any → false si pas de session", function()
    local f = (from_user(USER_CFG))("_any")
    local v = f({
      mac = "ff:ff:ff:ff:ff:ff",
      src_ip = "10.0.0.2"
    })
    return assert.is_false(v)
  end)
  it("_none → true si pas de session", function()
    local f = (from_user(USER_CFG))("_none")
    local v = f({
      mac = "ff:ff:ff:ff:ff:ff",
      src_ip = "10.0.0.2"
    })
    return assert.is_true(v)
  end)
  it("_none → false si session active", function()
    local f = (from_user(USER_CFG))("_none")
    local v = f({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_false(v)
  end)
  it("mac=nil, src_ip=nil → safe_get_mac(nil) → retourne nil", function()
    package.loaded["filter.conditions.from_user"] = nil
    local cfg_stub = package.loaded["config"]
    cfg_stub.MAC_LEARNER_QUERY_SOCK = cfg_stub.MAC_LEARNER_QUERY_SOCK or "/nonexistent/custos/mac_query.sock"
    local fu = require("filter.conditions.from_user")
    local f = (fu(USER_CFG))("_none")
    local v = f({
      mac = nil,
      src_ip = nil
    })
    return assert.is_true(v)
  end)
  it("mac=nil, src_ip présent + learner stub → safe_get_mac retourne nil", function()
    package.loaded["filter.conditions.from_user"] = nil
    package.loaded["mac_learner_ipc"] = nil
    local old_preload = package.preload["mac_learner_ipc"]
    package.preload["mac_learner_ipc"] = function()
      return {
        get_mac = function()
          return nil
        end
      }
    end
    local fu = require("filter.conditions.from_user")
    local f = (fu(USER_CFG))("_none")
    local v = f({
      mac = nil,
      src_ip = "10.0.0.1"
    })
    assert.is_true(v)
    package.preload["mac_learner_ipc"] = old_preload
    package.loaded["mac_learner_ipc"] = nil
    package.loaded["filter.conditions.from_user"] = nil
  end)
  it("mac=nil → safe_get_mac: chargement mac_learner_ipc échoue → nil", function()
    package.loaded["filter.conditions.from_user"] = nil
    package.loaded["mac_learner_ipc"] = nil
    local old_preload = package.preload["mac_learner_ipc"]
    package.preload["mac_learner_ipc"] = function()
      return error("mac_learner_ipc non disponible (test)")
    end
    local fu = require("filter.conditions.from_user")
    local f = (fu(USER_CFG))("_none")
    local v = f({
      mac = nil,
      src_ip = "10.0.0.1"
    })
    assert.is_true(v)
    package.preload["mac_learner_ipc"] = old_preload
    package.loaded["mac_learner_ipc"] = nil
  end)
  return it("mac=nil → safe_get_mac: _get_mac absent (mod sans get_mac) → nil", function()
    package.loaded["filter.conditions.from_user"] = nil
    package.loaded["mac_learner_ipc"] = nil
    local old_preload = package.preload["mac_learner_ipc"]
    package.preload["mac_learner_ipc"] = function()
      return { }
    end
    local fu = require("filter.conditions.from_user")
    local f = (fu(USER_CFG))("_none")
    local v = f({
      mac = nil,
      src_ip = "10.0.0.1"
    })
    assert.is_true(v)
    local v2 = f({
      mac = nil,
      src_ip = "10.0.0.2"
    })
    assert.is_true(v2)
    package.preload["mac_learner_ipc"] = old_preload
    package.loaded["mac_learner_ipc"] = nil
    package.loaded["filter.conditions.from_user"] = nil
  end)
end)
describe("filter.conditions.from_users (auto-généré)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_users")
  local SESSION_FILE = "./tmp/test_from_users.lua"
  local USER_CFG = {
    auth = {
      sessions_file = SESSION_FILE
    }
  }
  local FAR_FUTURE = os.time() + 86400 * 365
  before_each(function()
    package.loaded["auth.sessions"] = nil
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
    local cond = factory(USER_CFG)({
      "alice",
      "bob"
    })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_true(ok)
  end)
  it("aucun match", function()
    local cond = factory(USER_CFG)({
      "bob",
      "charlie"
    })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_false(ok)
  end)
  return it("liste vide → faux", function()
    local cond = factory(USER_CFG)({ })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_false(ok)
  end)
end)
describe("filter.conditions.from_user_list (auto-généré, fichier)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_user_list")
  local LIST_DIR = "/tmp/custos_test_user_list"
  local SESSION_FILE = "./tmp/test_from_user_list.lua"
  local USER_CFG = {
    lists_dir = LIST_DIR,
    auth = {
      sessions_file = SESSION_FILE
    }
  }
  local FAR_FUTURE = os.time() + 86400 * 365
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
  before_each(function()
    package.loaded["auth.sessions"] = nil
    local sessions_mod = require("auth.sessions")
    os.execute("mkdir -p " .. tostring(LIST_DIR) .. "/user")
    local fh = io.open(tostring(LIST_DIR) .. "/user/admins.txt", "w")
    fh:write("alice\nbob\n# commentaire\n\n")
    fh:close()
    fh = io.open(tostring(LIST_DIR) .. "/user/guests.txt", "w")
    fh:write("charlie\n")
    fh:close()
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
    os.execute("rm -rf " .. tostring(LIST_DIR))
    if io.open(SESSION_FILE, "r") then
      return os.remove(SESSION_FILE)
    end
  end)
  it("utilisateur dans fichier liste", function()
    local cond = factory(USER_CFG)("admins")
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_true(ok)
  end)
  it("utilisateur hors fichier liste", function()
    local cond = factory(USER_CFG)("guests")
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_false(ok)
  end)
  return it("liste inconnue → faux", function()
    local cond = factory(USER_CFG)("unknown")
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_false(ok)
  end)
end)
describe("filter.conditions.from_user_lists (auto-généré, fichiers)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("from_user_lists")
  local LIST_DIR = "/tmp/custos_test_user_lists"
  local SESSION_FILE = "./tmp/test_from_user_lists.lua"
  local USER_CFG = {
    lists_dir = LIST_DIR,
    auth = {
      sessions_file = SESSION_FILE
    }
  }
  local FAR_FUTURE = os.time() + 86400 * 365
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
  before_each(function()
    package.loaded["auth.sessions"] = nil
    local sessions_mod = require("auth.sessions")
    os.execute("mkdir -p " .. tostring(LIST_DIR) .. "/user")
    local fh = io.open(tostring(LIST_DIR) .. "/user/admins.txt", "w")
    fh:write("alice\n")
    fh:close()
    fh = io.open(tostring(LIST_DIR) .. "/user/guests.txt", "w")
    fh:write("charlie\n")
    fh:close()
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
    os.execute("rm -rf " .. tostring(LIST_DIR))
    if io.open(SESSION_FILE, "r") then
      return os.remove(SESSION_FILE)
    end
  end)
  it("premier fichier liste match", function()
    local cond = factory(USER_CFG)({
      "admins",
      "guests"
    })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_true(ok)
  end)
  it("deuxième fichier liste match", function()
    package.loaded["auth.sessions"] = nil
    local sessions_mod = require("auth.sessions")
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
    local cond = factory(USER_CFG)({
      "admins",
      "guests"
    })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_true(ok)
  end)
  return it("liste vide → faux", function()
    local cond = factory(USER_CFG)({ })
    local ok, _ = cond.eval({
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "10.0.0.1"
    })
    return assert.is_false(ok)
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
  it("liste vide → faux", function()
    local f = (stolen_computer({ }))({ })
    return assert.is_false((f({
      mac = "de:ad:be:ef:00:01"
    })))
  end)
  return it("MAC nil → faux", function()
    local f = (stolen_computer({ }))({
      "de:ad:be:ef:00:01"
    })
    local v = f({
      mac = nil
    })
    return assert.is_false(v)
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
describe("filter.conditions.in_times (auto-généré)", function()
  local compiler_api = require("filter.compiler_api")
  local factory = compiler_api.load_condition("in_times")
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
    local cond = factory(cfg)({
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
    local ok, _ = cond.eval({
      ts = ts1
    })
    assert.is_true(ok)
    local ts2 = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 20,
      min = 0,
      sec = 0
    })
    ok, _ = cond.eval({
      ts = ts2
    })
    assert.is_true(ok)
    local ts3 = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 15,
      min = 0,
      sec = 0
    })
    ok, _ = cond.eval({
      ts = ts3
    })
    return assert.is_false(ok)
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
    local cond = factory(cfg)({ })
    local ok, _ = cond.eval({
      ts = os.time()
    })
    return assert.is_false(ok)
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
            to_domain = "local"
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
            to_domain = "evil.com"
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
  it("compile_rules + decide : règles multiples", function()
    local cfg = {
      rules = {
        {
          description = "Autoriser LAN",
          conditions = {
            from_net = "192.168.0.0/16"
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
  it("first_match_wins garde la première règle horaire", function()
    local cfg = {
      times = {
        business = {
          "09:00",
          "18:00"
        }
      },
      decision = {
        first_match_wins = true
      },
      rules = {
        {
          description = "Autoriser heures ouvrées",
          conditions = {
            in_time = "business"
          },
          actions = {
            "allow"
          }
        },
        {
          description = "Deny final",
          conditions = { },
          actions = {
            "deny"
          }
        }
      }
    }
    local rules = m_rule.compile_rules(cfg)
    local ts = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 15,
      min = 0,
      sec = 0
    })
    local v, _, desc = m_rule.decide(rules, {
      ts = ts
    })
    assert.is_true(v)
    return assert.equals("Autoriser heures ouvrées", desc)
  end)
  it("first_match_wins=false laisse la dernière règle horaire gagner", function()
    local cfg = {
      times = {
        business = {
          "09:00",
          "18:00"
        }
      },
      decision = {
        first_match_wins = false
      },
      rules = {
        {
          description = "Autoriser heures ouvrées",
          conditions = {
            in_time = "business"
          },
          actions = {
            "allow"
          }
        },
        {
          description = "Deny final",
          conditions = { },
          actions = {
            "deny"
          }
        }
      }
    }
    local rules = m_rule.compile_rules(cfg)
    local ts = os.time({
      year = 2024,
      month = 1,
      day = 1,
      hour = 15,
      min = 0,
      sec = 0
    })
    local v, _, desc = m_rule.decide(rules, {
      ts = ts
    })
    assert.is_false(v)
    return assert.equals("Deny final", desc)
  end)
  it("condition inconnue → erreur", function()
    local cfg = {
      rules = {
        {
          description = "Règle invalide",
          conditions = {
            nonexistent_condition_xyz = "foo"
          },
          actions = {
            "allow"
          }
        }
      }
    }
    return assert.has_error(function()
      return m_rule.compile_rules(cfg)
    end)
  end)
  it("action inconnue → erreur", function()
    local cfg = {
      rules = {
        {
          description = "Action invalide",
          conditions = { },
          actions = {
            "nonexistent_action_xyz"
          }
        }
      }
    }
    return assert.has_error(function()
      return m_rule.compile_rules(cfg)
    end)
  end)
  return it("decide sans règles → false (default deny)", function()
    local v, msg = m_rule.decide({ }, {
      domain = "foo.com",
      src_ip = "10.0.0.1",
      ts = os.time()
    })
    assert.is_false(v)
    return assert.equals("No matching rule (default deny)", msg)
  end)
end)
describe("filter.actions.dnsonly", function()
  local dnsonly_action = require("filter.actions.dnsonly")
  it("retourne true (verdict allow)", function()
    local factory = dnsonly_action({ })
    local obj = factory({
      description = "test-dnsonly"
    })
    local v, msg = obj.eval({
      domain = "example.com",
      src_ip = "1.2.3.4",
      mac = "aa:bb:cc:dd:ee:ff",
      ts = os.time()
    })
    assert.is_true(v)
    assert.is_not_nil(msg)
    return assert(msg:find("DNS only", 1, true))
  end)
  return it("déclare on_response", function()
    local factory = dnsonly_action({ })
    local obj = factory({
      description = "test"
    })
    return assert.equals("function", type(obj.on_response))
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
  local TMP_CFG = "./tmp/test_filter_config.moon"
  before_each(function()
    if io.open(TMP_CFG, "r") then
      return os.remove(TMP_CFG)
    end
  end)
  after_each(function()
    if io.open(TMP_CFG, "r") then
      return os.remove(TMP_CFG)
    end
  end)
  it("chargement valide", function()
    local src = [[{
  domainlists_dir: "/etc/custos/lists"
  nets: { lan: {"192.168.0.0/16"} }
  times: { business: {"8:00", "18:00"} }
  rules: {
    { description: "Test rule", actions: {"allow"},
      conditions: { {to_domain: "example.com"} } }
  }
}
]]
    local fd = io.open(TMP_CFG, "w")
    fd:write(src)
    fd:close()
    local cfg, err = load_config(TMP_CFG)
    assert.is_not_nil(cfg)
    assert.is_nil(err)
    assert.equals("/etc/custos/lists", cfg.domainlists_dir)
    assert.equals("192.168.0.0/16", cfg.nets.lan[1])
    assert.equals("8:00", cfg.times.business[1])
    return assert.equals(1, #cfg.rules)
  end)
  it("fichier absent → nil + erreur", function()
    local cfg, err = load_config("/nonexistent.moon")
    assert.is_nil(cfg)
    assert.is_not_nil(err)
    return assert.is_string(err)
  end)
  it("syntaxe invalide → nil + erreur", function()
    local fd = io.open(TMP_CFG, "w")
    fd:write("{ invalid moon syntax ===\n")
    fd:close()
    local cfg, err = load_config(TMP_CFG)
    assert.is_nil(cfg)
    return assert.is_not_nil(err)
  end)
  it("sections manquantes → tables vides", function()
    local fd = io.open(TMP_CFG, "w")
    fd:write("{ rules: {} }\n")
    fd:close()
    local cfg, _ = load_config(TMP_CFG)
    assert.equals("table", type(cfg.nets))
    assert.equals("table", type(cfg.times))
    return assert.equals("table", type(cfg.sources))
  end)
  it("auth defaults", function()
    local fd = io.open(TMP_CFG, "w")
    fd:write("{ rules: {} }\n")
    fd:close()
    local cfg, _ = load_config(TMP_CFG)
    assert.equals(33443, cfg.auth.port)
    assert.equals(33080, cfg.auth.captive_port)
    assert.equals("::", cfg.auth.host)
    assert.equals(30, cfg.auth.heartbeat_interval)
    assert.equals(120, cfg.auth.idle_timeout)
    assert.is_true(cfg.auth.sni_verdict.enabled)
    assert.equals("strict-443", cfg.auth.sni_verdict.mode)
    assert.equals("both", cfg.auth.sni_verdict.protocols)
    return assert.equals("fail-closed", cfg.auth.sni_verdict.nft_failure_policy)
  end)
  return it("non-table → nil + erreur", function()
    local fd = io.open(TMP_CFG, "w")
    fd:write('"just a string"\n')
    fd:close()
    local cfg, err = load_config(TMP_CFG)
    assert.is_nil(cfg)
    return assert.is_not_nil(err)
  end)
end)
