-- tests/unit/filter/filter_spec.moon
-- Spec Busted pour les conditions et règles du système de filtrage DNS.
-- MoonScript → Lua, runner Busted 2.3.0 `--lua=luajit`.

-- Stubs injectés par tests/helpers/busted_setup.lua :
-- - ffi_defs (inet_pton, etc.)
-- - config (valeurs par défaut)
-- - log (fonctions de log)
-- - parse/ethernet (parsing paquets)

ffi = require "ffi"

describe "filter.lib.bsearch", ->
  { :bsearch } = require "filter.lib.bsearch"

  it "trouve en début", ->
    arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
    assert.is_true (bsearch arr, 3, 100ULL)

  it "trouve en milieu", ->
    arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
    assert.is_true (bsearch arr, 3, 200ULL)

  it "trouve en fin", ->
    arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
    assert.is_true (bsearch arr, 3, 300ULL)

  it "retourne faux si absent", ->
    arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
    assert.is_false (bsearch arr, 3, 150ULL)

  it "gère tableau vide", ->
    arr = ffi.new "uint64_t[0]"
    assert.is_false (bsearch arr, 0, 42ULL)

describe "filter.lib.ipcalc", ->
  ipcalc = require "filter.lib.ipcalc"

  it "IPv4 dans sous-réseau /16", ->
    n = ipcalc.Net "192.168.0.0/16"
    assert.is_not_nil n
    assert.is_true (n\contains "192.168.1.42")

  it "IPv4 hors sous-réseau", ->
    n = ipcalc.Net "192.168.0.0/16"
    assert.is_false (n\contains "10.0.0.1")

  it "masque /16 fonctionne", ->
    n = ipcalc.Net "10.0.0.0/8"
    assert.is_true (n\contains "10.255.255.1")
    assert.is_false (n\contains "11.0.0.1")

  it "IPv6 dans sous-réseau", ->
    n = ipcalc.Net "2001:db8::/32"
    assert.is_true (n\contains "2001:db8::1")

  it "IPv6 hors sous-réseau", ->
    n = ipcalc.Net "2001:db8::/32"
    assert.is_false (n\contains "2001:db9::1")

  it "CIDR invalide → nil", ->
    n = ipcalc.Net "not_an_ip/24"
    assert.is_nil n

describe "filter.conditions.to_domain", ->
  to_domain = require "filter.conditions.to_domain"

  it "correspondance exacte", ->
    f = (to_domain {}) "github.com"
    v, r = f {domain: "github.com"}
    assert.is_true v
    assert.equals "Exact match", r

  it "sous-domaine autorisé", ->
    f = (to_domain {}) "github.com"
    v = f {domain: "api.github.com"}
    assert.is_true v

  it "domaine différent bloqué", ->
    f = (to_domain {}) "github.com"
    v = f {domain: "notgithub.com"}
    assert.is_false v

  it "domaine vide → faux", ->
    f = (to_domain {}) "github.com"
    v = f {domain: nil}
    assert.is_false v

describe "filter.conditions.to_domains", ->
  to_domains = require "filter.conditions.to_domains"

  it "OR logique", ->
    f = (to_domains {}) {"github.com", "debian.org"}
    assert.is_true (f {domain: "github.com"})
    assert.is_true (f {domain: "packages.debian.org"})
    assert.is_false (f {domain: "evil.com"})

  it "liste vide → faux", ->
    f = (to_domains {}) {}
    assert.is_false (f {domain: "github.com"})

describe "filter.conditions.to_domainlist", ->
  to_domainlist = require "filter.conditions.to_domainlist"
  TMPDIR = "./tmp"
  TMPBIN = TMPDIR .. "/test_filter_domainlist.bin"

  before_each ->
    -- Créer fichier .bin de test avec xxhash
    ok, xxhash = pcall require, "ffi_xxhash"
    if ok
      test_domains = {"github.com", "debian.org", "cloudflare.com"}
      hashes = [xxhash.xxh64(d) for d in *test_domains]
      table.sort hashes, (a, b) -> a < b
      arr = ffi.new "uint64_t[?]", #hashes
      for i, h in ipairs hashes
        arr[i - 1] = h
      fd = io.open TMPBIN, "wb"
      fd\write ffi.string arr, #hashes * 8
      fd\close!

  after_each ->
    os.remove TMPBIN if io.open(TMPBIN, "r")

  it "domaine présent (fichier .bin)", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "test_filter_domainlist"
    assert.is_true (f {domain: "github.com"})

  it "sous-domaine présent", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "test_filter_domainlist"
    assert.is_true (f {domain: "api.github.com"})

  it "domaine absent", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "test_filter_domainlist"
    assert.is_false (f {domain: "evil.com"})

  it "domainlists_dir absent → faux", ->
    cfg = {}
    f = (to_domainlist cfg) "nonexistent"
    assert.is_false (f {domain: "github.com"})

describe "filter.conditions.to_domainlists", ->
  to_domainlists = require "filter.conditions.to_domainlists"
  TMPDIR = "./tmp"

  before_each ->
    ok, xxhash = pcall require, "ffi_xxhash"
    if ok
      -- Créer deux fichiers de test
      for name, domains in pairs {
        test_filter_domainlist1: {"github.com", "debian.org"}
        test_filter_domainlist2: {"malware.bad", "tracker.bad"}
      }
        hashes = [xxhash.xxh64(d) for d in *domains]
        table.sort hashes, (a, b) -> a < b
        arr = ffi.new "uint64_t[?]", #hashes
        for i, h in ipairs hashes
          arr[i - 1] = h
        path = TMPDIR .. "/" .. name .. ".bin"
        fd = io.open path, "wb"
        fd\write ffi.string arr, #hashes * 8
        fd\close!

  after_each ->
    for name in *{"test_filter_domainlist1", "test_filter_domainlist2"}
      os.remove (TMPDIR .. "/" .. name .. ".bin")

  it "OR sur plusieurs listes", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlists cfg) {"test_filter_domainlist1", "test_filter_domainlist2"}
    assert.is_true (f {domain: "github.com"})
    assert.is_true (f {domain: "malware.bad"})
    assert.is_false (f {domain: "safe.com"})

  it "liste vide → faux", ->
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlists cfg) {}
    assert.is_false (f {domain: "github.com"})

describe "filter.conditions.from_mac", ->
  from_mac = require "filter.conditions.from_mac"

  it "MAC correspondant", ->
    f = (from_mac {}) "aa:bb:cc:dd:ee:ff"
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff"})

  it "MAC différent", ->
    f = (from_mac {}) "aa:bb:cc:dd:ee:ff"
    assert.is_false (f {mac: "00:00:00:00:00:00"})

  it "MAC nil → faux", ->
    f = (from_mac {}) "aa:bb:cc:dd:ee:ff"
    assert.is_false (f {mac: nil})

  it "insensible à la casse", ->
    f = (from_mac {}) "AA:BB:CC:DD:EE:FF"
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff"})

describe "filter.conditions.from_macs", ->
  from_macs = require "filter.conditions.from_macs"

  it "MAC dans liste", ->
    f = (from_macs {}) {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff"})
    assert.is_true (f {mac: "11:22:33:44:55:66"})

  it "MAC absente", ->
    f = (from_macs {}) {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    assert.is_false (f {mac: "de:ad:be:ef:00:01"})

  it "liste vide → faux", ->
    f = (from_macs {}) {}
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff"})

describe "filter.conditions.from_maclist", ->
  from_maclist = require "filter.conditions.from_maclist"
  MACLIST_CFG = {
    maclists: {
      trusted: { "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66" }
      printers: { "de:ad:be:ef:00:01" }
    }
  }

  it "MAC dans groupe", ->
    f = (from_maclist MACLIST_CFG) "trusted"
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff"})

  it "MAC hors groupe", ->
    f = (from_maclist MACLIST_CFG) "trusted"
    assert.is_false (f {mac: "de:ad:be:ef:00:01"})

  it "groupe inconnu → faux", ->
    f = (from_maclist MACLIST_CFG) "unknown"
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff"})

describe "filter.conditions.from_maclists", ->
  from_maclists = require "filter.conditions.from_maclists"
  MACLIST_CFG = {
    maclists: {
      trusted: { "aa:bb:cc:dd:ee:ff" }
      printers: { "de:ad:be:ef:00:01" }
    }
  }

  it "OR sur plusieurs groupes", ->
    f = (from_maclists MACLIST_CFG) {"trusted", "printers"}
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff"})
    assert.is_true (f {mac: "de:ad:be:ef:00:01"})
    assert.is_false (f {mac: "00:00:00:00:00:00"})

  it "liste vide → faux", ->
    f = (from_maclists MACLIST_CFG) {}
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff"})

describe "filter.conditions.from_net", ->
  from_net = require "filter.conditions.from_net"

  it "IP dans CIDR", ->
    f = (from_net {}) "192.168.0.0/16"
    assert.is_true (f {src_ip: "192.168.1.42"})

  it "IP hors CIDR", ->
    f = (from_net {}) "192.168.0.0/16"
    assert.is_false (f {src_ip: "10.0.0.1"})

  it "CIDR invalide → faux", ->
    f = (from_net {}) "invalid/24"
    assert.is_false (f {src_ip: "192.168.1.1"})

describe "filter.conditions.from_nets", ->
  from_nets = require "filter.conditions.from_nets"

  it "IP dans l'un des CIDRs", ->
    f = (from_nets {}) {"192.168.0.0/16", "10.0.0.0/8"}
    assert.is_true (f {src_ip: "192.168.1.1"})
    assert.is_true (f {src_ip: "10.5.0.1"})

  it "IP hors de tous les CIDRs", ->
    f = (from_nets {}) {"192.168.0.0/16", "10.0.0.0/8"}
    assert.is_false (f {src_ip: "8.8.8.8"})

  it "liste vide → faux", ->
    f = (from_nets {}) {}
    assert.is_false (f {src_ip: "192.168.1.1"})

describe "filter.conditions.from_netlist", ->
  from_netlist = require "filter.conditions.from_netlist"
  NETLIST_CFG = {
    nets: {
      lan: {"192.168.0.0/16", "10.0.0.0/8"}
      dmz: {"172.16.0.0/12"}
    }
  }

  it "IP dans netlist", ->
    f = (from_netlist NETLIST_CFG) "lan"
    assert.is_true (f {src_ip: "192.168.1.42"})
    assert.is_true (f {src_ip: "10.5.0.1"})

  it "IP hors netlist", ->
    f = (from_netlist NETLIST_CFG) "lan"
    assert.is_false (f {src_ip: "8.8.8.8"})

  it "netlist inconnue → faux", ->
    f = (from_netlist NETLIST_CFG) "unknown"
    assert.is_false (f {src_ip: "192.168.1.1"})

describe "filter.conditions.from_netlists", ->
  from_netlists = require "filter.conditions.from_netlists"
  NETLIST_CFG = {
    nets: {
      lan: {"192.168.0.0/16"}
      dmz: {"172.16.0.0/12"}
    }
  }

  it "OR sur plusieurs netlists", ->
    f = (from_netlists NETLIST_CFG) {"lan", "dmz"}
    assert.is_true (f {src_ip: "192.168.0.1"})
    assert.is_true (f {src_ip: "172.16.1.1"})
    assert.is_false (f {src_ip: "1.2.3.4"})

  it "liste vide → faux", ->
    f = (from_netlists NETLIST_CFG) {}
    assert.is_false (f {src_ip: "192.168.1.1"})

describe "filter.conditions.from_user", ->
  from_user = require "filter.conditions.from_user"
  SESSION_FILE = "./tmp/test_from_user.lua"
  USER_CFG = { auth: { sessions_file: SESSION_FILE } }
  FAR_FUTURE = os.time! + 86400 * 365

  before_each ->
    sessions_mod = require "auth.sessions"
    write_session_file = (entries) ->
      fh = io.open SESSION_FILE, "w"
      fh\write "return {\n"
      for entry in *entries
        ips_str = ""
        if entry[4] or entry[5]
          ips_str = ", ips = { " .. (entry[4] and ("ipv4 = \""..entry[4].."\"") or "") .. (entry[5] and (", ipv6 = \""..entry[5].."\"") or "") .. " }"
        fh\write string.format('  ["%s"] = { user = "%s", expires = %d%s },\n', entry[1], entry[2], entry[3], ips_str)
      fh\write "}\n"
      fh\close!
    -- Nettoyer et créer fichier de session
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", FAR_FUTURE} }
    sessions_mod.reset_cache!

  after_each ->
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")

  it "session active bon user", ->
    f = (from_user USER_CFG) "alice"
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "session active mauvais user", ->
    f = (from_user USER_CFG) "bob"
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "session expirée", ->
    sessions_mod = require "auth.sessions"
    write_session_file = (entries) ->
      fh = io.open SESSION_FILE, "w"
      fh\write "return {\n"
      for entry in *entries
        fh\write string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3])
      fh\write "}\n"
      fh\close!
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", 1} }
    sessions_mod.reset_cache!
    f = (from_user USER_CFG) "alice"
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

describe "filter.conditions.from_users", ->
  from_users = require "filter.conditions.from_users"
  SESSION_FILE = "./tmp/test_from_users.lua"
  USER_CFG = { auth: { sessions_file: SESSION_FILE } }
  FAR_FUTURE = os.time! + 86400 * 365

  before_each ->
    sessions_mod = require "auth.sessions"
    write_session_file = (entries) ->
      fh = io.open SESSION_FILE, "w"
      fh\write "return {\n"
      for entry in *entries
        fh\write string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3])
      fh\write "}\n"
      fh\close!
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", FAR_FUTURE} }
    sessions_mod.reset_cache!

  after_each ->
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")

  it "premier utilisateur match", ->
    f = (from_users USER_CFG) {"alice", "bob"}
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "aucun match", ->
    f = (from_users USER_CFG) {"bob", "charlie"}
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "liste vide → faux", ->
    f = (from_users USER_CFG) {}
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

describe "filter.conditions.from_userlist", ->
  from_userlist = require "filter.conditions.from_userlist"
  SESSION_FILE = "./tmp/test_from_userlist.lua"
  USER_CFG = {
    auth: { sessions_file: SESSION_FILE }
    userlists: {
      admins: {"alice", "bob"}
      guests: {"charlie"}
    }
  }
  FAR_FUTURE = os.time! + 86400 * 365

  before_each ->
    sessions_mod = require "auth.sessions"
    write_session_file = (entries) ->
      fh = io.open SESSION_FILE, "w"
      fh\write "return {\n"
      for entry in *entries
        fh\write string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3])
      fh\write "}\n"
      fh\close!
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", FAR_FUTURE} }
    sessions_mod.reset_cache!

  after_each ->
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")

  it "utilisateur dans groupe", ->
    f = (from_userlist USER_CFG) "admins"
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "utilisateur hors groupe", ->
    f = (from_userlist USER_CFG) "guests"
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "groupe inconnu → faux", ->
    f = (from_userlist USER_CFG) "unknown"
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

describe "filter.conditions.from_userlists", ->
  from_userlists = require "filter.conditions.from_userlists"
  SESSION_FILE = "./tmp/test_from_userlists.lua"
  USER_CFG = {
    auth: { sessions_file: SESSION_FILE }
    userlists: {
      admins: {"alice"}
      guests: {"charlie"}
    }
  }
  FAR_FUTURE = os.time! + 86400 * 365

  before_each ->
    sessions_mod = require "auth.sessions"
    write_session_file = (entries) ->
      fh = io.open SESSION_FILE, "w"
      fh\write "return {\n"
      for entry in *entries
        fh\write string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3])
      fh\write "}\n"
      fh\close!
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", FAR_FUTURE} }
    sessions_mod.reset_cache!

  after_each ->
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")

  it "premier groupe match", ->
    f = (from_userlists USER_CFG) {"admins", "guests"}
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "deuxième groupe match", ->
    sessions_mod = require "auth.sessions"
    write_session_file = (entries) ->
      fh = io.open SESSION_FILE, "w"
      fh\write "return {\n"
      for entry in *entries
        fh\write string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3])
      fh\write "}\n"
      fh\close!
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "charlie", FAR_FUTURE} }
    sessions_mod.reset_cache!
    f = (from_userlists USER_CFG) {"admins", "guests"}
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "liste vide → faux", ->
    f = (from_userlists USER_CFG) {}
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

describe "filter.conditions.stolen_computer", ->
  stolen_computer = require "filter.conditions.stolen_computer"

  it "MAC blacklistée", ->
    f = (stolen_computer {}) {"de:ad:be:ef:00:01"}
    v, r = f {mac: "de:ad:be:ef:00:01"}
    assert.is_true v
    assert.equals "Stolen computer: de:ad:be:ef:00:01", r

  it "MAC non blacklistée", ->
    f = (stolen_computer {}) {"de:ad:be:ef:00:01"}
    v, r = f {mac: "aa:bb:cc:dd:ee:ff"}
    assert.is_false v

  it "liste vide → faux", ->
    f = (stolen_computer {}) {}
    assert.is_false (f {mac: "de:ad:be:ef:00:01"})

describe "filter.conditions.in_time", ->
  in_time = require "filter.conditions.in_time"

  it "heure dans plage", ->
    cfg = {times: {business: {"09:00", "18:00"}}}
    f = (in_time cfg) "business"
    -- Simuler 15h00
    ts = os.time {year: 2024, month: 1, day: 1, hour: 15, min: 0, sec: 0}
    v, r = f {ts: ts}
    assert.is_true v

  it "heure hors plage", ->
    cfg = {times: {business: {"09:00", "18:00"}}}
    f = (in_time cfg) "business"
    -- Simuler 20h00
    ts = os.time {year: 2024, month: 1, day: 1, hour: 20, min: 0, sec: 0}
    v, r = f {ts: ts}
    assert.is_false v

  it "fenêtre inconnue → faux", ->
    cfg = {times: {}}
    f = (in_time cfg) "unknown"
    v, r = f {ts: os.time!}
    assert.is_false v
    assert.equals "Time window 'unknown' not defined", r

describe "filter.conditions.in_times", ->
  in_times = require "filter.conditions.in_times"

  it "OR sur plusieurs fenêtres", ->
    cfg = {
      times: {
        morning: {"06:00", "12:00"}
        evening: {"18:00", "22:00"}
      }
    }
    f = (in_times cfg) {"morning", "evening"}
    -- 08h00 (dans morning)
    ts1 = os.time {year: 2024, month: 1, day: 1, hour: 8, min: 0, sec: 0}
    assert.is_true (f {ts: ts1})
    -- 20h00 (dans evening)
    ts2 = os.time {year: 2024, month: 1, day: 1, hour: 20, min: 0, sec: 0}
    assert.is_true (f {ts: ts2})
    -- 15h00 (nulle part)
    ts3 = os.time {year: 2024, month: 1, day: 1, hour: 15, min: 0, sec: 0}
    assert.is_false (f {ts: ts3})

  it "liste vide → faux", ->
    cfg = {times: {business: {"09:00", "18:00"}}}
    f = (in_times cfg) {}
    assert.is_false (f {ts: os.time!})

describe "filter.rule", ->
  m_rule = require "filter.rule"

  it "compile_rules + decide : règle allow", ->
    cfg = {
      rules: {
        {
          description: "Autoriser local"
          conditions: {{to_domain: "local"}}
          actions: {"allow"}
        }
      }
    }
    rules = m_rule.compile_rules cfg
    v, msg, desc = m_rule.decide rules, {domain: "test.local", mac: "aa:bb:cc:dd:ee:ff", src_ip: "192.168.1.1", ts: os.time!}
    assert.is_true v
    assert.equals "Autoriser local", desc

  it "compile_rules + decide : règle deny", ->
    cfg = {
      rules: {
        {
          description: "Bloquer evil"
          conditions: {{to_domain: "evil.com"}}
          actions: {"deny"}
        }
      }
    }
    rules = m_rule.compile_rules cfg
    v, msg, desc = m_rule.decide rules, {domain: "evil.com", mac: "aa:bb:cc:dd:ee:ff", src_ip: "192.168.1.1", ts: os.time!}
    assert.is_false v
    assert.equals "Bloquer evil", desc

  it "compile_rules + decide : règles multiples", ->
    cfg = {
      rules: {
        {
          description: "Autoriser LAN"
          conditions: {{from_net: "192.168.0.0/16"}}
          actions: {"allow"}
        }
        {
          description: "Bloquer tout"
          conditions: {}
          actions: {"deny"}
        }
      }
    }
    rules = m_rule.compile_rules cfg
    -- IP dans LAN → première règle match
    v1, _, desc1 = m_rule.decide rules, {domain: "example.com", src_ip: "192.168.1.1", ts: os.time!}
    assert.is_true v1
    assert.equals "Autoriser LAN", desc1
    -- IP hors LAN → deuxième règle (deny par défaut)
    v2, _, desc2 = m_rule.decide rules, {domain: "example.com", src_ip: "8.8.8.8", ts: os.time!}
    assert.is_false v2
    assert.equals "Bloquer tout", desc2

describe "filter.actions.dnsonly", ->
  dnsonly_action = require "filter.actions.dnsonly"

  it "retourne \"dnsonly\"", ->
    factory = dnsonly_action {}
    rule_fn = factory {description: "test-dnsonly"}
    v, msg = rule_fn {domain: "example.com", src_ip: "1.2.3.4", mac: "aa:bb:cc:dd:ee:ff", ts: os.time!}
    assert.equals "dnsonly", v
    assert.is_not_nil msg
    assert msg\find("DNS only", 1, true)

  it "verdict distinct de true/false", ->
    factory = dnsonly_action {}
    rule_fn = factory {description: "test"}
    v, _ = rule_fn {}
    assert.equals "string", type(v)
    assert.is_not_true v  -- pas true
    assert.is_not_false v -- pas false

describe "filter.lib.parse_domains", ->
  { :parse, :parse_simple, :parse_hosts, :parse_adblock, :is_valid } = require "filter.lib.parse_domains"

  -- Helper : vérifie qu'une valeur est dans un tableau
  has = (tbl, val) ->
    for v in *tbl
      return true if v == val
    false

  it "parse_simple", ->
    text = [[
# Commentaire
example.com
ads.example.com
DOUBLECLICK.NET
# autre commentaire
]]
    result = parse_simple text
    assert.equals 3, #result
    assert.is_true (has result, "example.com")
    assert.is_true (has result, "ads.example.com")
    assert.is_true (has result, "doubleclick.net")

  it "parse_hosts", ->
    text = [[
127.0.0.1 localhost
0.0.0.0 ads.example.com
0.0.0.0 0.0.0.0
127.0.0.1 tracking.example.org
0.0.0.0 DOUBLECLICK.NET
]]
    result = parse_hosts text
    assert.equals 3, #result
    assert.is_true (has result, "ads.example.com")
    assert.is_true (has result, "tracking.example.org")
    assert.is_true (has result, "doubleclick.net")

  it "parse_adblock", ->
    text = [[
! Commentaire adblock
||ads.example.com^
||tracker.example.org^$third-party
@@||whitelist.example.com^
||DOUBLECLICK.NET^
]]
    result = parse_adblock text
    assert.equals 3, #result
    assert.is_true (has result, "ads.example.com")
    assert.is_true (has result, "tracker.example.org")
    assert.is_true (has result, "doubleclick.net")

  it "parse dispatch", ->
    result1 = parse "simple", "example.com\n# comment\n"
    assert.equals 1, #result1
    assert.equals "example.com", result1[1]

    result2 = parse "unknown", "example.com\n"
    assert.equals 1, #result2  -- fallback vers simple

  it "is_valid", ->
    assert.is_true (is_valid "example.com")
    assert.is_true (is_valid "sub.example.com")
    assert.is_false (is_valid "")
    assert.is_false (is_valid "1.2.3.4")  -- IPv4
    assert.is_false (is_valid "::1")      -- IPv6
    assert.is_false (is_valid "localhost") -- pas de point
    assert.is_false (is_valid (string.rep("a", 254))) -- trop long

describe "filter.lib.load_config", ->
  { :load_config } = require "filter.lib.load_config"
  TMP_YAML = "./tmp/test_filter_config.yml"

  before_each ->
    os.remove TMP_YAML if io.open(TMP_YAML, "r")

  after_each ->
    os.remove TMP_YAML if io.open(TMP_YAML, "r")

  it "chargement valide", ->
    yaml = [[
domainlists_dir: /etc/custos/lists
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
    fd = io.open TMP_YAML, "w"
    fd\write yaml
    fd\close!
    cfg, err = load_config TMP_YAML
    assert.is_not_nil cfg
    assert.is_nil err
    assert.equals "/etc/custos/lists", cfg.domainlists_dir
    assert.equals "192.168.0.0/16", cfg.nets.lan[1]
    assert.equals "8:00", cfg.times.business[1]
    assert.equals 1, #cfg.rules

  it "fichier absent → nil + erreur", ->
    cfg, err = load_config "/nonexistent.yml"
    assert.is_nil cfg
    assert.is_not_nil err
    assert.is_string err

  it "YAML invalide → nil + erreur", ->
    fd = io.open TMP_YAML, "w"
    fd\write "invalid: yaml: ["
    fd\close!
    cfg, err = load_config TMP_YAML
    assert.is_nil cfg
    assert.is_not_nil err

  it "sections manquantes → tables vides", ->
    yaml = "rules: []\n"
    fd = io.open TMP_YAML, "w"
    fd\write yaml
    fd\close!
    cfg, _ = load_config TMP_YAML
    assert.equals "table", type(cfg.nets)
    assert.equals "table", type(cfg.times)
    assert.equals "table", type(cfg.sources)

  it "auth defaults", ->
    yaml = "rules: []\n"
    fd = io.open TMP_YAML, "w"
    fd\write yaml
    fd\close!
    cfg, _ = load_config TMP_YAML
    assert.equals 33443, cfg.auth.port
    assert.equals 33080, cfg.auth.captive_port
    assert.equals "::", cfg.auth.host
    assert.equals 30, cfg.auth.heartbeat_interval
    assert.equals 120, cfg.auth.idle_timeout
