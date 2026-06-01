-- tests/unit/filter/filter_spec.moon
-- Spec Busted pour les conditions et règles du système de filtrage DNS.
-- MoonScript → Lua, runner Busted 2.3.0 `--lua=luajit`.

-- Stubs injectés par tests/helpers/busted_setup.lua :
-- - ffi_defs (inet_pton, etc.)
-- - config (valeurs par défaut)
-- - log (fonctions de log)
-- - parse/ethernet (parsing paquets)

ffi = require "ffi"

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

  it "contains avec IP invalide → false", ->
    n = ipcalc.Net "192.168.0.0/16"
    assert.is_false (n\contains "not_an_ip")

  it "contains avec IP vide → false", ->
    n = ipcalc.Net "192.168.0.0/16"
    assert.is_false (n\contains "")

  it "/31 boundary (dernier bit)", ->
    n = ipcalc.Net "10.0.0.2/31"
    assert.is_true (n\contains "10.0.0.2")
    assert.is_true (n\contains "10.0.0.3")
    assert.is_false (n\contains "10.0.0.4")

describe "filter.conditions.to_domain", ->
  to_domain = (require "filter.conditions.to_domain").factory

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

  it "_any → true si domaine présent", ->
    f = (to_domain {}) "_any"
    v = f {domain: "github.com"}
    assert.is_true v

  it "_any → false si domaine absent", ->
    f = (to_domain {}) "_any"
    v = f {domain: nil}
    assert.is_false v

  it "_none → true si domaine absent", ->
    f = (to_domain {}) "_none"
    v = f {domain: nil}
    assert.is_true v

  it "_none → false si domaine présent", ->
    f = (to_domain {}) "_none"
    v = f {domain: "github.com"}
    assert.is_false v

describe "filter.conditions.to_domains", ->
  to_domains = (require "filter.conditions.to_domains").factory

  it "OR logique", ->
    f = (to_domains {}) {"github.com", "debian.org"}
    assert.is_true (f {domain: "github.com"})
    assert.is_true (f {domain: "packages.debian.org"})
    assert.is_false (f {domain: "evil.com"})

  it "liste vide → faux", ->
    f = (to_domains {}) {}
    assert.is_false (f {domain: "github.com"})

describe "filter.conditions.to_domainlist", ->
  to_domainlist = (require "filter.conditions.to_domainlist").factory
  TMPDIR = "./tmp"
  TMPBIN = TMPDIR .. "/test_filter_domainlist.bin"

  before_each ->
    -- Créer fichier .bin de test (format 48 bits, cf. filter.lib.bin48)
    ok = pcall require, "ffi_xxhash"
    if ok
      bin48 = require "filter.lib.bin48"
      test_domains = {"github.com", "debian.org", "cloudflare.com"}
      payload = bin48.pack_domains test_domains
      fd = io.open TMPBIN, "wb"
      fd\write payload
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

  it "fichier .bin absent → faux (load échoue)", ->
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "does_not_exist_xyz"
    v, r = f {domain: "github.com"}
    assert.is_false v
    assert.is_not_nil r

  it "fichier .bin vide (0 octets) → faux", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    empty_bin = TMPDIR .. "/empty_domainlist.bin"
    fd = io.open empty_bin, "wb"
    fd\close!
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "empty_domainlist"
    v, r = f {domain: "github.com"}
    assert.is_false v
    os.remove empty_bin

  it "nom de liste invalide (commence par /) → faux", ->
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "/etc/passwd"
    v, r = f {domain: "github.com"}
    assert.is_false v
    assert.is_not_nil (r\find "invalide", 1, true)

  it "domaine absent dans req → faux", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "test_filter_domainlist"
    v, r = f {domain: nil}
    assert.is_false v
    assert.is_not_nil (r\find "Missing", 1, true)

  it "fichier texte .domains → domaines chargés et matchés", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    -- Créer un fichier texte .domains (pas .bin) pour tester la branche texte
    domains_path = TMPDIR .. "/test_text_domainlist.domains"
    fd = io.open domains_path, "w"
    fd\write "# commentaire\ngithub.com\ndebian.org\n"
    fd\close!
    cfg = { domainlists_dir: TMPDIR }
    -- Pas de .bin correspondant → fallback sur .domains
    f = (to_domainlist cfg) "test_text_domainlist"
    assert.is_true (f {domain: "github.com"})
    assert.is_true (f {domain: "api.debian.org"})
    assert.is_false (f {domain: "evil.com"})
    os.remove domains_path

  it "fichier .domains vide → faux", ->
    ok = pcall require, "ffi_xxhash"
    pending "ffi_xxhash non disponible" unless ok
    empty_domains = TMPDIR .. "/empty_text_domainlist.domains"
    fd = io.open empty_domains, "w"
    fd\write ""
    fd\close!
    cfg = { domainlists_dir: TMPDIR }
    f = (to_domainlist cfg) "empty_text_domainlist"
    v, r = f {domain: "github.com"}
    assert.is_false v
    os.remove empty_domains

describe "filter.conditions.to_domainlists", ->
  to_domainlists = (require "filter.conditions.to_domainlists").factory
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
  from_mac = (require "filter.conditions.from_mac").factory

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

  it "_any → true si MAC présente", ->
    f = (from_mac {}) "_any"
    assert.is_true (f {mac: "aa:bb:cc:dd:ee:ff"})

  it "_any → false si MAC absente", ->
    f = (from_mac {}) "_any"
    assert.is_false (f {mac: nil})

  it "_none → true si MAC absente", ->
    f = (from_mac {}) "_none"
    assert.is_true (f {mac: nil})

  it "_none → false si MAC présente", ->
    f = (from_mac {}) "_none"
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff"})

describe "filter.conditions.from_macs (auto-généré)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_macs"

  it "MAC dans liste", ->
    cond = factory({}) {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff"}
    assert.is_true ok
    ok, _ = cond.eval {mac: "11:22:33:44:55:66"}
    assert.is_true ok

  it "MAC absente", ->
    cond = factory({}) {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    ok, _ = cond.eval {mac: "de:ad:be:ef:00:01"}
    assert.is_false ok

  it "liste vide → faux", ->
    cond = factory({}) {}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff"}
    assert.is_false ok

describe "filter.conditions.from_mac_list (auto-généré, fichier)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_mac_list"
  LIST_DIR = "/tmp/custos_test_mac_list"
  CFG = { lists_dir: LIST_DIR }

  before_each ->
    os.execute "mkdir -p #{LIST_DIR}/mac"
    fh = io.open "#{LIST_DIR}/mac/trusted.txt", "w"
    fh\write "aa:bb:cc:dd:ee:ff\n11:22:33:44:55:66\n# commentaire\n\n"
    fh\close!

  after_each ->
    os.execute "rm -rf #{LIST_DIR}"

  it "MAC dans fichier liste", ->
    cond = factory(CFG) "trusted"
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff"}
    assert.is_true ok

  it "MAC absente du fichier", ->
    cond = factory(CFG) "trusted"
    ok, _ = cond.eval {mac: "de:ad:be:ef:00:01"}
    assert.is_false ok

  it "liste inconnue → faux", ->
    cond = factory(CFG) "unknown"
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff"}
    assert.is_false ok

describe "filter.conditions.from_mac_lists (auto-généré, fichiers)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_mac_lists"
  LIST_DIR = "/tmp/custos_test_mac_lists"
  CFG = { lists_dir: LIST_DIR }

  before_each ->
    os.execute "mkdir -p #{LIST_DIR}/mac"
    fh = io.open "#{LIST_DIR}/mac/trusted.txt", "w"
    fh\write "aa:bb:cc:dd:ee:ff\n"
    fh\close!
    fh = io.open "#{LIST_DIR}/mac/printers.txt", "w"
    fh\write "de:ad:be:ef:00:01\n"
    fh\close!

  after_each ->
    os.execute "rm -rf #{LIST_DIR}"

  it "OR sur plusieurs fichiers listes", ->
    cond = factory(CFG) {"trusted", "printers"}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff"}
    assert.is_true ok
    ok, _ = cond.eval {mac: "de:ad:be:ef:00:01"}
    assert.is_true ok
    ok, _ = cond.eval {mac: "00:00:00:00:00:00"}
    assert.is_false ok

  it "liste vide → faux", ->
    cond = factory(CFG) {}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff"}
    assert.is_false ok

describe "filter.conditions.from_net", ->
  from_net = (require "filter.conditions.from_net").factory

  it "IP dans CIDR", ->
    f = (from_net {}) "192.168.0.0/16"
    assert.is_true (f {src_ip: "192.168.1.42"})

  it "IP hors CIDR", ->
    f = (from_net {}) "192.168.0.0/16"
    assert.is_false (f {src_ip: "10.0.0.1"})

  it "CIDR invalide → faux", ->
    f = (from_net {}) "invalid/24"
    assert.is_false (f {src_ip: "192.168.1.1"})

  it "_any → true si src_ip présente", ->
    f = (from_net {}) "_any"
    v = f {src_ip: "10.0.0.1"}
    assert.is_true v

  it "_any → false si src_ip absente", ->
    f = (from_net {}) "_any"
    v = f {src_ip: nil}
    assert.is_false v

  it "_none → true si src_ip absente", ->
    f = (from_net {}) "_none"
    v = f {src_ip: nil}
    assert.is_true v

  it "_none → false si src_ip présente", ->
    f = (from_net {}) "_none"
    v = f {src_ip: "10.0.0.1"}
    assert.is_false v

  it "src_ip absente sur CIDR valide → faux", ->
    f = (from_net {}) "192.168.0.0/16"
    v = f {src_ip: nil}
    assert.is_false v

describe "filter.conditions.from_nets (auto-généré)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_nets"

  it "IP dans l'un des CIDRs", ->
    cond = factory({}) {"192.168.0.0/16", "10.0.0.0/8"}
    ok, _ = cond.eval {src_ip: "192.168.1.1"}
    assert.is_true ok
    ok, _ = cond.eval {src_ip: "10.5.0.1"}
    assert.is_true ok

  it "IP hors de tous les CIDRs", ->
    cond = factory({}) {"192.168.0.0/16", "10.0.0.0/8"}
    ok, _ = cond.eval {src_ip: "8.8.8.8"}
    assert.is_false ok

  it "liste vide → faux", ->
    cond = factory({}) {}
    ok, _ = cond.eval {src_ip: "192.168.1.1"}
    assert.is_false ok

describe "filter.conditions.from_net_list (auto-généré, fichier)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_net_list"
  LIST_DIR = "/tmp/custos_test_net_list"
  CFG = { lists_dir: LIST_DIR }

  before_each ->
    os.execute "mkdir -p #{LIST_DIR}/net"
    fh = io.open "#{LIST_DIR}/net/lan.txt", "w"
    fh\write "192.168.0.0/16\n10.0.0.0/8\n# commentaire\n\n"
    fh\close!

  after_each ->
    os.execute "rm -rf #{LIST_DIR}"

  it "IP dans fichier netlist", ->
    cond = factory(CFG) "lan"
    ok, _ = cond.eval {src_ip: "192.168.1.42"}
    assert.is_true ok
    ok, _ = cond.eval {src_ip: "10.5.0.1"}
    assert.is_true ok

  it "IP hors fichier netlist", ->
    cond = factory(CFG) "lan"
    ok, _ = cond.eval {src_ip: "8.8.8.8"}
    assert.is_false ok

  it "liste inconnue → faux", ->
    cond = factory(CFG) "unknown"
    ok, _ = cond.eval {src_ip: "192.168.1.1"}
    assert.is_false ok

describe "filter.conditions.from_net_lists (auto-généré, fichiers)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_net_lists"
  LIST_DIR = "/tmp/custos_test_net_lists"
  CFG = { lists_dir: LIST_DIR }

  before_each ->
    os.execute "mkdir -p #{LIST_DIR}/net"
    fh = io.open "#{LIST_DIR}/net/lan.txt", "w"
    fh\write "192.168.0.0/16\n"
    fh\close!
    fh = io.open "#{LIST_DIR}/net/dmz.txt", "w"
    fh\write "172.16.0.0/12\n"
    fh\close!

  after_each ->
    os.execute "rm -rf #{LIST_DIR}"

  it "OR sur plusieurs fichiers netlists", ->
    cond = factory(CFG) {"lan", "dmz"}
    ok, _ = cond.eval {src_ip: "192.168.0.1"}
    assert.is_true ok
    ok, _ = cond.eval {src_ip: "172.16.1.1"}
    assert.is_true ok
    ok, _ = cond.eval {src_ip: "1.2.3.4"}
    assert.is_false ok

  it "liste vide → faux", ->
    cond = factory(CFG) {}
    ok, _ = cond.eval {src_ip: "192.168.1.1"}
    assert.is_false ok

describe "filter.conditions.from_user", ->
  from_user = (require "filter.conditions.from_user").factory
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
    package.loaded["filter.conditions.from_user"] = nil
    from_user = (require "filter.conditions.from_user").factory

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
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", os.time! - 1} }
    sessions_mod.reset_cache!
    f = (from_user USER_CFG) "alice"
    assert.is_false (f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"})

  it "_any → true si session active", ->
    f = (from_user USER_CFG) "_any"
    v = f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_true v

  it "_any → false si pas de session", ->
    f = (from_user USER_CFG) "_any"
    v = f {mac: "ff:ff:ff:ff:ff:ff", src_ip: "10.0.0.2"}
    assert.is_false v

  it "_none → true si pas de session", ->
    f = (from_user USER_CFG) "_none"
    v = f {mac: "ff:ff:ff:ff:ff:ff", src_ip: "10.0.0.2"}
    assert.is_true v

  it "_none → false si session active", ->
    f = (from_user USER_CFG) "_none"
    v = f {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_false v

  -- ── safe_get_mac : branches non couvertes ────────────────────────────────
  -- Ces tests rechargent from_user pour réinitialiser _get_mac_tried.
  -- La config stub n'a pas MAC_LEARNER_QUERY_SOCK ; on l'ajoute si nécessaire.

  it "mac=nil, src_ip=nil → safe_get_mac(nil) → retourne nil", ->
    -- Force rechargement pour réinitialiser _get_mac_tried = false
    package.loaded["filter.conditions.from_user"] = nil
    cfg_stub = package.loaded["config"]
    cfg_stub.MAC_LEARNER_QUERY_SOCK = cfg_stub.MAC_LEARNER_QUERY_SOCK or "/nonexistent/custos/mac_query.sock"
    fu = (require "filter.conditions.from_user").factory
    f = (fu USER_CFG) "_none"
    -- mac=nil, src_ip=nil → safe_get_mac(nil) → nil → session_for_mac(nil, nil, ...) → nil
    v = f {mac: nil, src_ip: nil}
    assert.is_true v  -- _none + pas de session

  it "mac=nil, src_ip présent + learner stub → safe_get_mac retourne nil", ->
    -- Rechargement fresh de from_user avec un stub mac_learner_ipc qui retourne nil
    package.loaded["filter.conditions.from_user"] = nil
    package.loaded["mac_learner_ipc"] = nil
    old_preload = package.preload["mac_learner_ipc"]
    package.preload["mac_learner_ipc"] = -> { get_mac: -> nil }
    fu = (require "filter.conditions.from_user").factory
    f = (fu USER_CFG) "_none"
    v = f {mac: nil, src_ip: "10.0.0.1"}
    assert.is_true v  -- _none : pas de session active
    -- Restaurer
    package.preload["mac_learner_ipc"] = old_preload
    package.loaded["mac_learner_ipc"] = nil
    package.loaded["filter.conditions.from_user"] = nil

  it "mac=nil → safe_get_mac: chargement mac_learner_ipc échoue → nil", ->
    -- Forcer pcall(require) à échouer pour couvrir la branche 'not ok'
    package.loaded["filter.conditions.from_user"] = nil
    package.loaded["mac_learner_ipc"] = nil
    old_preload = package.preload["mac_learner_ipc"]
    package.preload["mac_learner_ipc"] = -> error "mac_learner_ipc non disponible (test)"
    fu = (require "filter.conditions.from_user").factory
    f = (fu USER_CFG) "_none"
    v = f {mac: nil, src_ip: "10.0.0.1"}
    assert.is_true v  -- safe_get_mac retourne nil → pas de session → _none vrai
    -- Restaurer
    package.preload["mac_learner_ipc"] = old_preload
    package.loaded["mac_learner_ipc"] = nil

  it "mac=nil → safe_get_mac: _get_mac absent (mod sans get_mac) → nil", ->
    -- Forcer mac_learner_ipc à charger mais sans get_mac
    package.loaded["filter.conditions.from_user"] = nil
    package.loaded["mac_learner_ipc"] = nil
    old_preload = package.preload["mac_learner_ipc"]
    package.preload["mac_learner_ipc"] = -> {}  -- table vide, pas de get_mac
    fu = (require "filter.conditions.from_user").factory
    -- Premier appel : charge mac_learner_ipc → _get_mac = nil (pas de get_mac)
    f = (fu USER_CFG) "_none"
    v = f {mac: nil, src_ip: "10.0.0.1"}
    assert.is_true v  -- safe_get_mac → _get_mac nil → retourne nil → _none vrai
    -- Deuxième appel : _get_mac_tried = true, _get_mac = nil → branche 'not _get_mac'
    v2 = f {mac: nil, src_ip: "10.0.0.2"}
    assert.is_true v2
    -- Restaurer
    package.preload["mac_learner_ipc"] = old_preload
    package.loaded["mac_learner_ipc"] = nil
    package.loaded["filter.conditions.from_user"] = nil

describe "filter.conditions.from_users (auto-généré)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_users"
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
    cond = factory(USER_CFG) {"alice", "bob"}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_true ok

  it "aucun match", ->
    cond = factory(USER_CFG) {"bob", "charlie"}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_false ok

  it "liste vide → faux", ->
    cond = factory(USER_CFG) {}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_false ok

describe "filter.conditions.from_user_list (auto-généré, fichier)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_user_list"
  LIST_DIR = "/tmp/custos_test_user_list"
  SESSION_FILE = "./tmp/test_from_user_list.lua"
  USER_CFG = { lists_dir: LIST_DIR, auth: { sessions_file: SESSION_FILE } }
  FAR_FUTURE = os.time! + 86400 * 365

  write_session_file = (entries) ->
    fh = io.open SESSION_FILE, "w"
    fh\write "return {\n"
    for entry in *entries
      fh\write string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3])
    fh\write "}\n"
    fh\close!

  before_each ->
    sessions_mod = require "auth.sessions"
    os.execute "mkdir -p #{LIST_DIR}/user"
    fh = io.open "#{LIST_DIR}/user/admins.txt", "w"
    fh\write "alice\nbob\n# commentaire\n\n"
    fh\close!
    fh = io.open "#{LIST_DIR}/user/guests.txt", "w"
    fh\write "charlie\n"
    fh\close!
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", FAR_FUTURE} }
    sessions_mod.reset_cache!

  after_each ->
    os.execute "rm -rf #{LIST_DIR}"
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")

  it "utilisateur dans fichier liste", ->
    cond = factory(USER_CFG) "admins"
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_true ok

  it "utilisateur hors fichier liste", ->
    cond = factory(USER_CFG) "guests"
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_false ok

  it "liste inconnue → faux", ->
    cond = factory(USER_CFG) "unknown"
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_false ok

describe "filter.conditions.from_user_lists (auto-généré, fichiers)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "from_user_lists"
  LIST_DIR = "/tmp/custos_test_user_lists"
  SESSION_FILE = "./tmp/test_from_user_lists.lua"
  USER_CFG = { lists_dir: LIST_DIR, auth: { sessions_file: SESSION_FILE } }
  FAR_FUTURE = os.time! + 86400 * 365

  write_session_file = (entries) ->
    fh = io.open SESSION_FILE, "w"
    fh\write "return {\n"
    for entry in *entries
      fh\write string.format('  ["%s"] = { user = "%s", expires = %d },\n', entry[1], entry[2], entry[3])
    fh\write "}\n"
    fh\close!

  before_each ->
    sessions_mod = require "auth.sessions"
    os.execute "mkdir -p #{LIST_DIR}/user"
    fh = io.open "#{LIST_DIR}/user/admins.txt", "w"
    fh\write "alice\n"
    fh\close!
    fh = io.open "#{LIST_DIR}/user/guests.txt", "w"
    fh\write "charlie\n"
    fh\close!
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "alice", FAR_FUTURE} }
    sessions_mod.reset_cache!

  after_each ->
    os.execute "rm -rf #{LIST_DIR}"
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")

  it "premier fichier liste match", ->
    cond = factory(USER_CFG) {"admins", "guests"}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_true ok

  it "deuxième fichier liste match", ->
    sessions_mod = require "auth.sessions"
    os.remove SESSION_FILE if io.open(SESSION_FILE, "r")
    write_session_file { {"aa:bb:cc:dd:ee:ff", "charlie", FAR_FUTURE} }
    sessions_mod.reset_cache!
    cond = factory(USER_CFG) {"admins", "guests"}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_true ok

  it "liste vide → faux", ->
    cond = factory(USER_CFG) {}
    ok, _ = cond.eval {mac: "aa:bb:cc:dd:ee:ff", src_ip: "10.0.0.1"}
    assert.is_false ok

describe "filter.conditions.stolen_computer", ->
  stolen_computer = (require "filter.conditions.stolen_computer").factory

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

  it "MAC nil → faux", ->
    f = (stolen_computer {}) {"de:ad:be:ef:00:01"}
    v = f {mac: nil}
    assert.is_false v

describe "filter.conditions.in_time", ->
  in_time = (require "filter.conditions.in_time").factory

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

describe "filter.conditions.in_times (auto-généré)", ->
  compiler_api = require "filter.compiler_api"
  factory = compiler_api.load_condition "in_times"

  it "OR sur plusieurs fenêtres", ->
    cfg = {
      times: {
        morning: {"06:00", "12:00"}
        evening: {"18:00", "22:00"}
      }
    }
    cond = factory(cfg) {"morning", "evening"}
    ts1 = os.time {year: 2024, month: 1, day: 1, hour: 8, min: 0, sec: 0}
    ok, _ = cond.eval {ts: ts1}
    assert.is_true ok
    ts2 = os.time {year: 2024, month: 1, day: 1, hour: 20, min: 0, sec: 0}
    ok, _ = cond.eval {ts: ts2}
    assert.is_true ok
    ts3 = os.time {year: 2024, month: 1, day: 1, hour: 15, min: 0, sec: 0}
    ok, _ = cond.eval {ts: ts3}
    assert.is_false ok

  it "liste vide → faux", ->
    cfg = {times: {business: {"09:00", "18:00"}}}
    cond = factory(cfg) {}
    ok, _ = cond.eval {ts: os.time!}
    assert.is_false ok

describe "filter.rule", ->
  m_rule = require "filter.rule"

  it "compile_rules + decide : règle allow", ->
    cfg = {
      rules: {
        {
          description: "Autoriser local"
          conditions: {to_domain: "local"}
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
          conditions: {to_domain: "evil.com"}
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
          conditions: {from_net: "192.168.0.0/16"}
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

  it "first_match_wins garde la première règle horaire", ->
    cfg = {
      times: {
        business: {"09:00", "18:00"}
      }
      decision: {
        first_match_wins: true
      }
      rules: {
        {
          description: "Autoriser heures ouvrées"
          conditions: {in_time: "business"}
          actions: {"allow"}
        }
        {
          description: "Deny final"
          conditions: {}
          actions: {"deny"}
        }
      }
    }
    rules = m_rule.compile_rules cfg
    ts = os.time {year: 2024, month: 1, day: 1, hour: 15, min: 0, sec: 0}
    v, _, desc = m_rule.decide rules, {ts: ts}
    assert.is_true v
    assert.equals "Autoriser heures ouvrées", desc

  it "first_match_wins=false laisse la dernière règle horaire gagner", ->
    cfg = {
      times: {
        business: {"09:00", "18:00"}
      }
      decision: {
        first_match_wins: false
      }
      rules: {
        {
          description: "Autoriser heures ouvrées"
          conditions: {in_time: "business"}
          actions: {"allow"}
        }
        {
          description: "Deny final"
          conditions: {}
          actions: {"deny"}
        }
      }
    }
    rules = m_rule.compile_rules cfg
    ts = os.time {year: 2024, month: 1, day: 1, hour: 15, min: 0, sec: 0}
    v, _, desc = m_rule.decide rules, {ts: ts}
    assert.is_false v
    assert.equals "Deny final", desc

  it "condition inconnue → erreur", ->
    cfg = {
      rules: {
        {
          description: "Règle invalide"
          conditions: {nonexistent_condition_xyz: "foo"}
          actions: {"allow"}
        }
      }
    }
    assert.has_error -> m_rule.compile_rules cfg

  it "action inconnue → erreur", ->
    cfg = {
      rules: {
        {
          description: "Action invalide"
          conditions: {}
          actions: {"nonexistent_action_xyz"}
        }
      }
    }
    assert.has_error -> m_rule.compile_rules cfg

  it "decide sans règles → false (default deny)", ->
    v, msg = m_rule.decide {}, {domain: "foo.com", src_ip: "10.0.0.1", ts: os.time!}
    assert.is_false v
    assert.equals "No matching rule (default deny)", msg

describe "filter.actions.dnsonly", ->
  dnsonly_action = (require "filter.actions.dnsonly").factory

  it "retourne true (verdict allow)", ->
    factory = dnsonly_action {}
    obj = factory {description: "test-dnsonly"}
    v, msg = obj.eval {domain: "example.com", src_ip: "1.2.3.4", mac: "aa:bb:cc:dd:ee:ff", ts: os.time!}
    assert.is_true v
    assert.is_not_nil msg
    assert msg\find("DNS only", 1, true)

  it "déclare on_response", ->
    factory = dnsonly_action {}
    obj = factory {description: "test"}
    assert.equals "function", type(obj.on_response)

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
  TMP_CFG = "./tmp/test_filter_config.moon"

  before_each ->
    os.remove TMP_CFG if io.open(TMP_CFG, "r")

  after_each ->
    os.remove TMP_CFG if io.open(TMP_CFG, "r")

  it "chargement valide", ->
    src = [[
{
  domainlists_dir: "/etc/custos/lists"
  nets: { lan: {"192.168.0.0/16"} }
  times: { business: {"8:00", "18:00"} }
  rules: {
    { description: "Test rule", actions: {"allow"},
      conditions: { {to_domain: "example.com"} } }
  }
}
]]
    fd = io.open TMP_CFG, "w"
    fd\write src
    fd\close!
    cfg, err = load_config TMP_CFG
    assert.is_not_nil cfg
    assert.is_nil err
    assert.equals "/etc/custos/lists", cfg.domainlists_dir
    assert.equals "192.168.0.0/16", cfg.nets.lan[1]
    assert.equals "8:00", cfg.times.business[1]
    assert.equals 1, #cfg.rules

  it "fichier absent → nil + erreur", ->
    cfg, err = load_config "/nonexistent.moon"
    assert.is_nil cfg
    assert.is_not_nil err
    assert.is_string err

  it "syntaxe invalide → nil + erreur", ->
    fd = io.open TMP_CFG, "w"
    fd\write "{ invalid moon syntax ===\n"
    fd\close!
    cfg, err = load_config TMP_CFG
    assert.is_nil cfg
    assert.is_not_nil err

  it "sections manquantes → tables vides", ->
    fd = io.open TMP_CFG, "w"
    fd\write "{ rules: {} }\n"
    fd\close!
    cfg, _ = load_config TMP_CFG
    assert.equals "table", type(cfg.nets)
    assert.equals "table", type(cfg.times)
    assert.equals "table", type(cfg.sources)

  it "auth defaults", ->
    fd = io.open TMP_CFG, "w"
    fd\write "{ rules: {} }\n"
    fd\close!
    cfg, _ = load_config TMP_CFG
    assert.equals 33443, cfg.auth.port
    assert.equals 33080, cfg.auth.captive_port
    assert.equals "::", cfg.auth.host
    assert.equals 30, cfg.auth.heartbeat_interval
    assert.equals 120, cfg.auth.idle_timeout
    assert.is_true cfg.sni.enabled
    assert.equals "strict-443", cfg.sni.mode
    assert.equals "both", cfg.sni.protocols
    assert.equals "fail-closed", cfg.sni.nft_failure_policy

  it "non-table → nil + erreur", ->
    fd = io.open TMP_CFG, "w"
    fd\write '"just a string"\n'
    fd\close!
    cfg, err = load_config TMP_CFG
    assert.is_nil cfg
    assert.is_not_nil err
