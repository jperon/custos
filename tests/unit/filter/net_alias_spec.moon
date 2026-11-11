-- tests/unit/filter/net_alias_spec.moon
-- Résolution des alias de `filter.nets` par from_net/to_net (et variantes
-- auto-générées). Un argument qui n'est ni _any/_none ni un CIDR/IP littéral
-- mais une clé de cfg.nets devient un OU sur les CIDRs du groupe.
--
-- Toutes les sorties de test restent sous ./tmp/ (cf. AGENTS.md).

log          = require "log"
compiler_api = require "filter.compiler_api"
from_net     = (require "filter.conditions.from_net").factory
to_net       = (require "filter.conditions.to_net").factory

TMP_DIR   = "./tmp/net_alias_spec"
LISTS_DIR = "#{TMP_DIR}/lists"

warns = {}
original_warn = log.log_warn

capture_warns = ->
  warns = {}
  log.log_warn = (thunk) ->
    fields = thunk!
    warns[#warns + 1] = fields if fields != nil

write_file = (path, content) ->
  fh = assert io.open path, "w"
  fh\write content
  fh\close!

CFG = {
  lists_dir: LISTS_DIR
  nets: {
    lan:            { "192.168.0.0/16", "10.0.0.0/8" }
    v6:             { "2001:db8::/32" }
    single:         "172.16.0.0/12"
    mixed:          { "192.168.50.0/24", "2001:db8:50::/64" }
    "10.0.0.0/8":   { "192.168.99.0/24" }   -- collision nom/CIDR : le CIDR gagne
  }
}

before_each ->
  os.execute "mkdir -p #{LISTS_DIR}/net"
  capture_warns!

after_each ->
  log.log_warn = original_warn
  os.execute "rm -rf #{TMP_DIR}"

describe "from_net — alias de filter.nets", ->
  it "groupe de plusieurs CIDRs : OU logique", ->
    cond = (from_net CFG) "lan"
    assert.is_true (cond.eval { src_ip: "192.168.1.42" })
    assert.is_true (cond.eval { src_ip: "10.5.0.1" })
    assert.is_false (cond.eval { src_ip: "8.8.8.8" })
    assert.equals 0, #warns

  it "groupe IPv6", ->
    cond = (from_net CFG) "v6"
    assert.is_true (cond.eval { src_ip: "2001:db8::1" })
    assert.is_false (cond.eval { src_ip: "2001:db9::1" })

  it "valeur scalaire (chaîne) acceptée", ->
    cond = (from_net CFG) "single"
    assert.is_true (cond.eval { src_ip: "172.20.0.1" })
    assert.is_false (cond.eval { src_ip: "192.168.1.1" })

  it "un CIDR littéral reste littéral même si nets a une clé de même nom", ->
    cond = (from_net CFG) "10.0.0.0/8"
    assert.is_true (cond.eval { src_ip: "10.5.0.1" })
    assert.is_false (cond.eval { src_ip: "192.168.99.5" })

  it "nom inconnu : ne matche jamais et un seul avertissement à la construction", ->
    cond = (from_net CFG) "inconnu"
    assert.is_false (cond.eval { src_ip: "192.168.1.1" })
    assert.is_false (cond.eval { src_ip: "192.168.1.2" })  -- aucun warn dans eval
    assert.equals 1, #warns
    assert.equals "filter_net_unknown", warns[1].action
    assert.equals "from_net", warns[1].condition
    assert.equals "inconnu", warns[1].net

  it "_any et _none inchangés", ->
    any = (from_net CFG) "_any"
    none = (from_net CFG) "_none"
    assert.is_true (any.eval { src_ip: "1.2.3.4" })
    assert.is_false (any.eval {})
    assert.is_true (none.eval {})
    assert.is_false (none.eval { src_ip: "1.2.3.4" })
    assert.equals 0, #warns

describe "to_net — alias de filter.nets", ->
  it "groupe résolu sur dst_ip", ->
    cond = (to_net CFG) "lan"
    assert.is_true (cond.eval { dst_ip: "10.1.2.3" })
    assert.is_false (cond.eval { dst_ip: "203.0.113.1" })

  it "nom inconnu : avertissement from_net/to_net distinct", ->
    cond = (to_net CFG) "inconnu"
    assert.is_false (cond.eval { dst_ip: "10.1.2.3" })
    assert.equals 1, #warns
    assert.equals "filter_net_unknown", warns[1].action
    assert.equals "to_net", warns[1].condition

describe "capabilities nft des alias", ->
  it "alias vers un seul CIDR : nft conservé", ->
    cond = (from_net CFG) "single"
    assert.is_true cond.capabilities.nft
    expr, err = cond.compile_nft "ip"
    assert.equals "ip saddr 172.16.0.0/12", expr
    assert.is_nil err

  it "alias multi-CIDR : worker-only (nft false)", ->
    cond = (from_net CFG) "lan"
    assert.is_false cond.capabilities.nft
    expr, err = cond.compile_nft "ip"
    assert.is_nil expr
    assert.is_not_nil err

  it "alias mixte IPv4/IPv6 : worker-only (nft false)", ->
    cond = (to_net CFG) "mixed"
    assert.is_false cond.capabilities.nft

  it "from_nets de CIDRs littéraux : comportement nft inchangé", ->
    factory = compiler_api.load_condition "from_nets"
    cond = factory({}) { "192.168.0.0/16", "10.0.0.0/8" }
    assert.is_true cond.capabilities.nft
    expr, err = cond.compile_nft "ip"
    assert.is_nil err
    assert.truthy expr\find("192.168.0.0/16", 1, true)
    assert.truthy expr\find("10.0.0.0/8", 1, true)

describe "variantes auto-générées héritant des alias", ->
  it "from_nets : un élément peut être un alias", ->
    factory = compiler_api.load_condition "from_nets"
    cond = factory(CFG) { "lan", "8.8.8.0/24" }
    assert.is_true (cond.eval { src_ip: "10.5.0.1" })
    assert.is_true (cond.eval { src_ip: "8.8.8.8" })
    assert.is_false (cond.eval { src_ip: "1.1.1.1" })

  it "from_net_list : une ligne de fichier peut être un alias", ->
    write_file "#{LISTS_DIR}/net/alias.txt", "lan\n8.8.8.0/24\n"
    factory = compiler_api.load_condition "from_net_list"
    cond = factory(CFG) "alias"
    assert.is_true (cond.eval { src_ip: "192.168.1.1" })
    assert.is_true (cond.eval { src_ip: "8.8.8.8" })
    assert.is_false (cond.eval { src_ip: "1.1.1.1" })
    assert.equals 0, #warns

  it "from_net_lists : alias dans un fichier parmi plusieurs", ->
    write_file "#{LISTS_DIR}/net/alias.txt", "lan\n"
    write_file "#{LISTS_DIR}/net/dmz.txt", "172.16.0.0/12\n"
    factory = compiler_api.load_condition "from_net_lists"
    cond = factory(CFG) { "alias", "dmz" }
    assert.is_true (cond.eval { src_ip: "10.5.0.1" })
    assert.is_true (cond.eval { src_ip: "172.16.0.1" })
    assert.is_false (cond.eval { src_ip: "1.1.1.1" })
