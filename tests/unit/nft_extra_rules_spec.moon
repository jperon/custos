-- tests/unit/nft_extra_rules_spec.moon
-- Spec direct de src/nft_extra_rules.moon : init (suppression des occurrences
-- existantes par handle + insertion en position 0), run_cmd, cleanup et
-- apply_from_config (ré-application du ruleset + population de filter_ips4/6).
--
-- Le module crée un contexte libnftables au chargement : on installe un stub
-- ffi_defs le temps du require, puis on restaure le stub partagé de
-- busted_setup (le module garde la référence aux tables capturées, donc les
-- mutations de nft_stub restent visibles sans fuiter vers les autres specs).

ffi = require "ffi"
fake_ctx = ffi.new "char[1]"
nft_rc = 0
nft_cmds = {}

nft_stub = {
  nft_ctx_new: -> fake_ctx
  nft_ctx_free: -> nil
  nft_run_cmd_from_buffer: (ctx, cmd) ->
    nft_cmds[#nft_cmds + 1] = cmd
    nft_rc
}

orig_ffi_defs = package.loaded["ffi_defs"]
package.loaded["ffi_defs"] = {
  :ffi
  libc: ffi.C
  libnfq: {}
  libnft: nft_stub
}
package.loaded["nft_extra_rules"] = nil
nft_extra = require "nft_extra_rules"
if orig_ffi_defs
  package.loaded["ffi_defs"] = orig_ffi_defs
else
  package.loaded["ffi_defs"] = nil

config = require "config"
config.nft.extra_rules = nil
orig_nft_rules = package.loaded["nft_rules"]

-- io.popen factice : répond au `read "*a"` (nft -a list chain) et aux
-- itérateurs `lines!` (ip addr show), selon la commande.
orig_popen = io.popen
orig_execute = os.execute
popen_output = {}
popen_cmds = {}

install_popen = (output_by_substring) ->
  popen_output = output_by_substring
  popen_cmds = {}
  io.popen = (cmd) ->
    popen_cmds[#popen_cmds + 1] = cmd
    out = ""
    for needle, body in pairs popen_output
      if cmd\find needle, 1, true
        out = body
        break
    rows = {}
    for line in (out .. "\n")\gmatch "([^\n]*)\n"
      rows[#rows + 1] = line
    idx = 0
    {
      read: (_n) -> out
      lines: ->
        ->
          idx += 1
          rows[idx]
      close: -> true
    }

reset_nft = ->
  nft_cmds = {}
  nft_rc = 0

describe "nft_extra_rules.run_cmd", ->
  after_each ->
    reset_nft!

  it "succès (rc 0) → true, 0 et commande transmise", ->
    ok, rc = nft_extra.run_cmd "add element bridge t s { 10.0.0.1 }"
    assert.is_true ok
    assert.equals 0, rc
    assert.equals 1, #nft_cmds
    assert.truthy nft_cmds[1]\find "add element bridge", 1, true

  it "échec (rc ≠ 0) → false, rc et warning thunk", ->
    nft_rc = 7
    ok, rc = nft_extra.run_cmd "add element bridge t s { 10.0.0.1 }"
    assert.is_false ok
    assert.equals 7, rc

describe "nft_extra_rules.init", ->
  before_each ->
    reset_nft!
    install_popen {}

  after_each ->
    io.popen = orig_popen
    config.nft.extra_rules = nil

  it "nil ou table vide → true, aucune commande", ->
    assert.is_true nft_extra.init nil
    assert.is_true nft_extra.init {}
    assert.equals 0, #nft_cmds
    assert.equals 0, #popen_cmds

  it "insère chaque règle en position 0, ordre UCI préservé (inversion)", ->
    ok = nft_extra.init {
      "ip saddr 10.0.0.0/8 counter accept"
      "  udp   dport { 123, 5353 }   accept  "
    }
    assert.is_true ok
    assert.equals 2, #nft_cmds
    -- Parcours inverse : la dernière règle est insérée d'abord (donc elle finit
    -- sous la première en tête de chaîne).
    assert.truthy nft_cmds[1]\find "position 0 udp dport { 123, 5353 } accept", 1, true
    assert.truthy nft_cmds[2]\find "position 0 ip saddr 10.0.0.0/8 counter accept", 1, true

  it "ignore les fragments vides ou blancs", ->
    ok = nft_extra.init { "", "   ", "\t\n" }
    assert.is_true ok
    assert.equals 0, #nft_cmds

  it "supprime les occurrences existantes par handle avant d'insérer", ->
    install_popen {
      ["nft -a list chain"]: [[
        ip saddr 10.0.0.0/8 counter accept # handle 12
        ip saddr 10.0.0.0/8 counter accept # handle 34
      ]]
    }
    ok = nft_extra.init { "ip saddr 10.0.0.0/8 counter accept" }
    assert.is_true ok
    assert.equals 3, #nft_cmds
    assert.truthy nft_cmds[1]\find "delete rule bridge dns-filter-bridge forward handle 12", 1, true
    assert.truthy nft_cmds[2]\find "delete rule bridge dns-filter-bridge forward handle 34", 1, true
    assert.truthy nft_cmds[3]\find "insert rule bridge dns-filter-bridge forward position 0", 1, true

  it "une suppression échouée n'empêche pas l'insertion", ->
    install_popen {
      ["nft -a list chain"]: "ip saddr 10.0.0.0/8 accept # handle 99\n"
    }
    -- 1er appel (delete) échoue, le suivant (insert) réussit.
    nft_rc = 1
    orig_run = nft_stub.nft_run_cmd_from_buffer
    nft_stub.nft_run_cmd_from_buffer = (ctx, cmd) ->
      nft_cmds[#nft_cmds + 1] = cmd
      if cmd\find "insert rule", 1, true
        0
      else
        1
    ok = nft_extra.init { "ip saddr 10.0.0.0/8 accept" }
    nft_stub.nft_run_cmd_from_buffer = orig_run
    assert.is_true ok
    assert.equals 2, #nft_cmds

  it "échec d'insertion → false", ->
    nft_rc = 1
    ok = nft_extra.init { "ip saddr 10.0.0.0/8 accept" }
    assert.is_false ok

describe "nft_extra_rules.cleanup", ->
  before_each ->
    reset_nft!
    install_popen {}

  after_each ->
    io.popen = orig_popen
    config.nft.extra_rules = nil

  it "supprime les règles insérées (handles retrouvés) puis vide son état", ->
    nft_extra.init { "ip saddr 10.0.0.0/8 accept" }
    reset_nft!
    install_popen {
      ["nft -a list chain"]: "ip saddr 10.0.0.0/8 accept # handle 77\n"
    }
    nft_extra.cleanup!
    assert.equals 1, #nft_cmds
    assert.truthy nft_cmds[1]\find "handle 77", 1, true

    -- Deuxième cleanup : plus d'état inséré et plus de handle → aucune commande.
    reset_nft!
    install_popen {}
    nft_extra.cleanup!
    assert.equals 0, #nft_cmds

  it "nettoie aussi les fragments encore présents dans la config", ->
    config.nft.extra_rules = { "udp dport 123 accept" }
    install_popen {
      ["nft -a list chain"]: "udp dport 123 accept # handle 5\n"
    }
    nft_extra.cleanup!
    assert.equals 1, #nft_cmds
    assert.truthy nft_cmds[1]\find "handle 5", 1, true

describe "nft_extra_rules.apply_from_config", ->
  before_each ->
    reset_nft!
    config.nft.extra_rules = nil
    package.loaded["nft_rules"] = { apply: -> true }

  after_each ->
    io.popen = orig_popen
    os.execute = orig_execute
    config.nft.extra_rules = nil
    package.loaded["nft_rules"] = orig_nft_rules

  it "chaîne forward présente : pas de ré-application, IPs du filtre + règles", ->
    os.execute = -> true
    install_popen {
      ["ip -4 addr show"]: "    inet 10.0.0.254/24 brd 10.0.0.255 scope global br\n"
      ["ip -6 addr show"]: "    inet6 fe80::1/64 scope link\n    inet6 2a01:db8::1/64 scope global\n"
    }
    config.nft.extra_rules = { "udp dport 123 accept" }
    ok = nft_extra.apply_from_config!
    assert.is_true ok
    joined = table.concat nft_cmds, "\n"
    assert.truthy joined\find "add element bridge dns-filter-bridge filter_ips4 { 10.0.0.254 }", 1, true
    assert.truthy joined\find "add element bridge dns-filter-bridge filter_ips6 { 2a01:db8::1 }", 1, true
    assert.is_nil joined\find "fe80::1", 1, true
    assert.truthy joined\find "insert rule bridge dns-filter-bridge forward position 0 udp dport 123 accept", 1, true
    -- populate_filter_ips est exécuté avant init : 2 adds puis l'insert.
    assert.equals 3, #nft_cmds

  it "chaîne forward absente : ré-applique le ruleset principal", ->
    os.execute = -> nil, "exit", 1
    reapplied = 0
    package.loaded["nft_rules"] = {
      apply: ->
        reapplied += 1
        true, 0
    }
    install_popen {}
    ok = nft_extra.apply_from_config!
    assert.is_true ok
    assert.equals 1, reapplied
    assert.equals 0, #nft_cmds

  it "ré-application échouée → false, aucune insertion", ->
    os.execute = -> nil, "exit", 1
    package.loaded["nft_rules"] = { apply: -> false, 9 }
    install_popen {}
    ok = nft_extra.apply_from_config!
    assert.is_false ok
    assert.equals 0, #nft_cmds
