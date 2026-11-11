-- tests/unit/filter/localnets_spec.moon
-- Couvre get_bridge_ifname (deux formes d'argument + repli "br0") et
-- inject_localnets : parsing des routes ip -4/-6 (seuils de masque) et ajout
-- des CIDR locaux à la whitelist.

{ :get_bridge_ifname, :inject_localnets } = require "filter.localnets"

describe "filter.localnets.get_bridge_ifname", ->
  it "lit bridge_ifname au niveau racine (config auth directe)", ->
    assert.equals "br-lan", get_bridge_ifname { bridge_ifname: "br-lan" }

  it "lit bridge_ifname sous .auth (config filtre)", ->
    assert.equals "br-lan", get_bridge_ifname { auth: { bridge_ifname: "br-lan" } }

  it "préfère la racine si les deux sont présents", ->
    assert.equals "br0root", get_bridge_ifname {
      bridge_ifname: "br0root"
      auth: { bridge_ifname: "br-nested" }
    }

  it "retombe sur br0 si rien n'est fourni", ->
    assert.equals "br0", get_bridge_ifname {}
    assert.equals "br0", get_bridge_ifname nil
    assert.equals "br0", get_bridge_ifname { auth: {} }

describe "filter.localnets.inject_localnets", ->
  orig_popen = io.popen
  cmds = {}

  before_each ->
    cmds = {}
    io.popen = (cmd) ->
      cmds[#cmds + 1] = cmd
      {
        lines: -> (-> nil)
        close: -> true
      }

  after_each ->
    io.popen = orig_popen

  -- Remplace le stub popen de before_each par des sorties de routes simulées.
  fake_routes = (v4, v6) ->
    io.popen = (cmd) ->
      cmds[#cmds + 1] = cmd
      out = if cmd\find "ip -4", 1, true then v4 else v6
      rows = {}
      for line in ((out or "") .. "\n")\gmatch "([^\n]*)\n"
        rows[#rows + 1] = line
      idx = 0
      {
        lines: ->
          ->
            idx += 1
            rows[idx]
        close: -> true
      }

  it "quote l'interface dans les commandes ip -4/-6 route", ->
    inject_localnets { allow_localnets: true, bridge_ifname: "br0; touch /x" }, {}
    assert.equals 2, #cmds
    assert.truthy cmds[1]\find "dev 'br0; touch /x'", 1, true
    assert.truthy cmds[2]\find "dev 'br0; touch /x'", 1, true

  it "ajoute les CIDR v4 (masque ≥ 8) puis v6 (masque ≥ 48)", ->
    fake_routes [[
10.35.1.0/24 dev br0 proto kernel scope link src 10.35.1.254
169.254.0.0/16 dev br0 scope link metric 1000
]], [[
2a01:db8:1::/64 dev br0 proto kernel metric 256 pref medium
fe80::/64 dev br0 proto kernel metric 256 pref medium
]]
    whitelist = { "1.1.1.1" }
    inject_localnets { allow_localnets: true, bridge_ifname: "br0" }, whitelist
    assert.same { "1.1.1.1", "10.35.1.0/24", "169.254.0.0/16", "2a01:db8:1::/64", "fe80::/64" }, whitelist

  it "ignore les routes hors seuil (v4 < /8, v6 < /48)", ->
    fake_routes [[
0.0.0.0/0 dev br0 proto static
]], [[
::/0 dev br0 proto static
]]
    whitelist = {}
    inject_localnets { allow_localnets: true, bridge_ifname: "br0" }, whitelist
    assert.equals 0, #whitelist

  it "ignore les lignes sans CIDR", ->
    fake_routes "default via 10.0.0.1 dev br0\n", "unreachable default metric 4278198272\n"
    whitelist = {}
    inject_localnets { allow_localnets: true, bridge_ifname: "br0" }, whitelist
    assert.equals 0, #whitelist

  it "allow_localnets faux ou absent → aucune commande, whitelist intacte", ->
    whitelist = { "8.8.8.8" }
    inject_localnets { bridge_ifname: "br0" }, whitelist
    inject_localnets { allow_localnets: false, bridge_ifname: "br0" }, whitelist
    inject_localnets nil, whitelist
    assert.equals 0, #cmds
    assert.same { "8.8.8.8" }, whitelist
