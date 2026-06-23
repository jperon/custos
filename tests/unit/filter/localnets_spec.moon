-- tests/unit/filter/localnets_spec.moon
-- Couvre get_bridge_ifname : tolérance aux deux formes d'argument (config auth
-- directe vs config filtre avec auth en sous-table) + repli "br0".

{ :get_bridge_ifname } = require "filter.localnets"

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
