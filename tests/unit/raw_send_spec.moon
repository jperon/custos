-- tests/unit/raw_send_spec.moon
-- Tests unitaires de raw_send. Les sockets RAW exigent CAP_NET_RAW (indisponible
-- en CI non-root) : on vérifie le chargement, l'API et la robustesse aux entrées
-- invalides (sans privilège ni réseau).

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

rs = require "raw_send"

describe "raw_send", ->
  it "expose l'API attendue", ->
    assert.is_function rs.open
    assert.is_function rs.send
    assert.is_function rs.routable

  describe "send", ->
    it "renvoie false sur entrées nil", ->
      assert.is_false rs.send nil, 4, "pkt", "1.2.3.4"
      assert.is_false rs.send 3, 4, nil, "1.2.3.4"
      assert.is_false rs.send 3, 4, "pkt", nil

    it "renvoie false sur IP destination invalide", ->
      assert.is_false rs.send 3, 4, "pkt", "pas-une-ip"

  describe "routable", ->
    it "renvoie false sur IP invalide ou nil", ->
      assert.is_false rs.routable 4, nil
      assert.is_false rs.routable 4, "pas-une-ip"
