-- tests/unit/filter/ipcalc_spec.moon
-- Bornes de préfixe de parse_net et appartenance ip_in_net (IPv4/IPv6).

describe "filter.lib.ipcalc", ->
  ipcalc = require "filter.lib.ipcalc"

  describe "parse_net — préfixes valides", ->
    it "accepte les bornes IPv4 (/0, /8, /32, sans préfixe)", ->
      for cidr in *{ "0.0.0.0/0", "10.0.0.0/8", "192.168.1.1/32", "10.0.0.1" }
        net = ipcalc.parse_net cidr
        assert.is_not_nil net
        assert.is_false net.is_v6

    it "accepte les bornes IPv6 (/0, /128, sans préfixe)", ->
      for cidr in *{ "::/0", "2001:db8::/32", "2001:db8::1/128", "2001:db8::1" }
        net = ipcalc.parse_net cidr
        assert.is_not_nil net
        assert.is_true net.is_v6

  describe "parse_net — préfixes invalides", ->
    it "rejette un préfixe IPv4 hors bornes", ->
      assert.is_nil ipcalc.parse_net "10.0.0.0/33"
      assert.is_nil ipcalc.parse_net "10.0.0.0/99"

    it "rejette un préfixe IPv6 hors bornes", ->
      assert.is_nil ipcalc.parse_net "fc00::/129"
      assert.is_nil ipcalc.parse_net "fc00::/200"
      assert.is_nil ipcalc.parse_net "::1/999"

  describe "ip_in_net", ->
    it "IPv4 dedans/dehors", ->
      net = ipcalc.parse_net "192.168.0.0/16"
      assert.is_true ipcalc.ip_in_net ipcalc.parse_ip("192.168.1.42"), net
      assert.is_false ipcalc.ip_in_net ipcalc.parse_ip("10.0.0.1"), net

    it "IPv6 dedans/dehors", ->
      net = ipcalc.parse_net "2001:db8::/32"
      assert.is_true ipcalc.ip_in_net ipcalc.parse_ip("2001:db8::1"), net
      assert.is_false ipcalc.ip_in_net ipcalc.parse_ip("2001:db9::1"), net

    it "limite d'octet /20", ->
      net = ipcalc.parse_net "10.0.16.0/20"
      -- 10.0.16.0–10.0.31.255
      assert.is_true ipcalc.ip_in_net ipcalc.parse_ip("10.0.16.0"), net
      assert.is_true ipcalc.ip_in_net ipcalc.parse_ip("10.0.31.255"), net
      assert.is_false ipcalc.ip_in_net ipcalc.parse_ip("10.0.15.255"), net
      assert.is_false ipcalc.ip_in_net ipcalc.parse_ip("10.0.32.0"), net
