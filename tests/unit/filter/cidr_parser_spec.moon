-- tests/unit/filter/cidr_parser_spec.moon
-- Busted spec pour filter.lib.cidr_parser.

describe "filter.lib.cidr_parser", ->
  { :parse_cidr, :parse_ipv4_cidr, :parse_ipv6_cidr, :validate_cidr, :format_cidr } = require "filter.lib.cidr_parser"

  describe "parse_ipv4_cidr", ->
    it "CIDR IPv4 standard", ->
      r = parse_ipv4_cidr "192.168.0.0/24"
      assert.is_not_nil r
      assert.equals "inet", r.family
      assert.equals 24, r.prefix
      assert.equals "192.168.0.0", r.net
      assert.is_true r.is_valid

    it "host unique /32", ->
      r = parse_ipv4_cidr "10.0.0.1/32"
      assert.is_not_nil r
      assert.equals 32, r.prefix

    it "préfixe /0", ->
      r = parse_ipv4_cidr "0.0.0.0/0"
      assert.is_not_nil r
      assert.equals 0, r.prefix

    it "sans masque → /32 implicite", ->
      r = parse_ipv4_cidr "10.0.0.1"
      assert.is_not_nil r
      assert.equals 32, r.prefix

    it "nil → nil", ->
      assert.is_nil parse_ipv4_cidr nil

    it "chaîne vide → nil", ->
      assert.is_nil parse_ipv4_cidr ""

    it "IPv6 → nil (mauvaise famille)", ->
      assert.is_nil parse_ipv4_cidr "::1/128"

    it "préfixe > 32 → nil", ->
      assert.is_nil parse_ipv4_cidr "10.0.0.0/33"

    it "octet hors plage → nil", ->
      assert.is_nil parse_ipv4_cidr "256.0.0.0/8"

    it "format invalide → nil", ->
      assert.is_nil parse_ipv4_cidr "not_an_ip/24"

  describe "parse_ipv6_cidr", ->
    it "CIDR IPv6 standard", ->
      r = parse_ipv6_cidr "2001:db8::/32"
      assert.is_not_nil r
      assert.equals "inet6", r.family
      assert.equals 32, r.prefix
      assert.is_true r.is_valid

    it "loopback /128", ->
      r = parse_ipv6_cidr "::1/128"
      assert.is_not_nil r
      assert.equals 128, r.prefix

    it "sans masque → /128 implicite", ->
      r = parse_ipv6_cidr "::1"
      assert.is_not_nil r
      assert.equals 128, r.prefix

    it "nil → nil", ->
      assert.is_nil parse_ipv6_cidr nil

    it "IPv4 → nil (mauvaise famille)", ->
      assert.is_nil parse_ipv6_cidr "192.168.0.0/16"

    it "préfixe > 128 → nil", ->
      assert.is_nil parse_ipv6_cidr "::1/129"

  describe "parse_cidr", ->
    it "détecte auto IPv4", ->
      r = parse_cidr "10.0.0.0/8"
      assert.is_not_nil r
      assert.equals "inet", r.family

    it "détecte auto IPv6", ->
      r = parse_cidr "fc00::/7"
      assert.is_not_nil r
      assert.equals "inet6", r.family

    it "nil → nil", ->
      assert.is_nil parse_cidr nil

  describe "validate_cidr", ->
    it "CIDR valide → true, nil", ->
      ok, err = validate_cidr "192.168.0.0/24"
      assert.is_true ok
      assert.is_nil err

    it "CIDR invalide → false, message d'erreur", ->
      ok, err = validate_cidr "invalid"
      assert.is_false ok
      assert.is_not_nil err

  describe "format_cidr", ->
    it "formate un objet parsé", ->
      r = parse_cidr "10.0.0.0/8"
      s = format_cidr r
      assert.equals "10.0.0.0/8", s

    it "nil → nil", ->
      assert.is_nil format_cidr nil
