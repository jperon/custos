-- tests/unit/filter/conditions_spec.moon
-- Busted spec pour les conditions filter : any_of, to_net, from_subnet,
-- stolen_computer, from_user. Charge depuis lua/ pour alimenter luacov.

-- Stubs avant tout require de module de production
package.loaded["ipc"] or= { register_modifier: -> nil }
package.loaded["dns_ede"] or= {
  strip_dns_rr: (raw, _t) -> raw
  add_ede_modified: (raw, _r) -> raw
  clear_ad_bit: (raw) -> raw
}
-- auth.sessions stub avec contrôle pour from_user
_auth_sessions_stub = {
  session_for_mac:   -> nil
  enrich_session_ip: -> nil
  bind_session_mac:  -> nil
  user_for_mac:      -> nil
  reset_cache:       ->
}
package.loaded["auth.sessions"] = _auth_sessions_stub
package.loaded["auth.user_sessions"] = { get_session: -> nil }
package.loaded["mac_learner_ipc"] = { get_mac: -> nil }

describe "filter.conditions.to_domain (NCSI/MSFT)", ->
  to_domain_factory = (require "filter.conditions.to_domain").factory
  cfg = {}

  it "msftncsi.com matche la sonde DNS dns.msftncsi.com (suffixe)", ->
    cond = (to_domain_factory cfg) "msftncsi.com"
    ok = cond.eval { domain: "dns.msftncsi.com" }
    assert.is_true ok

  it "msftncsi.com matche la sonde HTTP héritée www.msftncsi.com", ->
    cond = (to_domain_factory cfg) "msftncsi.com"
    ok = cond.eval { domain: "www.msftncsi.com" }
    assert.is_true ok

  it "msftconnecttest.com matche www.msftconnecttest.com et ipv6.msftconnecttest.com", ->
    cond = (to_domain_factory cfg) "msftconnecttest.com"
    assert.is_true (cond.eval { domain: "www.msftconnecttest.com" })
    assert.is_true (cond.eval { domain: "ipv6.msftconnecttest.com" })

  it "ne matche pas un domaine voisin non couvert", ->
    cond = (to_domain_factory cfg) "msftncsi.com"
    ok = cond.eval { domain: "evil-msftncsi.com.attacker.test" }
    assert.is_false ok

describe "filter.conditions.any_of", ->
  any_of_factory = (require "filter.conditions.any_of").factory
  cfg = { nft: { ip_timeout: "2m" } }

  it "OU logique : retourne true si la première sous-condition passe", ->
    cond = (any_of_factory cfg) {
      { from_vlan: 1 }
      { from_vlan: 2 }
    }
    v, _ = cond.eval { vlan: 1 }
    assert.is_true v

  it "OU logique : retourne true si la deuxième sous-condition passe", ->
    cond = (any_of_factory cfg) {
      { from_vlan: 1 }
      { from_vlan: 2 }
    }
    v, _ = cond.eval { vlan: 2 }
    assert.is_true v

  it "retourne false si aucune sous-condition ne passe", ->
    cond = (any_of_factory cfg) {
      { from_vlan: 1 }
      { from_vlan: 2 }
    }
    v, msg = cond.eval { vlan: 99 }
    assert.is_false v
    assert.is_not_nil msg

  it "table vide → false", ->
    cond = (any_of_factory cfg) {}
    v, _ = cond.eval { vlan: 1 }
    assert.is_false v

  it "nil → false", ->
    cond = (any_of_factory cfg) nil
    v, _ = cond.eval {}
    assert.is_false v

  it "capabilities : worker=true, nft=false", ->
    cond = (any_of_factory cfg) { { from_vlan: 1 } }
    assert.is_true cond.capabilities.worker
    assert.is_false cond.capabilities.nft

  it "creates_dynamic_scope hérité si sous-condition a dns scope", ->
    cond = (any_of_factory cfg) {
      { to_domain: "example.com" }
    }
    assert.is_true cond.creates_dynamic_scope

  it "creates_dynamic_scope false si pas de sous-condition dns", ->
    cond = (any_of_factory cfg) {
      { from_vlan: 1 }
    }
    assert.is_false (not not cond.creates_dynamic_scope)

describe "filter.conditions.to_net", ->
  to_net_factory = (require "filter.conditions.to_net").factory
  cfg = {}

  it "_any → true si dst_ip présente", ->
    cond = (to_net_factory cfg) "_any"
    v, _ = cond.eval { dst_ip: "8.8.8.8" }
    assert.is_true v

  it "_any → false si dst_ip absente", ->
    cond = (to_net_factory cfg) "_any"
    v, _ = cond.eval {}
    assert.is_false v

  it "_none → true si dst_ip absente", ->
    cond = (to_net_factory cfg) "_none"
    v, _ = cond.eval {}
    assert.is_true v

  it "_none → false si dst_ip présente", ->
    cond = (to_net_factory cfg) "_none"
    v, _ = cond.eval { dst_ip: "8.8.8.8" }
    assert.is_false v

  it "IPv4 CIDR : match", ->
    cond = (to_net_factory cfg) "8.8.8.0/24"
    v, _ = cond.eval { dst_ip: "8.8.8.8" }
    assert.is_true v

  it "IPv4 CIDR : non-match", ->
    cond = (to_net_factory cfg) "8.8.8.0/24"
    v, _ = cond.eval { dst_ip: "1.1.1.1" }
    assert.is_false v

  it "IPv4 CIDR : dst_ip absente → false", ->
    cond = (to_net_factory cfg) "10.0.0.0/8"
    v, _ = cond.eval {}
    assert.is_false v

  it "CIDR invalide → false toujours", ->
    cond = (to_net_factory cfg) "not_a_cidr/99"
    v, _ = cond.eval { dst_ip: "10.0.0.1" }
    assert.is_false v

  it "IPv4 CIDR compile_nft family ip", ->
    cond = (to_net_factory cfg) "10.0.0.0/8"
    expr, err = cond.compile_nft "ip"
    assert.equals "ip daddr 10.0.0.0/8", expr
    assert.is_nil err

  it "IPv4 CIDR compile_nft family ip6 → erreur", ->
    cond = (to_net_factory cfg) "10.0.0.0/8"
    expr, err = cond.compile_nft "ip6"
    assert.is_nil expr
    assert.is_not_nil err

  it "IPv6 CIDR compile_nft family inet6", ->
    cond = (to_net_factory cfg) "2001:db8::/32"
    expr, err = cond.compile_nft "inet6"
    assert.equals "ip6 daddr 2001:db8::/32", expr
    assert.is_nil err

  it "IPv6 CIDR compile_nft family ip → erreur cross-family", ->
    cond = (to_net_factory cfg) "2001:db8::/32"
    expr, err = cond.compile_nft "ip"
    assert.is_nil expr
    assert.is_not_nil err

describe "filter.conditions.from_subnet", ->
  from_subnet_factory = (require "filter.conditions.from_subnet").factory
  cfg = {}

  it "syntaxe string : match", ->
    cond = (from_subnet_factory cfg) "192.168.0.0/16"
    v, _ = cond.eval { src_ip: "192.168.1.42" }
    assert.is_true v

  it "syntaxe string : non-match", ->
    cond = (from_subnet_factory cfg) "192.168.0.0/16"
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_false v

  it "syntaxe table {net:...} : match", ->
    cond = (from_subnet_factory cfg) { net: "10.0.0.0/8" }
    v, _ = cond.eval { src_ip: "10.5.3.1" }
    assert.is_true v

  it "syntaxe table {net:...} : non-match", ->
    cond = (from_subnet_factory cfg) { net: "10.0.0.0/8" }
    v, _ = cond.eval { src_ip: "192.168.1.1" }
    assert.is_false v

  it "nil spec → false", ->
    cond = (from_subnet_factory cfg) nil
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_false v

  it "table sans net → false", ->
    cond = (from_subnet_factory cfg) { something: "else" }
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_false v

  it "CIDR invalide → false", ->
    cond = (from_subnet_factory cfg) "invalid/cidr"
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_false v

  it "src_ip absente → false", ->
    cond = (from_subnet_factory cfg) "10.0.0.0/8"
    v, _ = cond.eval {}
    assert.is_false v

  it "compile_nft IPv4 family ip", ->
    cond = (from_subnet_factory cfg) "10.0.0.0/8"
    expr, err = cond.compile_nft "ip"
    assert.equals "ip saddr 10.0.0.0/8", expr
    assert.is_nil err

  it "compile_nft IPv4 family ip6 → erreur cross-family", ->
    cond = (from_subnet_factory cfg) "10.0.0.0/8"
    expr, err = cond.compile_nft "ip6"
    assert.is_nil expr
    assert.is_not_nil err

  it "compile_nft IPv6 family inet6", ->
    cond = (from_subnet_factory cfg) "2001:db8::/32"
    expr, err = cond.compile_nft "inet6"
    assert.equals "ip6 saddr 2001:db8::/32", expr
    assert.is_nil err

describe "filter.conditions.stolen_computer", ->
  stolen_factory = (require "filter.conditions.stolen_computer").factory
  cfg = {}

  it "MAC dans la blacklist → true", ->
    cond = (stolen_factory cfg) { "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66" }
    v, msg = cond.eval { mac: "AA:BB:CC:DD:EE:FF" }
    assert.is_true v
    assert.is_not_nil msg

  it "MAC absente de la blacklist → false", ->
    cond = (stolen_factory cfg) { "aa:bb:cc:dd:ee:ff" }
    v, _ = cond.eval { mac: "00:11:22:33:44:55" }
    assert.is_false v

  it "req.mac absent → false", ->
    cond = (stolen_factory cfg) { "aa:bb:cc:dd:ee:ff" }
    v, _ = cond.eval {}
    assert.is_false v

  it "table invalide (non-table) → false", ->
    cond = (stolen_factory cfg) "not_a_table"
    v, _ = cond.eval { mac: "aa:bb:cc:dd:ee:ff" }
    assert.is_false v

  it "compile_nft génère expression multi-MAC", ->
    cond = (stolen_factory cfg) { "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66" }
    expr, err = cond.compile_nft "bridge"
    assert.is_not_nil expr
    assert.is_nil err
    assert.is_not_nil expr\find "ether saddr", 1, true
    assert.is_not_nil expr\find "aa:bb:cc:dd:ee:ff", 1, true
    assert.is_not_nil expr\find "11:22:33:44:55:66", 1, true

  it "capabilities : worker=true, nft=true", ->
    cond = (stolen_factory cfg) { "aa:bb:cc:dd:ee:ff" }
    assert.is_true cond.capabilities.worker
    assert.is_true cond.capabilities.nft

describe "filter.conditions.from_user", ->
  from_user_factory = (require "filter.conditions.from_user").factory
  cfg = {
    auth: { sessions_file: "/nonexistent/sessions.lua" }
    nft: {}
  }

  -- auth.sessions stub contrôlé
  setup ->
    package.loaded["auth.sessions"] = _auth_sessions_stub

  it "_none → true si pas de session", ->
    _auth_sessions_stub.session_for_mac = -> nil
    cond = (from_user_factory cfg) "_none"
    v, _ = cond.eval { src_ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:ff" }
    assert.is_true v

  it "_any → false si pas de session", ->
    _auth_sessions_stub.session_for_mac = -> nil
    cond = (from_user_factory cfg) "_any"
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_false v

  it "_any → true si session active", ->
    orig = _auth_sessions_stub.session_for_mac
    _auth_sessions_stub.session_for_mac = -> { user: "alice", mac: "aa:bb:cc:dd:ee:ff" }
    package.loaded["filter.conditions.from_user"] = nil
    local_factory = (require "filter.conditions.from_user").factory
    cond = (local_factory cfg) "_any"
    v, _ = cond.eval { src_ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:ff" }
    assert.is_true v
    _auth_sessions_stub.session_for_mac = orig
    package.loaded["filter.conditions.from_user"] = nil

  it "utilisateur spécifique → false si pas de session", ->
    _auth_sessions_stub.session_for_mac = -> nil
    cond = (from_user_factory cfg) "alice"
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_false v

  it "utilisateur spécifique → true si session correspond", ->
    orig = _auth_sessions_stub.session_for_mac
    _auth_sessions_stub.session_for_mac = -> { user: "alice", mac: "aa:bb:cc:dd:ee:ff" }
    package.loaded["filter.conditions.from_user"] = nil
    local_factory = (require "filter.conditions.from_user").factory
    cond = (local_factory cfg) "alice"
    v, _ = cond.eval { src_ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:ff" }
    assert.is_true v
    _auth_sessions_stub.session_for_mac = orig
    package.loaded["filter.conditions.from_user"] = nil

  it "source tls : get_session nil → false", ->
    package.loaded["auth.user_sessions"] = { get_session: -> nil }
    cond = (from_user_factory cfg) { user: "bob", source: "tls" }
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_false v

  it "source tls : session présente → true", ->
    package.loaded["auth.user_sessions"] = {
      get_session: (user) ->
        return { src_ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:ff" } if user == "bob"
        nil
    }
    package.loaded["filter.conditions.from_user"] = nil
    local_factory = (require "filter.conditions.from_user").factory
    cond = (local_factory cfg) { user: "bob", source: "tls" }
    v, _ = cond.eval { src_ip: "10.0.0.1" }
    assert.is_true v
    package.loaded["auth.user_sessions"] = { get_session: -> nil }
    package.loaded["filter.conditions.from_user"] = nil

  it "user nil → false", ->
    cond = (from_user_factory cfg) { source: "tls" }
    v, _ = cond.eval {}
    assert.is_false v

  it "capabilities : requires_auth=true", ->
    cond = (from_user_factory cfg) "_any"
    assert.is_true cond.capabilities.requires_auth
    assert.is_false cond.capabilities.nft
