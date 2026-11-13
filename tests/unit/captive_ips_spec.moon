-- tests/unit/captive_ips_spec.moon
-- Tests de captive_ips.domain_from_url (extraction du hostname du portail).

{ :domain_from_url, :new_detector, :RETRY_INTERVAL } = require "captive_ips"

describe "captive_ips.domain_from_url", ->

  it "extrait le hostname d'une URL https avec port", ->
    assert.equals "custos.example.net", domain_from_url "https://custos.example.net:8443/"

  it "extrait le hostname d'une URL http simple", ->
    assert.equals "portail.lan", domain_from_url "http://portail.lan"

  it "met le hostname en casse basse", ->
    assert.equals "custos.lan", domain_from_url "https://Custos.LAN/login"

  it "renvoie nil pour une IPv4 brute", ->
    assert.is_nil domain_from_url "https://192.168.1.1:8443/"

  it "renvoie nil pour une IPv6 entre crochets", ->
    assert.is_nil domain_from_url "https://[fd00::1]:8443/"

  it "renvoie nil pour une URL nil ou malformée", ->
    assert.is_nil domain_from_url nil
    assert.is_nil domain_from_url "pas-une-url"

describe "captive_ips lazy detection", ->
  local orig_popen, orig_time, orig_socket

  before_each ->
    orig_popen = io.popen
    orig_time = os.time
    orig_socket = package.loaded["socket"]
    -- Désactive le fallback socket pour tester la branche io.popen.
    package.loaded["socket"] = { udp: -> nil }

  after_each ->
    io.popen = orig_popen
    os.time = orig_time
    package.loaded["socket"] = orig_socket

  it "détecte au départ si l'IP est déjà présente", ->
    io.popen = (cmd) ->
      handle = {}
      handle.read = (self, fmt) -> "10.35.1.254\n"
      handle.close = (self) -> true
      handle
    os.time = -> 0
    d = new_detector { bridge_ifname: "br0" }
    ip4, ip6 = d\get!
    assert.equals "10.35.1.254", ip4

  it "retente après l'intervalle si l'IP manquait", ->
    calls = 0
    io.popen = (cmd) ->
      calls += 1
      if calls <= 1
        nil
      else
        handle = {}
        handle.read = (self, fmt) -> "10.35.1.254\n"
        handle.close = (self) -> true
        handle
    os.time = -> 0
    d = new_detector { bridge_ifname: "br0" }
    -- Pas de re-tentative avant l'intervalle.
    ip4, ip6 = d\ensure 5
    assert.is_nil ip4
    -- Après l'intervalle, la détection réussit.
    ip4, ip6 = d\ensure 10
    assert.equals "10.35.1.254", ip4
    assert.is_true calls >= 2

  it "ne retente pas avant l'intervalle", ->
    calls = 0
    io.popen = (cmd) ->
      calls += 1
      nil
    os.time = -> 0
    d = new_detector { bridge_ifname: "br0" }
    first_calls = calls
    d\ensure 1
    d\ensure 5
    d\ensure 9
    -- Aucune nouvelle tentative avant RETRY_INTERVAL.
    assert.equals first_calls, calls

  it "mémorise l'IP et ne la re-détecte pas", ->
    calls = 0
    io.popen = (cmd) ->
      calls += 1
      handle = {}
      handle.read = (self, fmt) -> "10.35.1.254\n"
      handle.close = (self) -> true
      handle
    os.time = -> 0
    d = new_detector { bridge_ifname: "br0" }
    first_calls = calls
    d\ensure 100
    assert.equals first_calls, calls
