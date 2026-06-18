-- tests/unit/captive_ips_spec.moon
-- Tests de captive_ips.domain_from_url (extraction du hostname du portail).

{ :domain_from_url } = require "captive_ips"

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
