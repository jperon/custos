-- tests/unit/auth/nft_auth_sets_spec.moon
-- Tests de auth.nft_auth_sets : sets globaux + per-règle d'authentification.
-- Régressions couvertes :
--   * refresh_nft doit rafraîchir LES DEUX familles de sets (globaux et
--     per-règle) — le découpage handlers/nft_auth_sets avait laissé les sets
--     per-règle expirer malgré les pings, et les sets globaux absents au login ;
--   * le log post-add pour un client IPv4 ne doit pas lever (précédence
--     MoonScript : `ip\find ":" == nil` compilait en `ip\find false`).

config = require "config"
nas = require "auth.nft_auth_sets"

MAC = "aa:bb:cc:11:22:33"
IP4 = "10.42.0.50"
IP6 = "fd00::50"
USER = "alice"
TTL = 300

RULE = {
  description: "test auth rule"
  conditions: { from_users: { USER } }
  actions: { "allow" }
}

make_nft_mock = ->
  calls = { run_nft: {}, add_auth: {}, add_auth_mac: {} }
  mock = {
    :calls
    run_nft: (cmd) -> calls.run_nft[#calls.run_nft + 1] = cmd
    add_authenticated: (ip, ttl) -> calls.add_auth[#calls.add_auth + 1] = { ip, ttl }
    add_authenticated_mac: (mac, ttl) -> calls.add_auth_mac[#calls.add_auth_mac + 1] = { mac, ttl }
  }
  mock

describe "auth.nft_auth_sets", ->
  original_filter = config.filter

  before_each ->
    config.filter = { rules: { RULE } }

  after_each ->
    config.filter = original_filter

  describe "auth_set_names", ->
    it "retourne le set ip4 pour une IPv4", ->
      mac_set, ip_set = nas.auth_set_names IP4
      assert.equals "_auth_mac", mac_set
      assert.equals "_auth_ip4", ip_set

    it "retourne le set ip6 pour une IPv6", ->
      _, ip_set = nas.auth_set_names IP6
      assert.equals "_auth_ip6", ip_set

    it "ne retourne pas de set ip pour une IP inconnue", ->
      mac_set, ip_set = nas.auth_set_names "unknown"
      assert.equals "_auth_mac", mac_set
      assert.is_nil ip_set

  describe "refresh_rule_auth_sets", ->
    it "ajoute mac + ip4 sans lever pour un client IPv4", ->
      mock = make_nft_mock!
      assert.has_no_error -> nas.refresh_rule_auth_sets mock, IP4, MAC, TTL, USER
      assert.equals 2, #mock.calls.run_nft
      assert.truthy mock.calls.run_nft[1]\find "_auth_mac", 1, true
      assert.truthy mock.calls.run_nft[2]\find "_auth_ip4", 1, true
      assert.truthy mock.calls.run_nft[1]\find "timeout #{TTL}s", 1, true

    it "ajoute mac + ip6 sans lever pour un client IPv6", ->
      mock = make_nft_mock!
      assert.has_no_error -> nas.refresh_rule_auth_sets mock, IP6, MAC, TTL, USER
      assert.equals 2, #mock.calls.run_nft
      assert.truthy mock.calls.run_nft[2]\find "_auth_ip6", 1, true

    it "n'ajoute rien pour un utilisateur non qualifié", ->
      mock = make_nft_mock!
      nas.refresh_rule_auth_sets mock, IP4, MAC, TTL, "mallory"
      assert.equals 0, #mock.calls.run_nft

  describe "refresh_nft", ->
    it "rafraîchit les sets globaux ET per-règle", ->
      mock = make_nft_mock!
      nas.refresh_nft mock, IP4, MAC, TTL, USER
      assert.equals 1, #mock.calls.add_auth
      assert.equals 1, #mock.calls.add_auth_mac
      assert.equals TTL, mock.calls.add_auth[1][2]
      assert.equals 2, #mock.calls.run_nft, "les sets per-règle doivent aussi être rafraîchis"

    it "saute les sets ip globaux quand l'IP est inconnue", ->
      mock = make_nft_mock!
      nas.refresh_nft mock, "unknown", MAC, TTL, USER
      assert.equals 0, #mock.calls.add_auth
      assert.equals 1, #mock.calls.add_auth_mac
      assert.equals 1, #mock.calls.run_nft  -- per-règle : mac seulement

  describe "delete_rule_auth_sets", ->
    it "supprime les éléments per-règle sans timeout", ->
      mock = make_nft_mock!
      nas.delete_rule_auth_sets mock, IP4, MAC, USER
      assert.equals 2, #mock.calls.run_nft
      assert.truthy mock.calls.run_nft[1]\find "delete element", 1, true
      assert.is_nil mock.calls.run_nft[1]\find "timeout", 1, true
