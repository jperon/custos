-- tests/unit/doh/upstream_doh_curl_spec.moon
-- Tests de doh.upstream_doh_curl.
-- new_client et close sont testés directement.
-- query est testée via des URLs qui échouent immédiatement (sans réseau externe),
-- ce qui couvre le chemin d'erreur curl et la gestion du code retour.

eval_log = (f) -> (type(f) == "function") and f!
package.loaded["log"] = { log_debug: eval_log, log_warn: eval_log }

load_mod = ->
  package.loaded["doh.upstream_doh_curl"] = nil
  require "doh.upstream_doh_curl"

describe "doh.upstream_doh_curl", ->

  describe "new_client", ->

    it "retourne un handle avec les bons champs", ->
      mod = load_mod!
      h = mod.new_client "https://9.9.9.9/dns-query", 1500, true
      assert.equals "https://9.9.9.9/dns-query", h.url
      assert.equals 1500,                         h.timeout_ms
      assert.is_true                              h.verify_tls
      assert.equals mod,                          h._mod

    it "valeurs par défaut : timeout 2000, verify_tls false", ->
      mod = load_mod!
      h = mod.new_client "https://1.1.1.1/dns-query"
      assert.equals 2000,  h.timeout_ms
      assert.is_false      h.verify_tls

  describe "close", ->

    it "ne plante pas sur un handle valide", ->
      mod = load_mod!
      h = mod.new_client "https://9.9.9.9/dns-query"
      assert.has_no_error -> mod.close h

    it "ne plante pas sur nil", ->
      mod = load_mod!
      assert.has_no_error -> mod.close nil

  describe "query", ->

    it "URL injoignable → nil + message d'erreur curl", ->
      -- Port 1 est réservé et refusé immédiatement : pas de réseau externe requis.
      mod = load_mod!
      h = mod.new_client "https://127.0.0.1:1/dns-query", 500
      body, err = mod.query h, "dns_raw"
      assert.is_nil body
      assert.is_not_nil err
      assert.truthy err\find "upstream_doh_curl", 1, true

    it "URL invalide → nil + erreur", ->
      mod = load_mod!
      h = mod.new_client "https://this.domain.does.not.exist.invalid/dns-query", 500
      body, err = mod.query h, "dns_raw"
      assert.is_nil body
      assert.is_not_nil err
