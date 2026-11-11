-- tests/unit/doh/upstream_select_spec.moon
-- Sélection du transport DoH amont : curl (normal) puis wolfSSL (repli).
-- Aucune I/O réseau, aucun chargement réel de libcurl/libwolfssl : les modules
-- sont injectés via package.loaded ou un require_fn de test.

warns = {}
infos = {}

eval_log = (f) -> (type(f) == "function") and f!

package.loaded["log"] = {
  log_info: (f) -> infos[#infos + 1] = eval_log(f)
  log_warn: (f) -> warns[#warns + 1] = eval_log(f)
  log_debug: eval_log
}

reset_logs = ->
  warns = {}
  infos = {}

-- Stub de doh.upstream_doh_curl.
make_curl_stub = (probe_ok=true, probe_err=nil) ->
  calls = { new: 0, query: 0, close: 0 }
  mod = {}
  mod.probe = ->
    return false, probe_err if not probe_ok
    true
  mod.new_client = (url, timeout_ms, verify_tls) ->
    calls.new += 1
    { url: url, timeout_ms: timeout_ms, verify_tls: verify_tls, _mod: mod }
  mod.query = (client, raw) ->
    calls.query += 1
    nil, "curl_query_timeout"
  mod.close = (client) ->
    calls.close += 1
  mod, calls

-- Stub de doh.upstream_doh.
make_wolf_stub = (verify_ok=true, verify_why=nil, ca="/etc/ssl/certs/ca-certificates.crt") ->
  calls = { new: 0 }
  mod = {}
  mod.verification_available = (opts) ->
    return false, verify_why or "pas de magasin de CA", nil unless verify_ok
    true, nil, ca
  mod.new_client = (url, timeout_ms, verify_tls, opts) ->
    calls.new += 1
    { url: url, timeout_ms: timeout_ms, verify_tls: verify_tls,
      ca_file: opts and opts.ca_file, _mod: mod }
  mod.query = (client, raw) -> "stub_dns_response", nil
  mod.close = (->)
  mod, calls

-- require_fn de test : erreurs configurables par module.
make_require = (curl_mod, wolf_mod, curl_err=nil, wolf_err=nil) ->
  (name) ->
    switch name
      when "doh.upstream_doh_curl"
        error curl_err if curl_err
        curl_mod
      when "doh.upstream_doh"
        error wolf_err if wolf_err
        wolf_mod
      else
        error "unexpected require #{name}"

load_select = ->
  package.loaded["doh.upstream_select"] = nil
  require "doh.upstream_select"

select = (opts, curl_mod, wolf_mod, curl_err, wolf_err) ->
  mod = load_select!
  mod.select opts, { require_fn: make_require curl_mod, wolf_mod, curl_err, wolf_err }

base_opts = {
  url: "https://1.1.1.1/dns-query"
  timeout_ms: 2000
  verify_tls: true
  fallback_insecure: false
  role: "upstream"
}

fallback_warns = ->
  [w for w in *warns when w and w.action == "doh_upstream_fallback_wolfssl"]

describe "doh.upstream_select", ->

  before_each -> reset_logs!

  describe "transport normal (curl)", ->

    it "curl disponible → transport curl, aucun repli", ->
      curl, ccalls = make_curl_stub true
      wolf, _ = make_wolf_stub!
      desc = select base_opts, curl, wolf
      assert.equals "curl", desc.transport
      assert.is_true desc.verify_tls
      assert.equals 0, #fallback_warns!
      assert.equals 1, #infos
      assert.equals "upstream_doh_curl_enabled", infos[1].action

    it "curl disponible → make_client délègue à curl avec verify_tls", ->
      curl, ccalls = make_curl_stub true
      wolf, wcalls = make_wolf_stub!
      desc = select base_opts, curl, wolf
      client = desc.make_client "https://9.9.9.9/dns-query", 1500, desc.verify_tls
      assert.equals 1, ccalls.new
      assert.equals 0, wcalls.new
      assert.is_true client.verify_tls

    it "une erreur de requête curl ne déclenche PAS le repli", ->
      curl, ccalls = make_curl_stub true
      wolf, wcalls = make_wolf_stub!
      desc = select base_opts, curl, wolf
      client = desc.make_client base_opts.url, 2000, desc.verify_tls
      body, err = curl.query client, "dns_raw"
      assert.is_nil body
      assert.truthy err\find "curl_query_timeout", 1, true
      assert.equals "curl", desc.transport
      assert.equals 0, wcalls.new
      assert.equals 0, #fallback_warns!

  describe "repli wolfSSL", ->

    it "échec de chargement libcurl (ffi.load) → repli wolfSSL, un seul warn", ->
      wolf, wcalls = make_wolf_stub true
      desc = select base_opts, nil, wolf,
        "upstream_doh_curl: libcurl introuvable (curl / libcurl.so.4)"
      assert.equals "wolfssl", desc.transport
      assert.is_true desc.verify_tls
      assert.equals 1, #fallback_warns!
      w = fallback_warns![1]
      assert.truthy tostring(w.reason)\find "libcurl introuvable", 1, true
      assert.is_true w.verify_tls
      client = desc.make_client base_opts.url, 2000
      assert.equals 1, wcalls.new
      assert.is_true client.verify_tls

    it "échec de curl_easy_init (probe) → repli wolfSSL", ->
      curl, _ = make_curl_stub false, "curl_easy_init_failed"
      wolf, _ = make_wolf_stub true
      desc = select base_opts, curl, wolf
      assert.equals "wolfssl", desc.transport
      assert.equals 1, #fallback_warns!
      assert.truthy tostring(fallback_warns![1].reason)\find "curl_easy_init_failed", 1, true

    it "échec de chargement wolfSSL aussi → nil + warn, pas de transport", ->
      desc, err = select base_opts, nil, nil,
        "libcurl introuvable", "libwolfssl not found"
      assert.is_nil desc
      assert.truthy err\find "libcurl introuvable", 1, true
      assert.equals 1, #fallback_warns!
      assert.equals "none", fallback_warns![1].verify_tls

  describe "vérification TLS du repli", ->

    it "repli vérifié quand la lib le permet", ->
      wolf, _ = make_wolf_stub true
      desc = select base_opts, nil, wolf, "libcurl introuvable"
      assert.is_true desc.verify_tls
      client = desc.make_client base_opts.url, 2000
      assert.is_true client.verify_tls
      assert.equals "/etc/ssl/certs/ca-certificates.crt", client.ca_file

    it "vérification impossible + fallback_insecure=false → repli REFUSÉ", ->
      wolf, wcalls = make_wolf_stub false, "symbole wolfSSL_check_domain_name absent"
      desc = select base_opts, nil, wolf, "libcurl introuvable"
      assert.equals "wolfssl_refused", desc.transport
      assert.equals 1, #fallback_warns!
      assert.equals false, fallback_warns![1].verify_tls
      client, err = desc.make_client base_opts.url, 2000
      assert.is_nil client
      assert.truthy err\find "tls_verify_unavailable", 1, true
      assert.equals 0, wcalls.new

    it "vérification impossible + fallback_insecure=true (upstream) → non vérifié accepté + warn", ->
      wolf, _ = make_wolf_stub false, "aucun magasin de CA trouvé"
      opts = {
        url: base_opts.url
        timeout_ms: base_opts.timeout_ms
        verify_tls: base_opts.verify_tls
        role: base_opts.role
        fallback_insecure: true
      }
      desc = select opts, nil, wolf, "libcurl introuvable"
      assert.equals "wolfssl", desc.transport
      assert.is_false desc.verify_tls
      assert.equals 1, #fallback_warns!
      assert.equals false, fallback_warns![1].verify_tls
      assert.truthy tostring(fallback_warns![1].detail)\find "NON vérifié", 1, true
      client = desc.make_client base_opts.url, 2000
      assert.is_false client.verify_tls

    it "validateur : jamais de mode non vérifié, même avec fallback_insecure=true", ->
      wolf, wcalls = make_wolf_stub false, "aucun magasin de CA trouvé"
      opts = { url: base_opts.url, timeout_ms: 2000, verify_tls: true,
               role: "validator", fallback_insecure: true }
      desc = select opts, nil, wolf, "libcurl introuvable"
      assert.equals "wolfssl_refused", desc.transport
      client, err = desc.make_client base_opts.url, 2000
      assert.is_nil client
      assert.truthy err\find "tls_verify_unavailable", 1, true
      assert.equals 0, wcalls.new

    it "validateur : repli vérifié quand la lib le permet", ->
      wolf, _ = make_wolf_stub true
      opts = { url: base_opts.url, timeout_ms: 2000, verify_tls: true,
               role: "validator", fallback_insecure: true }
      desc = select opts, nil, wolf, "libcurl introuvable"
      assert.equals "wolfssl", desc.transport
      assert.is_true desc.verify_tls
