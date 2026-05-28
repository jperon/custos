-- tests/unit/doh_config_spec.moon
-- Vérifie la nomenclature cert/key (pas cert_path/key_path) et la normalisation
-- des champs DoH dans config.moon et la logique de main.moon.

ffi = require "ffi"
pcall ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]]

reload = (path) ->
  package.loaded["config"] = nil
  if path
    ffi.C.setenv "CUSTOS_CONFIG_PATH", path, 1
  else
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
  require "config"

write_moon = (path, content) ->
  f = assert io.open path, "w"
  f\write content
  f\close!

-- Reproduit la normalisation de src/main.moon (run_doh_worker).
normalize_doh_paths = (doh) ->
  {
    cert: if doh.cert and #doh.cert > 0 then doh.cert else nil
    key:  if doh.key  and #doh.key  > 0 then doh.key  else nil
  }

-- ── Defaults ──────────────────────────────────────────────────────────────────

describe "config.doh — valeurs par défaut", ->

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  it "cert est nil par défaut", ->
    cfg = reload nil
    assert.is_nil cfg.doh.cert

  it "key est nil par défaut", ->
    cfg = reload nil
    assert.is_nil cfg.doh.key

  it "cert_path n'existe plus (renommé en cert)", ->
    cfg = reload nil
    assert.is_nil cfg.doh.cert_path

  it "key_path n'existe plus (renommé en key)", ->
    cfg = reload nil
    assert.is_nil cfg.doh.key_path

  it "prefer_ipv6 est un booléen", ->
    cfg = reload nil
    assert.is_true type(cfg.doh.prefer_ipv6) == "boolean"

  it "prefer_ipv6 vaut true par défaut", ->
    cfg = reload nil
    assert.is_true cfg.doh.prefer_ipv6

  it "enabled vaut true par défaut", ->
    cfg = reload nil
    assert.is_true cfg.doh.enabled

  it "port vaut 8443 par défaut", ->
    cfg = reload nil
    assert.equals 8443, cfg.doh.port

-- ── Fusion config externe ─────────────────────────────────────────────────────

describe "config.doh — fusion avec config externe", ->

  after_each ->
    ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
    package.loaded["config"] = nil

  it "cert et key sont propagés depuis la config externe", ->
    path = "tmp/doh_config_spec_cert.moon"
    write_moon path, [[{ doh: { cert: "/etc/ssl/my.pem", key: "/etc/ssl/my.key" } }]]
    cfg = reload path
    os.remove path
    assert.equals "/etc/ssl/my.pem", cfg.doh.cert
    assert.equals "/etc/ssl/my.key", cfg.doh.key

  it "prefer_ipv6: false dans config externe → false après normalize", ->
    path = "tmp/doh_config_spec_ipv6.moon"
    write_moon path, [[{ doh: { prefer_ipv6: false } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.doh.prefer_ipv6

  it "prefer_ipv6: 'false' (string) → false après coerce_boolean", ->
    path = "tmp/doh_config_spec_str.moon"
    write_moon path, [[{ doh: { prefer_ipv6: "false" } }]]
    cfg = reload path
    os.remove path
    assert.is_false cfg.doh.prefer_ipv6

-- ── Normalisation chemins (logique main.moon) ─────────────────────────────────

describe "normalize_doh_paths — coerce cert/key vers nil si vide", ->

  it "chemins non-vides → conservés", ->
    r = normalize_doh_paths { cert: "/etc/ssl/c.pem", key: "/etc/ssl/k.key" }
    assert.equals "/etc/ssl/c.pem", r.cert
    assert.equals "/etc/ssl/k.key", r.key

  it "nil → nil", ->
    r = normalize_doh_paths { cert: nil, key: nil }
    assert.is_nil r.cert
    assert.is_nil r.key

  it "chaîne vide → nil (évite de tenter d'ouvrir un fichier vide)", ->
    r = normalize_doh_paths { cert: "", key: "" }
    assert.is_nil r.cert
    assert.is_nil r.key

  it "cert présent mais key absent → key nil", ->
    r = normalize_doh_paths { cert: "/etc/ssl/c.pem", key: nil }
    assert.equals "/etc/ssl/c.pem", r.cert
    assert.is_nil r.key
