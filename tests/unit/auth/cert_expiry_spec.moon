-- tests/unit/auth/cert_expiry_spec.moon
-- Avertissements d'expiration des certificats statiques : parsing ASN.1 pur,
-- classification, et lecture réelle de notAfter via WolfSSL.

ffi = require "ffi"
ssl_ok, ssl = pcall require, "auth.ffi_wolfssl"
expiry_ok, expiry = pcall require, "auth.cert_expiry"

TMP_DIR = "tmp/cert_expiry"
CERT    = TMP_DIR .. "/cert.pem"
KEY     = TMP_DIR .. "/key.pem"

exit_ok = (ret) -> ret == 0 or ret == true

-- 2026-12-12T00:00:00Z, 1950-01-01T00:00:00Z, 2050-01-01T00:00:00Z
-- et 2049-12-31T23:59:59Z.
EPOCH_2026_12_12 = 1797033600
EPOCH_1950_01_01 = -631152000
EPOCH_2050_01_01 = 2524608000
EPOCH_2049_12_31 = 2524607999

describe "auth.cert_expiry — parsing ASN.1", ->

  if not expiry_ok
    it "module disponible", -> pending "auth.cert_expiry non chargeable"
    return

  it "UTCTime 2 chiffres (261212000000Z)", ->
    assert.equals EPOCH_2026_12_12, expiry.parse_asn1_time "261212000000Z"

  it "GeneralizedTime 4 chiffres (20261212000000Z)", ->
    assert.equals EPOCH_2026_12_12, expiry.parse_asn1_time "20261212000000Z"

  it "UTCTime : 50 → 1950, 49 → 2049 (RFC 5280)", ->
    assert.equals EPOCH_1950_01_01, expiry.parse_asn1_time "500101000000Z"
    assert.equals EPOCH_2049_12_31, expiry.parse_asn1_time "491231235959Z"

  it "GeneralizedTime 4 chiffres : 2050", ->
    assert.equals EPOCH_2050_01_01, expiry.parse_asn1_time "20500101000000Z"

  it "rejette un format inattendu", ->
    assert.is_nil expiry.parse_asn1_time "261212000000"
    assert.is_nil expiry.parse_asn1_time "261212000000+0000"
    assert.is_nil expiry.parse_asn1_time "261312000000Z"
    assert.is_nil expiry.parse_asn1_time "261200000000Z"
    assert.is_nil expiry.parse_asn1_time nil

describe "auth.cert_expiry — classification", ->

  if not expiry_ok
    it "module disponible", -> pending "auth.cert_expiry non chargeable"
    return

  now = 1800000000

  it "expiré", ->
    assert.equals "expired", expiry.classify_expiry now - 1, now
    assert.equals "expired", expiry.classify_expiry now, now

  it "proche de l'expiration (≤ 14 jours)", ->
    assert.equals "expires_soon", expiry.classify_expiry now + 13 * 86400, now
    assert.equals "expires_soon", expiry.classify_expiry now + 14 * 86400, now

  it "valide au-delà du seuil", ->
    assert.equals "valid", expiry.classify_expiry now + 14 * 86400 + 1, now

  it "seuil configurable", ->
    assert.equals "expires_soon", expiry.classify_expiry now + 2 * 86400, now, 3
    assert.equals "valid", expiry.classify_expiry now + 4 * 86400, now, 3

  it "date absente → nil", ->
    assert.is_nil expiry.classify_expiry nil, now

describe "auth.cert_expiry — check_cert (lib simulée)", ->

  if not expiry_ok
    it "module disponible", -> pending "auth.cert_expiry non chargeable"
    return

  make_fake_lib = (text) ->
    asn = ffi.new "WOLFSSL_ASN1_TIME"
    ffi.copy asn.data, text, #text
    asn.length = #text
    {
      wolfSSL_X509_load_certificate_file: -> ffi.new "int[1]"
      wolfSSL_X509_get_notAfter: -> asn
      wolfSSL_X509_free: ->
    }

  it "expiré → cert_expired avec jours négatifs", ->
    warnings = {}
    lib = make_fake_lib "261212000000Z"
    status = expiry.check_cert "x.pem", {
      :lib
      now: EPOCH_2026_12_12 + 4 * 86400
      worker: "auth"
      log_warn_fn: (fields) -> warnings[#warnings + 1] = fields!
      log_debug_fn: ->
    }
    assert.equals "expired", status
    assert.equals 1, #warnings
    assert.equals "cert_expired", warnings[1].action
    assert.equals "x.pem", warnings[1].cert
    assert.equals "auth", warnings[1].worker
    assert.equals -4, warnings[1].days_left

  it "expire dans 10 jours → cert_expires_soon", ->
    warnings = {}
    lib = make_fake_lib "261212000000Z"
    status = expiry.check_cert "x.pem", {
      :lib
      now: EPOCH_2026_12_12 - 10 * 86400
      worker: "doh"
      log_warn_fn: (fields) -> warnings[#warnings + 1] = fields!
      log_debug_fn: ->
    }
    assert.equals "expires_soon", status
    assert.equals 1, #warnings
    assert.equals "cert_expires_soon", warnings[1].action
    assert.equals "doh", warnings[1].worker
    assert.equals 10, warnings[1].days_left

  it "valide → aucun avertissement", ->
    warnings = {}
    lib = make_fake_lib "261212000000Z"
    status = expiry.check_cert "x.pem", {
      :lib
      now: EPOCH_2026_12_12 - 30 * 86400
      log_warn_fn: (fields) -> warnings[#warnings + 1] = fields!
      log_debug_fn: ->
    }
    assert.equals "valid", status
    assert.equals 0, #warnings

  it "date illisible → debug, pas d'avertissement", ->
    warnings, debugs = {}, {}
    lib = {
      wolfSSL_X509_load_certificate_file: -> nil
      wolfSSL_X509_get_notAfter: -> nil
      wolfSSL_X509_free: ->
    }
    status = expiry.check_cert "x.pem", {
      :lib
      now: EPOCH_2026_12_12
      log_warn_fn: (fields) -> warnings[#warnings + 1] = fields!
      log_debug_fn: (fields) -> debugs[#debugs + 1] = fields!
    }
    assert.is_nil status
    assert.equals 0, #warnings
    assert.equals 1, #debugs
    assert.equals "cert_expiry_unknown", debugs[1].action

describe "auth.cert_expiry — lecture réelle notAfter (WolfSSL)", ->

  if not (expiry_ok and ssl_ok)
    it "modules réels disponibles", -> pending "auth.ffi_wolfssl/cert_expiry non chargeables"
    return

  unless ssl.symbol_available "wolfSSL_X509_load_certificate_file"
    it "symboles WolfSSL X509 disponibles", ->
      pending "libwolfssl sans wolfSSL_X509_load_certificate_file : lecture notAfter ignorée"
    return

  it "lit une date cohérente sur un certificat généré", ->
    ok_gen = exit_ok os.execute "command -v openssl >/dev/null 2>&1"
    unless ok_gen
      pending "openssl absent : lecture réelle notAfter ignorée"
    os.execute "rm -rf '#{TMP_DIR}' && mkdir -p '#{TMP_DIR}'"
    ok = exit_ok os.execute "openssl req -x509 -newkey rsa:2048 -nodes " ..
      "-keyout '#{KEY}' -out '#{CERT}' -days 30 -subj '/CN=localhost' 2>/dev/null"
    assert.is_true ok
    now = os.time!
    not_after, err = expiry.certificate_not_after CERT
    assert.is_nil err
    assert.is_not_nil not_after
    assert.is_true not_after > now
    assert.is_true not_after <= now + 31 * 86400
