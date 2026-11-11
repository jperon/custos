-- tests/unit/auth/cert_name_spec.moon
-- Validation des noms d'hôte utilisés dans un nom de fichier et un CN de
-- certificat. Le SNI vient du client (non authentifié) : rien d'autre qu'un
-- nom DNS simple ne doit passer.

{
  :sanitize_hostname
  :safe_cert_name
  :MAX_HOSTNAME_LEN
  :MAX_LABEL_LEN
} = require "auth.cert_name"

describe "auth/cert_name sanitize_hostname", ->

  it "accepte un nom DNS simple", ->
    assert.equals "example.com", sanitize_hostname "example.com"

  it "accepte tirets, points et sous-domaines", ->
    assert.equals "my-host.example.co.uk", sanitize_hostname "my-host.example.co.uk"

  it "normalise les majuscules en minuscules", ->
    assert.equals "portal.example", sanitize_hostname "Portal.Example"

  it "refuse une IP littérale IPv4", ->
    assert.is_nil sanitize_hostname "192.168.1.1"
    assert.is_nil sanitize_hostname "203.0.113.7"

  it "refuse une IP littérale IPv6", ->
    assert.is_nil sanitize_hostname "::1"
    assert.is_nil sanitize_hostname "2001:db8::1"

  it "refuse un chemin ou une traversée", ->
    assert.is_nil sanitize_hostname "../etc/passwd"
    assert.is_nil sanitize_hostname "a/b"
    assert.is_nil sanitize_hostname ".."
    assert.is_nil sanitize_hostname "a..b"

  it "refuse un octet nul ou un caractère de contrôle", ->
    assert.is_nil sanitize_hostname "evil\0host"
    assert.is_nil sanitize_hostname "evil\1host"
    assert.is_nil sanitize_hostname "evil\nhost"

  it "refuse les jokers, underscores et caractères hors LDH", ->
    assert.is_nil sanitize_hostname "*.example.com"
    assert.is_nil sanitize_hostname "under_score.example"
    assert.is_nil sanitize_hostname "space host.example"

  it "refuse un point en tête, en queue ou un label vide", ->
    assert.is_nil sanitize_hostname ".example.com"
    assert.is_nil sanitize_hostname "example.com."
    assert.is_nil sanitize_hostname "a..com"

  it "refuse un label commençant ou finissant par un tiret", ->
    assert.is_nil sanitize_hostname "-bad.example"
    assert.is_nil sanitize_hostname "bad-.example"

  it "refuse un nom trop long (> 253) ou un label trop long (> 63)", ->
    assert.equals MAX_HOSTNAME_LEN, 253
    assert.is_nil sanitize_hostname string.rep "a", (MAX_HOSTNAME_LEN + 1)
    assert.equals MAX_LABEL_LEN, 63
    assert.is_nil sanitize_hostname (string.rep "a", MAX_LABEL_LEN + 1) .. ".example.com"

  it "accepte un nom de longueur maximale", ->
    -- 4 labels de 63 => 4*63 + 3 points = 255 > 253 : on construit 253 exactement
    name = string.rep("a", 63) .. "." .. string.rep("b", 63) .. "." ..
      string.rep("c", 63) .. "." .. string.rep("d", 61)
    assert.equals 253, #name
    assert.equals name, sanitize_hostname name

  it "refuse nil, une valeur non chaîne ou une chaîne vide", ->
    assert.is_nil sanitize_hostname nil
    assert.is_nil sanitize_hostname 42
    assert.is_nil sanitize_hostname ""

describe "auth/cert_name safe_cert_name", ->

  it "accepte les noms DNS validés", ->
    assert.equals "example.com", safe_cert_name "Example.COM"

  it "accepte une IP locale IPv4 (repli historique)", ->
    assert.equals "203.0.113.1", safe_cert_name "203.0.113.1"

  it "accepte une IP locale IPv6 (repli historique)", ->
    assert.equals "2001:db8::1", safe_cert_name "2001:db8::1"

  it "refuse un chemin, une traversée ou un caractère de contrôle", ->
    assert.is_nil safe_cert_name "../etc/passwd"
    assert.is_nil safe_cert_name "a/b"
    assert.is_nil safe_cert_name "a..b"
    assert.is_nil safe_cert_name "evil\0host"
    assert.is_nil safe_cert_name "evil\nhost"

  it "refuse un nom trop long ou vide", ->
    assert.is_nil safe_cert_name string.rep "a", 254
    assert.is_nil safe_cert_name ""
    assert.is_nil safe_cert_name nil
