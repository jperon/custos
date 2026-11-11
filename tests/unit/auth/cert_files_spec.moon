-- tests/unit/auth/cert_files_spec.moon
-- Écriture atomique des paires clé/certificat SNI (temporaire propre au PID +
-- rename) et réutilisation de la paire déjà matérialisée par un autre enfant.

{
  :write_pem_atomic
  :materialize_pair
  :read_file
} = require "auth.cert_files"

KEY_A  = "-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----\n"
CERT_A = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n"
KEY_B  = "-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n"
CERT_B = "-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----\n"

tmp_files = (prefix) ->
  f = io.popen "ls tmp 2>/dev/null | grep -F '#{prefix}'"
  return {} unless f
  out = f\read "*a"
  f\close!
  names = {}
  for line in out\gmatch "[^\n]+"
    table.insert names, line
  names

describe "auth/cert_files write_pem_atomic", ->

  it "écrit le contenu au chemin final", ->
    path = "tmp/spec_atomic_ok.crt"
    os.remove path
    ok, err = write_pem_atomic path, CERT_A
    assert.is_true ok, tostring err
    assert.equals CERT_A, read_file path
    os.remove path

  it "n'écrit aucun fichier partiel si le rename échoue", ->
    path = "tmp/spec_atomic_rename_fail.crt"
    os.remove path
    ok, err = write_pem_atomic path, CERT_A, -> nil, "renommage refusé"
    assert.is_false ok
    assert.is_string err
    assert.is_nil io.open(path, "r"), "aucun fichier final ne doit exister"
    assert.equals 0, #tmp_files("spec_atomic_rename_fail.crt.tmp."),
      "le temporaire doit être supprimé"

  it "retourne false si le chemin de destination est inouvrable", ->
    ok, err = write_pem_atomic "tmp/absent_dir_spec/x.crt", CERT_A
    assert.is_false ok
    assert.is_string err

describe "auth/cert_files materialize_pair", ->

  it "écrit clé et certificat atomiquement", ->
    key_path  = "tmp/spec_pair_a.key"
    cert_path = "tmp/spec_pair_a.crt"
    os.remove key_path
    os.remove cert_path
    key_pem, cert_pem, err = materialize_pair key_path, cert_path, KEY_A, CERT_A
    assert.is_nil err
    assert.equals KEY_A, key_pem
    assert.equals CERT_A, cert_pem
    assert.equals KEY_A, read_file key_path
    assert.equals CERT_A, read_file cert_path

  it "réutilise la paire d'un autre enfant au lieu de l'écraser", ->
    key_path  = "tmp/spec_pair_race.key"
    cert_path = "tmp/spec_pair_race.crt"
    os.remove key_path
    os.remove cert_path
    materialize_pair key_path, cert_path, KEY_A, CERT_A
    -- Le second enfant arrive avec sa propre génération : la paire déjà
    -- complète est conservée (les deux viennent de la même écriture verrouillée).
    key_pem, cert_pem = materialize_pair key_path, cert_path, KEY_B, CERT_B
    assert.equals KEY_A, key_pem
    assert.equals CERT_A, cert_pem

  it "répare une paire incomplète (clé seule) sans laisser de dépareillage", ->
    key_path  = "tmp/spec_pair_partial.key"
    cert_path = "tmp/spec_pair_partial.crt"
    os.remove key_path
    os.remove cert_path
    fh = io.open key_path, "w"
    fh\write KEY_A
    fh\close!
    key_pem, cert_pem = materialize_pair key_path, cert_path, KEY_B, CERT_B
    assert.equals KEY_B, key_pem
    assert.equals CERT_B, cert_pem
    assert.equals KEY_B, read_file key_path
    assert.equals CERT_B, read_file cert_path

  it "ne laisse pas de clé sans certificat si le rename du certificat échoue", ->
    key_path  = "tmp/spec_pair_fail.key"
    cert_path = "tmp/spec_pair_fail.crt"
    os.remove key_path
    os.remove cert_path
    calls = 0
    rename_fn = (src, dst) ->
      calls += 1
      if calls == 2
        nil, "disque plein"
      else
        os.rename src, dst
    ok, err = pcall ->
      materialize_pair key_path, cert_path, KEY_A, CERT_A, { rename_fn: rename_fn }
    assert.is_false ok
    assert.is_string err
    assert.is_nil io.open(key_path, "r")
    assert.is_nil io.open(cert_path, "r")
