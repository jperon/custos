-- tests/unit/filter/updater_io_spec.moon
-- Tests des helpers I/O de l'updater (extraits de filter/updater.moon pour être
-- testables). Couvre en particulier download_file dans les DEUX sémantiques de
-- os.execute : Lua 5.1 (0 = succès, ≠0 = échec) et Lua 5.2+/LUA52COMPAT
-- (true = succès, nil = échec). Régression : `ret == 0` seul faisait passer
-- tout téléchargement réussi pour un échec sous LUA52COMPAT.

updater_io = require "filter.updater_io"

describe "filter.updater_io.download_file", ->
  orig_execute = os.execute
  last_cmd = nil

  before_each ->
    last_cmd = nil

  after_each ->
    os.execute = orig_execute

  it "retourne true si os.execute renvoie 0 (Lua 5.1)", ->
    os.execute = (cmd) ->
      last_cmd = cmd
      0
    assert.is_true updater_io.download_file "https://exemple.test/l.txt", "tmp/dest.bin"
    assert.truthy last_cmd\find("curl", 1, true)
    assert.truthy last_cmd\find("https://exemple.test/l.txt", 1, true)
    assert.truthy last_cmd\find("tmp/dest.bin", 1, true)

  it "retourne false si os.execute renvoie un code non nul (Lua 5.1)", ->
    os.execute = -> 7
    assert.is_false updater_io.download_file "https://exemple.test/l.txt", "tmp/dest.bin"

  it "retourne true si os.execute renvoie true (Lua 5.2+ / LUA52COMPAT)", ->
    os.execute = (cmd) ->
      last_cmd = cmd
      true
    assert.is_true updater_io.download_file "https://exemple.test/l.txt", "tmp/dest.bin"
    assert.truthy last_cmd\find("--max-time 120", 1, true)

  it "retourne false si os.execute renvoie nil (Lua 5.2+ / LUA52COMPAT)", ->
    os.execute = -> nil
    assert.is_false updater_io.download_file "https://exemple.test/l.txt", "tmp/dest.bin"

  it "honore le timeout fourni", ->
    os.execute = (cmd) ->
      last_cmd = cmd
      true
    updater_io.download_file "https://exemple.test/l.txt", "tmp/dest.bin", 42
    assert.truthy last_cmd\find("--max-time 42", 1, true)

describe "filter.updater_io.ensure_dir", ->
  orig_execute = os.execute
  after_each -> os.execute = orig_execute

  it "retourne true si rien à faire (dir vide/nil)", ->
    assert.is_true updater_io.ensure_dir nil
    assert.is_true updater_io.ensure_dir ""

  it "accepte 0 (Lua 5.1) et true (Lua 5.2+)", ->
    os.execute = -> 0
    assert.is_true updater_io.ensure_dir "tmp/x"
    os.execute = -> true
    assert.is_true updater_io.ensure_dir "tmp/x"

  it "rejette un échec dans les deux sémantiques", ->
    os.execute = -> 1
    assert.is_false updater_io.ensure_dir "tmp/x"
    os.execute = -> nil
    assert.is_false updater_io.ensure_dir "tmp/x"

describe "filter.updater_io.ensure_parent_dir", ->
  orig_execute = os.execute
  after_each -> os.execute = orig_execute

  it "retourne true quand aucun parent n'est nécessaire", ->
    assert.is_true updater_io.ensure_parent_dir "fichier"

  it "accepte 0 (Lua 5.1) et true (Lua 5.2+)", ->
    os.execute = -> 0
    assert.is_true updater_io.ensure_parent_dir "tmp/a/fichier"
    os.execute = -> true
    assert.is_true updater_io.ensure_parent_dir "tmp/a/fichier"

  it "rejette un échec dans les deux sémantiques", ->
    os.execute = -> 1
    assert.is_false updater_io.ensure_parent_dir "tmp/a/fichier"
    os.execute = -> nil
    assert.is_false updater_io.ensure_parent_dir "tmp/a/fichier"

describe "filter.updater_io.sh_quote", ->
  it "entoure de quotes simples et échappe les quotes internes", ->
    assert.equals "'abc'", updater_io.sh_quote "abc"
    assert.equals "'a'\"'\"'b'", updater_io.sh_quote "a'b"

describe "filter.updater_io.bin_name_for", ->
  it "retire le suffixe .txt d'un nom simple", ->
    assert.equals "ads", updater_io.bin_name_for "ads.txt"

  it "retire le répertoire et le suffixe .txt", ->
    assert.equals "ads", updater_io.bin_name_for "groupe/ads.txt"

  it "replie sur le nom complet sans suffixe .txt", ->
    assert.equals "sans-extension", updater_io.bin_name_for "sans-extension"
