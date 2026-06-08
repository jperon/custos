-- tests/unit/sync/apply_spec.moon
-- Tests d'intégration de sync/apply.moon.
-- Le script est invoqué via luajit (subprocess) car il utilise `arg` et `os.exit`.

TMP   = "tmp/apply_spec"
APPLY = "lua/sync/apply.lua"
LUA_PATH_VAR = "lua/?.lua;lua/?/init.lua;;"

-- ── Helpers ──────────────────────────────────────────────────────────────────

write_file = (path, content) ->
  f = assert io.open(path, "w"), "impossible d'ouvrir #{path}"
  f\write content
  f\close!

read_file = (path) ->
  f = io.open path, "r"
  return nil unless f
  out = f\read "*a"
  f\close!
  out

-- Exécute apply.lua avec les arguments donnés.
-- Retourne : code_retour (0=succès), sortie_combinée (stdout+stderr).
run = (args) ->
  out_path = "#{TMP}/run_out.txt"
  cmd = "LUA_PATH='#{LUA_PATH_VAR}' luajit #{APPLY} #{args} >'#{out_path}' 2>&1"
  ret = os.execute cmd
  out = read_file(out_path) or ""
  os.remove out_path
  ret, out

-- Charge un fichier config.moon (MoonScript) produit par apply,
-- exactement comme le runtime via moonscript.base.loadfile.
load_result = (path) ->
  moon_base = require "moonscript.base"
  fn, err = moon_base.loadfile path
  return nil, err unless fn
  ok, val = pcall fn
  return nil, tostring(val) unless ok
  val, nil

setup ->
  os.execute "mkdir -p #{TMP}/base #{TMP}/devices/router1"

after_each ->
  os.execute "rm -f #{TMP}/base/config.moon #{TMP}/devices/router1/config.moon"
  os.execute "rm -f #{TMP}/out.moon #{TMP}/device-explicit.moon #{TMP}/custom-out.moon"

-- ── Cas d'erreur ─────────────────────────────────────────────────────────────

describe "sync/apply — erreurs CLI", ->

  it "échoue si --base est absent", ->
    ret, out = run "--output #{TMP}/out.moon"
    assert.not_equals 0, ret
    assert.truthy out\match "base"

  it "échoue si la config de base est introuvable", ->
    ret, out = run "--base #{TMP}/base/nonexistent.moon --output #{TMP}/out.moon"
    assert.not_equals 0, ret
    assert.truthy out\match "introuvable"

-- ── Comportement nominal ──────────────────────────────────────────────────────

describe "sync/apply — comportement nominal", ->

  it "base seule si aucun device ne correspond (hostname inconnu)", ->
    write_file "#{TMP}/base/config.moon", [[
      { runtime: { log_level: "INFO" }, auth: { port: 33443 } }
    ]]
    ret, _ = run "--base #{TMP}/base/config.moon --hostname nobody --output #{TMP}/out.moon"
    assert.equals 0, ret
    cfg = assert load_result "#{TMP}/out.moon"
    assert.equals "INFO",  cfg.runtime.log_level
    assert.equals 33443,   cfg.auth.port

  it "les valeurs device écrasent la base (merge superficiel)", ->
    write_file "#{TMP}/base/config.moon", [[
      { runtime: { log_level: "INFO" }, auth: { port: 33443 } }
    ]]
    write_file "#{TMP}/devices/router1/config.moon", [[
      { runtime: { log_level: "DEBUG" } }
    ]]
    ret, _ = run "--base #{TMP}/base/config.moon --hostname router1 --output #{TMP}/out.moon"
    assert.equals 0, ret
    cfg = assert load_result "#{TMP}/out.moon"
    assert.equals "DEBUG", cfg.runtime.log_level  -- surchargé
    assert.equals 33443,   cfg.auth.port           -- préservé

  it "merge profond : sous-tables fusionnées et non remplacées", ->
    write_file "#{TMP}/base/config.moon", [[
      { nft: { family: "bridge", table: "dns-filter", ip_timeout: "2m" } }
    ]]
    write_file "#{TMP}/devices/router1/config.moon", [[
      { nft: { ip_timeout: "5m" } }
    ]]
    ret, _ = run "--base #{TMP}/base/config.moon --hostname router1 --output #{TMP}/out.moon"
    assert.equals 0, ret
    cfg = assert load_result "#{TMP}/out.moon"
    assert.equals "bridge",      cfg.nft.family      -- préservé
    assert.equals "dns-filter",  cfg.nft.table       -- préservé
    assert.equals "5m",          cfg.nft.ip_timeout  -- surchargé

  it "les tableaux sont remplacés et non fusionnés", ->
    write_file "#{TMP}/base/config.moon", [[
      { nft: { add_backoff_ms: { 20, 50, 100 } } }
    ]]
    write_file "#{TMP}/devices/router1/config.moon", [[
      { nft: { add_backoff_ms: { 10 } } }
    ]]
    ret, _ = run "--base #{TMP}/base/config.moon --hostname router1 --output #{TMP}/out.moon"
    assert.equals 0, ret
    cfg = assert load_result "#{TMP}/out.moon"
    assert.equals 1,  #cfg.nft.add_backoff_ms   -- remplacé (pas concaténé)
    assert.equals 10, cfg.nft.add_backoff_ms[1]

  it "--device spécifie explicitement le chemin de la config device", ->
    write_file "#{TMP}/base/config.moon",         [[ { runtime: { log_level: "INFO" } } ]]
    write_file "#{TMP}/device-explicit.moon",     [[ { runtime: { log_level: "WARN" } } ]]
    ret, _ = run "--base #{TMP}/base/config.moon --device #{TMP}/device-explicit.moon --output #{TMP}/out.moon"
    assert.equals 0, ret
    cfg = assert load_result "#{TMP}/out.moon"
    assert.equals "WARN", cfg.runtime.log_level

  it "--output spécifie un chemin de sortie personnalisé", ->
    write_file "#{TMP}/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]]
    ret, _ = run "--base #{TMP}/base/config.moon --hostname nobody --output #{TMP}/custom-out.moon"
    assert.equals 0, ret
    assert.truthy read_file "#{TMP}/custom-out.moon"

  it "le fichier de sortie est un MoonScript valide rechargeable par moonscript.base.loadfile", ->
    write_file "#{TMP}/base/config.moon", [[{
      runtime: { log_level: "INFO", benchmark: false }
      filter:  { rules: {}, allowed_domains: { "local", "lan" } }
    }]]
    ret, _ = run "--base #{TMP}/base/config.moon --hostname nobody --output #{TMP}/out.moon"
    assert.equals 0, ret
    cfg, err = load_result "#{TMP}/out.moon"
    assert.is_nil err
    assert.not_nil cfg
    assert.equals "INFO",  cfg.runtime.log_level
    assert.is_false        cfg.runtime.benchmark
    assert.equals 2,       #cfg.filter.allowed_domains

  it "affiche un message de confirmation sur la sortie standard", ->
    write_file "#{TMP}/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]]
    ret, out = run "--base #{TMP}/base/config.moon --hostname nobody --output #{TMP}/out.moon"
    assert.equals 0, ret
    assert.truthy out\match "mis à jour"

  it "--reload ne plante pas si le service est inactif (SIGHUP ignoré)", ->
    write_file "#{TMP}/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]]
    -- pkill retourne 1 si aucun process, apply doit quand même réussir
    ret, _ = run "--base #{TMP}/base/config.moon --hostname nobody --output #{TMP}/out.moon --reload"
    assert.equals 0, ret
    assert.truthy read_file "#{TMP}/out.moon"
