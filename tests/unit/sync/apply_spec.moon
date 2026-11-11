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
-- os.execute renvoie 0 en Lua 5.1 et true (succès) / nil (échec) en Lua 5.2+
-- (LUA52COMPAT) : on normalise pour que les assertions restent portables.
run = (args) ->
  out_path = "#{TMP}/run_out.txt"
  cmd = "LUA_PATH='#{LUA_PATH_VAR}' luajit #{APPLY} #{args} >'#{out_path}' 2>&1"
  ret = os.execute cmd
  code = if ret == 0 or ret == true then 0 else 1
  out = read_file(out_path) or ""
  os.remove out_path
  code, out

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

  it "échoue sur un --hostname qui sortirait du dossier devices/", ->
    write_file "#{TMP}/base/config.moon", [[ { runtime: { log_level: "INFO" } } ]]
    ret, out = run "--base #{TMP}/base/config.moon --hostname ../../etc --output #{TMP}/out.moon"
    assert.not_equals 0, ret
    assert.truthy out\match "nom d'hôte invalide"

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

-- ── Rechargement du superviseur (in-process) ────────────────────────────────
-- Le script est chargé via loadfile : son `main!` n'est lancé que si arg[0]
-- ressemble à « apply », donc les fonctions exportées sont utilisables ici.

APPLY_MOD = assert(loadfile APPLY)!

capture_stderr = (fn) ->
  captured = {}
  original = io.stderr
  io.stderr = { write: (self, msg) -> captured[#captured + 1] = msg }
  ok, result = pcall fn
  io.stderr = original
  error result unless ok
  table.concat(captured), result

fake_read_pid = (pid, err) -> (path) -> pid, err

fake_handle = (output) ->
  fh = {}
  fh.read = (self, fmt) -> output
  fh.close = (self) -> nil
  fh


describe "sync/apply — reload_supervisor", ->

  it "appelle kill_fn avec le PID du pidfile et SIGHUP (1)", ->
    calls = {}
    kill_fn = (pid, sig) ->
      calls[#calls + 1] = { pid, sig }
      true
    ok = APPLY_MOD.reload_supervisor "tmp/apply_spec/pidfile", kill_fn, fake_read_pid 4242
    assert.is_true ok
    assert.equals 1, #calls
    assert.equals 4242, calls[1][1]
    assert.equals APPLY_MOD.SIGHUP, calls[1][2]

  it "n'appelle pas kill_fn et avertit si le pidfile est absent", ->
    calls = {}
    kill_fn = (pid, sig) ->
      calls[#calls + 1] = pid
      true
    out, ok = capture_stderr ->
      APPLY_MOD.reload_supervisor "tmp/apply_spec/absent.pid", kill_fn, fake_read_pid nil, "pidfile introuvable : tmp/apply_spec/absent.pid"
    assert.is_false ok
    assert.equals 0, #calls
    assert.truthy out\match "SIGHUP non envoyé"
    assert.truthy out\match "pidfile introuvable"

  it "n'émet jamais de pkill (aucune commande shell de repli)", ->
    src = read_file APPLY
    assert.falsy src\find "pkill", 1, true
    -- Même avec pidfile absent et kill_fn par défaut, aucun shell n'est lancé.
    seen = {}
    original = os.execute
    os.execute = (cmd) ->
      seen[#seen + 1] = cmd
      0
    out, ok = capture_stderr ->
      APPLY_MOD.reload_supervisor "tmp/apply_spec/absent.pid", nil, fake_read_pid nil, "absent"
    os.execute = original
    assert.is_false ok
    assert.equals 0, #seen

-- ── Résolution du nom d'hôte ────────────────────────────────────────────────

describe "sync/apply — resolve_hostname", ->

  it "renvoie le nom d'hôte de uname -n", ->
    popen = (cmd) -> fake_handle "  router1  "
    assert.equals "router1", APPLY_MOD.resolve_hostname popen

  it "échoue explicitement si uname -n renvoie une sortie vide", ->
    popen = (cmd) -> fake_handle ""
    out, host = capture_stderr -> APPLY_MOD.resolve_hostname popen
    assert.is_nil host
    assert.truthy out\match "nom d'hôte vide"

  it "échoue explicitement si le lancement de uname -n échoue", ->
    out, host = capture_stderr -> APPLY_MOD.resolve_hostname (-> nil)
    assert.is_nil host
    assert.truthy out\match "uname %-n indisponible"

  it "rejette une sortie de uname -n non conforme (traversée, slash)", ->
    for raw in *{"../../etc", "a/b", "a b"}
      out, host = capture_stderr -> APPLY_MOD.resolve_hostname (-> fake_handle raw)
      assert.is_nil host, raw
      assert.truthy out\match "nom d'hôte invalide"

describe "sync/apply — valid_hostname", ->

  it "accepte les noms usuels (lettres, chiffres, point, tiret, souligné)", ->
    for h in *{"router1", "router.lan", "a_b-c", "CUSTOS-01"}
      assert.is_true APPLY_MOD.valid_hostname(h), h

  it "rejette les composants de traversée et les séparateurs de chemin", ->
    for h in *{".", "..", "../etc", "a/b", "a b", "a;b", ""}
      assert.is_false APPLY_MOD.valid_hostname(h), h
    assert.is_false APPLY_MOD.valid_hostname nil
