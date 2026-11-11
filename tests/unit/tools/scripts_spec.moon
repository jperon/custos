-- tests/unit/tools/scripts_spec.moon
-- Tests des petits outils autonomes (non compilés par make all) : embed_js.lua,
-- judge.moon, quick_coverage_report.lua et la syntaxe de setup.sh.
--
-- Les scripts sont exécutés en sous-processus (luajit/moon) : ils lisent `arg`
-- et appellent os.exit, donc les charger dans le processus Busted n'est pas
-- possible sans effet de bord. Les entrées/sorties restent dans ./tmp/.

ffi = require "ffi"
xxhash = require "ffi_xxhash"
bin48 = require "filter.lib.bin48"

TMP = "tmp/tools_scripts_spec"
OUT = "#{TMP}/out.txt"

read_file = (path) ->
  fh = io.open path, "r"
  return nil unless fh
  out = fh\read "*a"
  fh\close!
  out

write_file = (path, content) ->
  fh = assert io.open(path, "w"), "impossible d'ouvrir #{path}"
  fh\write content
  fh\close!

-- Normalise le retour d'os.execute (Lua 5.1 et LUA52COMPAT).
code_of = (a, b, c) ->
  return 0 if a == true or a == 0
  return c if a == nil and type(c) == "number"
  return math.floor a / 256 if type(a) == "number"
  1

run_cmd = (cmd) ->
  ret, kind, code = os.execute "#{cmd} >'#{OUT}' 2>&1"
  code_of(ret, kind, code), read_file(OUT) or ""

setup ->
  os.execute "rm -rf #{TMP}"
  os.execute "mkdir -p #{TMP}/bin6 #{TMP}/bin8 #{TMP}/bin_bad #{TMP}/bin_empty"

after_each ->
  os.remove OUT

-- ── embed_js.lua ────────────────────────────────────────────────────────────

describe "tools/embed_js.lua", ->

  it "embarque un JS contenant ]] et ]=] avec un niveau de long-bracket sûr", ->
    js = "if (a[i]] > 0) { x = ']=]'; } // ]]]"
    write_file "#{TMP}/in.js", js
    code, out = run_cmd "luajit tools/embed_js.lua #{TMP}/in.js #{TMP}/out.lua"
    assert.equals 0, code
    generated = read_file "#{TMP}/out.lua"
    assert.truthy generated\find "return [==[", 1, true
    chunk = assert loadfile "#{TMP}/out.lua"
    -- embed_js ajoute un saut de ligne avant la fermeture du long-bracket.
    assert.equals js .. "\n", chunk!
    assert.truthy generated\find "GENERATED from", 1, true

  it "échoue si les arguments manquent", ->
    code, out = run_cmd "luajit tools/embed_js.lua"
    assert.not_equals 0, code
    assert.truthy out\find "usage:", 1, true

-- ── judge.moon ──────────────────────────────────────────────────────────────

-- Format 8 octets (uint64 little-endian), hashes triés croissants.
make_u64_bin = (domains) ->
  hashes = [xxhash.xxh64 d for d in *domains]
  table.sort hashes, (a, b) -> a < b
  arr = ffi.new "uint64_t[?]", #hashes
  for i = 1, #hashes
    arr[i - 1] = hashes[i]
  ffi.string arr, #hashes * 8

describe "tools/judge.moon", ->

  before_each ->
    payload, n = bin48.pack_domains { "ads.example.com", "tracker.example.org" }
    assert.is_true n > 0
    write_file "#{TMP}/bin6/list.bin", payload
    write_file "#{TMP}/bin8/list.bin", make_u64_bin { "ads.example.com", "tracker.example.org" }
    write_file "#{TMP}/bin_bad/list.bin", string.rep "x", 7
    write_file "#{TMP}/bin_empty/list.bin", ""

  it "trouve un domaine exact dans une liste 6 octets (bin48)", ->
    code, out = run_cmd "moon tools/judge.moon #{TMP}/bin6 ads.example.com"
    assert.equals 0, code
    assert.truthy out\find "Exact (ads.example.com) : list", 1, true

  it "trouve un suffixe parent dans une liste 6 octets", ->
    code, out = run_cmd "moon tools/judge.moon #{TMP}/bin6 sub.ads.example.com"
    assert.equals 0, code
    assert.truthy out\find "Suffixe (ads.example.com) : list", 1, true

  it "trouve un domaine exact dans une liste 8 octets (uint64)", ->
    code, out = run_cmd "moon tools/judge.moon #{TMP}/bin8 tracker.example.org"
    assert.equals 0, code
    assert.truthy out\find "Exact (tracker.example.org) : list", 1, true

  it "signale une taille invalide puis l'absence de match (code 1)", ->
    code, out = run_cmd "moon tools/judge.moon #{TMP}/bin_bad ads.example.com"
    assert.equals 1, code
    assert.truthy out\find "taille 7 non multiple de 6 ou 8", 1, true
    assert.truthy out\find "aucun match", 1, true

  it "ignore silencieusement une liste vide et rend le code 1", ->
    code, out = run_cmd "moon tools/judge.moon #{TMP}/bin_empty ads.example.com"
    assert.equals 1, code
    assert.falsy out\find "taille", 1, true
    assert.truthy out\find "aucun match", 1, true

  it "rend le code 2 si aucun fichier .bin n'est trouvé", ->
    code, out = run_cmd "moon tools/judge.moon #{TMP} ads.example.com"
    assert.equals 2, code
    assert.truthy out\find "Aucun fichier .bin trouvé", 1, true

  it "affiche l'usage (code 2) sans argument", ->
    code, out = run_cmd "moon tools/judge.moon"
    assert.equals 2, code
    assert.truthy out\find "Usage:", 1, true

-- ── quick_coverage_report.lua ──────────────────────────────────────────────

COVERAGE_DIR = "tmp/coverage_quick"
COVERAGE_FILE = "#{COVERAGE_DIR}/quick_coverage.lua"

describe "tools/quick_coverage_report.lua", ->
  saved = nil
  before_each ->
    os.execute "mkdir -p #{COVERAGE_DIR}"
    saved = read_file COVERAGE_FILE

  after_each ->
    if saved != nil
      write_file COVERAGE_FILE, saved
    else
      os.remove COVERAGE_FILE

  it "échoue proprement si le fichier de couverture est absent", ->
    os.remove COVERAGE_FILE
    code, out = run_cmd "luajit tools/quick_coverage_report.lua"
    assert.equals 1, code
    assert.truthy out\find "Impossible de lire tmp/coverage_quick/quick_coverage.lua", 1, true

  it "affiche le nombre de lignes échantillonnées et le total", ->
    write_file COVERAGE_FILE, [[
      return { ["lua/worker_doh.lua"] = { [10] = true, [20] = true } }
    ]]
    code, out = run_cmd "luajit tools/quick_coverage_report.lua"
    assert.equals 0, code
    assert.truthy out\find "fichier", 1, true
    assert.truthy out\match "lua/worker_doh%.lua%s+2"
    assert.truthy out\find "fichiers lua/ (hors exclusions) au total", 1, true

-- ── setup.sh ────────────────────────────────────────────────────────────────

describe "setup.sh", ->
  it "passe la vérification syntaxique bash", ->
    code, out = run_cmd "bash -n setup.sh"
    assert.equals 0, code
    assert.equals "", out
