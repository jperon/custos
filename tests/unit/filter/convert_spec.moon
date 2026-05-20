-- tests/unit/filter/convert_spec.moon
-- Tests du script CLI lua/filter/convert.lua.
--
-- filter/convert.lua est un script autonome (pas un module require-able) :
-- il lit un fichier de domaines, hache chaque entrée avec xxhash64, déduplique,
-- trie, et écrit un tableau binaire d'uint64_t dans un fichier .bin.
--
-- Les tests le lancent en sous-processus (os.execute) en reconstruisant le
-- LUA_PATH exact utilisé par le Makefile.
--
-- Tous les fichiers temporaires sont dans ./tmp/ (règle AGENTS.md).

CONV_INPUT  = "tmp/test_convert_spec.domains"
CONV_OUTPUT = "tmp/test_convert_spec.bin"

-- Commande de base : reproduit le LUA_PATH du Makefile.
LUA_CMD = "LUA_PATH='lua/?.lua;lua/?/init.lua;;' luajit lua/filter/convert.lua"

-- Lance le script avec les arguments donnés ; retourne true si exit 0.
-- Lua 5.1/LuaJIT : os.execute renvoie l'exit code (0 = succès).
-- Lua 5.2+      : renvoie (true|nil, "exit"|"signal", code).
run_convert = (args) ->
  code = os.execute "#{LUA_CMD} #{args} 2>/dev/null"
  code == 0 or code == true

-- Lit un fichier binaire ; retourne nil en cas d'erreur.
read_bin = (path) ->
  fh = io.open path, "rb"
  return nil unless fh
  data = fh\read "*a"
  fh\close!
  data

-- Compare deux blobs uint64 little-endian à indices 0-basés i et j dans s.
-- Retourne true si s[i] <= s[j].
u64_le = (s, i, j) ->
  for b = 7, 0, -1
    ai = string.byte s, i * 8 + b + 1
    aj = string.byte s, j * 8 + b + 1
    return true if ai < aj
    return false if ai > aj
  true  -- égaux → non strict, donc ≤ est vrai

-- Vérifie que tous les blocs de 8 octets dans s sont en ordre croissant.
sorted_u64 = (s) ->
  n = math.floor #s / 8
  return true if n <= 1
  for i = 0, n - 2
    return false unless u64_le s, i, i + 1
  true

-- Supprime les fichiers temporaires s'ils existent.
cleanup = ->
  os.remove CONV_INPUT
  os.remove CONV_OUTPUT


-- Vérifie la disponibilité de ffi_xxhash une seule fois.
-- Notre fix dans ffi_xxhash.moon réinitialise package.loaded en cas d'échec,
-- donc le pcall est propre même si une suite précédente avait déjà échoué.
xxhash_ok = (pcall require, "ffi_xxhash")

-- ════════════════════════════════════════════════════════════════════════════
describe "filter/convert (CLI)", ->

  after_each -> cleanup!

  -- ── invocation sans arguments (exit non nul attendu, pas besoin de xxhash)
  describe "sans arguments", ->

    it "exit non nul si aucun argument", ->
      assert.is_false run_convert ""

  -- ── fichier d'entrée absent (exit non nul attendu) ───────────────────────
  describe "fichier d'entrée absent", ->

    it "exit non nul si le fichier source n'existe pas", ->
      assert.is_false run_convert "tmp/__nonexistent__.domains #{CONV_OUTPUT}"

  -- ── tests nécessitant libxxhash ──────────────────────────────────────────
  unless xxhash_ok
    it "libxxhash non disponible → tests CLI ignorés", -> pending "libxxhash non disponible"
    return

  -- ── domaines valides → binaire trié ──────────────────────────────────────
  describe "domaines valides", ->

    it "produit un fichier binaire (exit 0)", ->
      fh = io.open CONV_INPUT, "w"
      fh\write "github.com\nfacebook.com\ngoogle.com\n"
      fh\close!
      assert.is_true run_convert "#{CONV_INPUT} #{CONV_OUTPUT}"

    it "taille = nb_domaines × 8 octets", ->
      fh = io.open CONV_INPUT, "w"
      fh\write "github.com\nfacebook.com\ngoogle.com\n"
      fh\close!
      run_convert "#{CONV_INPUT} #{CONV_OUTPUT}"
      data = read_bin CONV_OUTPUT
      assert.is_not_nil data
      assert.equals 3 * 8, #data

    it "les hashes sont triés (ordre croissant uint64)", ->
      fh = io.open CONV_INPUT, "w"
      fh\write "github.com\nfacebook.com\ngoogle.com\n"
      fh\close!
      run_convert "#{CONV_INPUT} #{CONV_OUTPUT}"
      data = read_bin CONV_OUTPUT
      assert.is_not_nil data
      assert.is_true sorted_u64 data

  -- ── déduplication ─────────────────────────────────────────────────────────
  describe "déduplication", ->

    it "trois lignes identiques → un seul hash (8 octets)", ->
      fh = io.open CONV_INPUT, "w"
      fh\write "github.com\ngithub.com\ngithub.com\n"
      fh\close!
      ok = run_convert "#{CONV_INPUT} #{CONV_OUTPUT}"
      assert.is_true ok
      data = read_bin CONV_OUTPUT
      assert.is_not_nil data
      assert.equals 8, #data

  -- ── commentaires et lignes vides ignorés ─────────────────────────────────
  describe "commentaires et lignes vides", ->

    it "commentaires # et lignes vides ignorés → seul github.com compté", ->
      fh = io.open CONV_INPUT, "w"
      fh\write "# ce fichier a des commentaires\n"
      fh\write "\n"
      fh\write "github.com  # commentaire inline\n"
      fh\write "   \n"
      fh\close!
      ok = run_convert "#{CONV_INPUT} #{CONV_OUTPUT}"
      assert.is_true ok
      data = read_bin CONV_OUTPUT
      assert.is_not_nil data
      assert.equals 8, #data

  -- ── fichier d'entrée vide (aucun domaine valide) ──────────────────────────
  describe "fichier sans domaine valide", ->

    it "exit non nul si tous les lignes sont des commentaires ou vides", ->
      fh = io.open CONV_INPUT, "w"
      fh\write "# seulement des commentaires\n"
      fh\write "\n"
      fh\close!
      assert.is_false run_convert "#{CONV_INPUT} #{CONV_OUTPUT}"

  -- ── cohérence hash : même domaine → même hash dans deux exécutions ────────
  describe "cohérence du hash", ->

    it "deux exécutions sur le même domaine produisent le même binaire", ->
      fh = io.open CONV_INPUT, "w"
      fh\write "example.com\n"
      fh\close!
      run1_out = "tmp/test_convert_spec_run1.bin"
      run2_out = "tmp/test_convert_spec_run2.bin"
      run_convert "#{CONV_INPUT} #{run1_out} 2>/dev/null"
      run_convert "#{CONV_INPUT} #{run2_out} 2>/dev/null"
      d1 = read_bin run1_out
      d2 = read_bin run2_out
      assert.is_not_nil d1
      assert.is_not_nil d2
      assert.equals d1, d2
      os.remove run1_out
      os.remove run2_out
