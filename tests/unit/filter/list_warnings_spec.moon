-- tests/unit/filter/list_warnings_spec.moon
-- Couvre les avertissements émis à la CONSTRUCTION d'une condition quand une
-- liste référencée est introuvable ou vide. Le comportement de filtrage reste
-- inchangé (une liste absente ne correspond jamais) ; seul un log_warn est
-- ajouté, jamais dans `eval` (chemin chaud).

log           = require "log"
compiler_api  = require "filter.compiler_api"
to_domainlist = require "filter.conditions.to_domainlist"
to_domainlists = require "filter.conditions.to_domainlists"
bin48         = require "filter.lib.bin48"

-- Répertoires confinés au projet (cf. AGENTS.md : jamais /tmp système).
TMP_DIR   = "./tmp/list_warnings_spec"
LISTS_DIR = "#{TMP_DIR}/lists"        -- lists_dir des conditions *_list
DL_DIR    = "#{TMP_DIR}/domainlists"  -- domainlists_dir des to_domainlist

warns = {}
original_warn = log.log_warn

-- Remplace log_warn par un espion : les modules appellent log.log_warn au
-- moment de l'appel (référence de module), donc l'espion est bien vu.
capture_warns = ->
  warns = {}
  log.log_warn = (thunk) ->
    fields = thunk!
    warns[#warns + 1] = fields if fields != nil

write_file = (path, content) ->
  fh = assert io.open path, "w"
  fh\write content
  fh\close!

write_bin = (path, domains) ->
  payload = bin48.pack_domains domains
  fh = assert io.open path, "wb"
  fh\write payload
  fh\close!

xxhash_ok = -> (pcall require, "ffi_xxhash")

before_each ->
  os.execute "mkdir -p #{LISTS_DIR}/mac #{DL_DIR}/custom"
  capture_warns!

after_each ->
  log.log_warn = original_warn
  os.execute "rm -rf #{TMP_DIR}"

describe "conditions *_list : avertissement à la construction", ->
  factory = compiler_api.load_condition "from_mac_list"
  cfg = { lists_dir: LISTS_DIR }

  it "fichier absent → filter_list_missing + chemin cherché", ->
    cond = (factory cfg) "absente"
    assert.is_false (cond.eval { mac: "aa:bb:cc:dd:ee:ff" })
    assert.equals 1, #warns
    w = warns[1]
    assert.equals "filter_list_missing", w.action
    assert.equals "from_mac_list", w.condition
    assert.equals "absente", w.list
    assert.equals "#{LISTS_DIR}/mac/absente.txt", w.path

  it "fichier vide (commentaires seuls) → filter_list_empty", ->
    write_file "#{LISTS_DIR}/mac/vide.txt", "# commentaire\n\n"
    cond = (factory cfg) "vide"
    assert.is_false (cond.eval { mac: "aa:bb:cc:dd:ee:ff" })
    assert.equals 1, #warns
    w = warns[1]
    assert.equals "filter_list_empty", w.action
    assert.equals "from_mac_list", w.condition
    assert.equals "vide", w.list
    assert.equals "#{LISTS_DIR}/mac/vide.txt", w.path

  it "fichier valide → aucun avertissement", ->
    write_file "#{LISTS_DIR}/mac/valide.txt", "aa:bb:cc:dd:ee:ff\n"
    cond = (factory cfg) "valide"
    assert.is_true (cond.eval { mac: "aa:bb:cc:dd:ee:ff" })
    assert.equals 0, #warns

  it "lists_dir absent → défaut partagé (DEFAULTS.filter.lists_dir)", ->
    cond = (factory {}) "absente_defaut"
    assert.is_false (cond.eval { mac: "aa:bb:cc:dd:ee:ff" })
    assert.equals 1, #warns
    assert.equals "filter_list_missing", warns[1].action
    assert.equals "/etc/custos/lists/mac/absente_defaut.txt", warns[1].path

  it "plusieurs fichiers dans *_lists → un avertissement par liste absente", ->
    factory_lists = compiler_api.load_condition "from_mac_lists"
    write_file "#{LISTS_DIR}/mac/presente.txt", "aa:bb:cc:dd:ee:ff\n"
    cond = (factory_lists cfg) { "presente", "absente" }
    assert.is_true (cond.eval { mac: "aa:bb:cc:dd:ee:ff" })
    assert.equals 1, #warns
    w = warns[1]
    assert.equals "filter_list_missing", w.action
    assert.equals "from_mac_lists", w.condition
    assert.equals "absente", w.list
    assert.equals "#{LISTS_DIR}/mac/absente.txt", w.path

describe "to_domainlist : avertissement à la construction", ->
  cfg = { domainlists_dir: DL_DIR }

  it "ni .bin ni .domains → filter_list_missing avec le chemin .bin", ->
    pending "ffi_xxhash non disponible" unless xxhash_ok!
    cond = (to_domainlist.factory cfg) "custom/ferme"
    assert.is_false (cond.eval { domain: "exemple.fr" })
    assert.equals 1, #warns
    w = warns[1]
    assert.equals "filter_list_missing", w.action
    assert.equals "to_domainlist", w.condition
    assert.equals "custom/ferme", w.list
    assert.equals "#{DL_DIR}/custom/ferme.bin", w.path
    assert.equals "#{DL_DIR}/custom/ferme.domains", w.alt_path

  it ".bin présent mais vide → filter_list_empty", ->
    pending "ffi_xxhash non disponible" unless xxhash_ok!
    write_file "#{DL_DIR}/custom/vide.bin", ""
    cond = (to_domainlist.factory cfg) "custom/vide"
    assert.is_false (cond.eval { domain: "exemple.fr" })
    assert.equals 1, #warns
    w = warns[1]
    assert.equals "filter_list_empty", w.action
    assert.equals "to_domainlist", w.condition
    assert.equals "custom/vide", w.list
    assert.equals "#{DL_DIR}/custom/vide.bin", w.path

  it ".domains sans domaine (commentaires seuls) → filter_list_empty", ->
    pending "ffi_xxhash non disponible" unless xxhash_ok!
    write_file "#{DL_DIR}/custom/commente.domains", "# vide\n\n"
    cond = (to_domainlist.factory cfg) "custom/commente"
    assert.is_false (cond.eval { domain: "exemple.fr" })
    assert.equals 1, #warns
    w = warns[1]
    assert.equals "filter_list_empty", w.action
    assert.equals "#{DL_DIR}/custom/commente.domains", w.path

  it ".bin valide → aucun avertissement", ->
    pending "ffi_xxhash non disponible" unless xxhash_ok!
    write_bin "#{DL_DIR}/custom/valide.bin", { "exemple.fr" }
    cond = (to_domainlist.factory cfg) "custom/valide"
    assert.is_true (cond.eval { domain: "exemple.fr" })
    assert.equals 0, #warns

  it "to_domainlists délègue le chargement et nomme la condition", ->
    pending "ffi_xxhash non disponible" unless xxhash_ok!
    cond = (to_domainlists.factory cfg) { "custom/ferme" }
    assert.is_false (cond.eval { domain: "exemple.fr" })
    assert.equals 1, #warns
    w = warns[1]
    assert.equals "filter_list_missing", w.action
    assert.equals "to_domainlists", w.condition
    assert.equals "custom/ferme", w.list
    assert.equals "#{DL_DIR}/custom/ferme.bin", w.path
