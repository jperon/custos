-- tests/unit/idefix2filter_spec.moon
-- Conversion Idefix3 → Custos : logique pure (table décodée → config.moon +
-- listes) et sortie compilable par le compilateur MoonScript du projet.
--
-- Le format d'entrée est celui que lit réellement idefix2filter.moon :
--   data.groups[groupe].dest_domains
--   data.rules["block yahoo search"|"Salon profs"].dest_domains
--   data.maclists.{profs,abbes,eleves_limites,salon_profs,defaut}
--   data.users[profil][utilisateur].devices[nom].mac

json = require "lib.json"

mod = assert(loadfile "idefix2filter.lua")!
{ :clean_domain, :convert, :render_config, :run } = mod

GROUPE_PROFS = "Internet autorisé (filtré par catégories \"large\")"
GROUPE_DEFAUT = "Internet filtré par défaut (prieuré)"
GROUPE_LIMITE = "Internet limité (liste blanche)"

--- Petit JSON Idefix d'exemple, conforme aux champs lus par le script.
fixture = ->
  {
    groups: {
      reseaux_sociaux: { dest_domains: {"*. Exemple.COM", " example.net ", "", "  "} }
      vide: { dest_domains: {""} }
    }
    rules: {
      ["block yahoo search"]: { dest_domains: {"Yahoo.COM"} }
      ["Salon profs"]: { dest_domains: {"spotify.com"} }
    }
    maclists: {
      profs: {}
      abbes: {}
      eleves_limites: {}
      salon_profs: {}
      defaut: {}
    }
    users: {
      [GROUPE_PROFS]: {
        ["Prof A"]: { devices: { ["portable-prof"]: { mac: "AA:BB:CC:DD:EE:01" } } }
      }
      [GROUPE_DEFAUT]: {
        ["Père X"]: { devices: { ["pc-prieure"]: { mac: "aa:bb:cc:dd:ee:02" } } }
      }
      ["Profil non mappé"]: {
        ["Utilisateur X"]: {
          devices: {
            ["pc\"quote"]: { mac: "aa:bb:cc:dd:ee:06" }
            ["pc\nnewline"]: { mac: "aa:bb:cc:dd:ee:07" }
          }
        }
      }
      [GROUPE_LIMITE]: {
        ["Élève Y"]: { devices: { ["tablette-eleve"]: { mac: "aa:bb:cc:dd:ee:03" } } }
        ["Salon profs"]: { devices: { ["tablette-salon"]: { mac: "aa:bb:cc:dd:ee:04" } } }
        ["Abbés"]: { devices: { ["portable-abbe"]: { mac: "aa:bb:cc:dd:ee:05" } } }
      }
    }
  }

OUT_DIR = "tmp/idefix2filter_spec/out"
IDEFIX_JSON = "tmp/idefix2filter_spec/idefix.json"
PROBE = "tmp/idefix2filter_spec/probe.lua"

describe "idefix2filter — nettoyage des domaines", ->
  it "supprime les espaces, le préfixe « *. » et passe en minuscules", ->
    assert.equals "exemple.com", clean_domain "*. Exemple.COM"
    assert.equals "exemple.net", clean_domain "  Exemple.NET  "
  it "ignore les entrées vides ou absentes", ->
    assert.is_nil clean_domain ""
    assert.is_nil clean_domain "   "
    assert.is_nil clean_domain nil

describe "idefix2filter — conversion", ->
  it "extrait et trie les domaines des groupes", ->
    out = convert fixture!
    assert.same {"example.net", "exemple.com"}, out.lists.reseaux_sociaux
    assert.is_nil out.lists.vide
  it "extrait les listes spéciales block_yahoo et spotify", ->
    out = convert fixture!
    assert.same {"yahoo.com"}, out.specials.block_yahoo
    assert.same {"spotify.com"}, out.specials.spotify
  it "associe les appareils aux groupes de MAC (profils + cas Salon profs/Abbés)", ->
    out = convert fixture!
    assert.equals "AA:BB:CC:DD:EE:01", out.macs["portable-prof"]
    assert.same {"portable-prof"}, out.maclists.profs
    assert.same {"pc-prieure"}, out.maclists.defaut
    assert.same {"tablette-eleve"}, out.maclists.eleves_limites
    assert.same {"tablette-salon"}, out.maclists.salon_profs
    assert.same {"portable-abbe"}, out.maclists.abbes
    assert.equals "aa:bb:cc:dd:ee:06", out.macs['pc"quote']
    assert.equals "aa:bb:cc:dd:ee:07", out.macs["pc\nnewline"]
  it "construit les règles avec des clés de condition existantes", ->
    out = convert fixture!
    text = out.config
    assert.truthy text\find "from_macs: {\"portable-prof\"}", 1, true
    assert.truthy text\find "to_domains: {\"local\", \"lan\", \"home.arpa\"}", 1, true
    assert.is_nil text\find "from_maclist", 1, true
    assert.is_nil text\find "[local, lan, home.arpa]", 1, true
  it "omet les règles des groupes et listes spéciales absents", ->
    out = convert { groups: {}, rules: {}, users: {}, maclists: {} }
    assert.same {}, out.lists
    assert.equals 2, #out.rules
    assert.equals "Infrastructure et local", out.rules[1].description
    assert.equals "Verdict Final", out.rules[2].description
    assert.is_nil out.config\find "from_macs", 1, true
  it "ne référence pas une liste spéciale absente du JSON", ->
    out = convert { groups: {}, rules: {}, users: {}, maclists: { profs: { "p1" } } }
    assert.equals 3, #out.rules
    assert.equals "Accès total Profs", out.rules[1].description
    assert.is_nil out.config\find "custom/block_yahoo", 1, true
    assert.is_nil out.config\find "custom/spotify", 1, true

describe "idefix2filter — sortie MoonScript", ->
  out = convert fixture!

  it "compile avec le compilateur MoonScript du projet", ->
    moon = require "moonscript.base"
    code, err = moon.to_lua out.config
    assert.is_not_nil code, "compilation : #{tostring err}"

  it "se charge en table Lua avec les règles attendues", ->
    moon = require "moonscript.base"
    code = assert moon.to_lua out.config
    loaded = assert loadstring code
    cfg = loaded!
    assert.is_table cfg
    assert.equals 7, #cfg.filter.rules
    assert.equals "Blocages prioritaires", cfg.filter.rules[1].description
    assert.same {"deny"}, cfg.filter.rules[1].actions
    assert.same {"local", "lan", "home.arpa"}, cfg.filter.rules[3].conditions.to_domains
    assert.equals "Verdict Final", cfg.filter.rules[7].description
    assert.same {}, cfg.filter.rules[7].conditions

  it "n'émet que des conditions reconnues par compiler_api", ->
    compiler_api = require "filter.compiler_api"
    moon = require "moonscript.base"
    code = assert moon.to_lua out.config
    cfg = assert(loadstring code)!
    for rule in *cfg.filter.rules
      for key in pairs (rule.conditions or {})
        factory, err = compiler_api.load_condition key
        assert.is_not_nil factory, "condition '#{key}' inconnue : #{tostring err}"

  it "n'utilise pas d'accumulation « ..= » dans le script", ->
    f = assert io.open "idefix2filter.moon", "r"
    src = f\read "*a"
    f\close!
    assert.is_nil src\find "..=", 1, true

describe "idefix2filter — écriture et chargement", ->
  before_each ->
    os.execute "rm -rf tmp/idefix2filter_spec"
    os.execute "mkdir -p tmp/idefix2filter_spec"

  it "écrit config.moon et les listes .domains, puis le chargeur du projet la lit", ->
    os.execute "mkdir -p #{OUT_DIR}"
    text = json.encode fixture!
    f = assert io.open IDEFIX_JSON, "w"
    f\write text
    f\close!

    out = run IDEFIX_JSON, OUT_DIR
    assert.is_table out

    cfg_f = assert io.open "#{OUT_DIR}/config.moon", "r"
    written = cfg_f\read "*a"
    cfg_f\close!
    assert.equals out.config, written

    list_f = assert io.open "#{OUT_DIR}/listes/custom/block_yahoo.domains", "r"
    assert.equals "yahoo.com\n", list_f\read "*a"
    list_f\close!

    group_f = assert io.open "#{OUT_DIR}/listes/reseaux_sociaux.domains", "r"
    assert.equals "example.net\nexemple.com\n", group_f\read "*a"
    group_f\close!

    probe_f = assert io.open PROBE, "w"
    probe_f\write [==[
local config = require "config"
local m = assert(config.__meta, "config.__meta absent")
assert(m.external_loaded == true, "config externe non chargée")
assert(m.load_error == nil, "load_error: " .. tostring(m.load_error))
local found = false
for _, r in ipairs(config.filter.rules) do
  if r.description == "Verdict Final" then found = true end
end
assert(found, "règle Verdict Final absente après fusion")
print("LOADER_OK")
]==]
    probe_f\close!

    cmd = string.format(
      'LUA_PATH="lua/?.lua;lua/?/init.lua;;" CUSTOS_CONFIG_PATH=%q CUSTOS_REQUIRE_EXTERNAL_CONFIG=1 luajit %s 2>&1',
      "#{OUT_DIR}/config.moon", PROBE)
    pipe = assert io.popen cmd, "r"
    loaded = pipe\read "*a"
    pipe\close!
    loaded = loaded\gsub "%s+$", ""
    assert.equals "LOADER_OK", loaded
