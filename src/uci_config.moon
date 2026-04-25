-- src/uci_config.moon
-- Préprocesseur UCI → génère /var/run/custos/config.lua avant le démarrage.
--
-- Lit /etc/config/custos via `uci` et produit un fichier config.lua dans
-- OUTPUT_DIR. config.moon est la source unique des valeurs par défaut.
-- Pour chaque clé de config.moon, on tente une lecture UCI (clé en minuscules).
-- L'écriture est atomique (rename(2) sur le même filesystem tmpfs).
--
-- Usage (appelé par /etc/init.d/custos) :
--   luajit /usr/share/custos/uci_config.lua

-- Ajout du répertoire du script à package.path pour l'exécution standalone
-- (l'init script lance uci_config.lua sans LUA_PATH).
script_dir = (arg and arg[0] or "")\match("^(.*)/") or "."
package.path = "#{script_dir}/?.lua;#{package.path}"

C = require "config"
UCI_PKG    = "custos"
UCI_SEC    = "main"
OUTPUT_DIR = "/var/run/custos"

-- ── Lecture UCI ───────────────────────────────────────────────────

--- Lit une option scalaire UCI.
-- @tparam string option Nom de l'option UCI (minuscules)
-- @treturn string|nil Valeur brute ou nil si absente
uci_get = (option) ->
  fh = io.popen "uci get #{UCI_PKG}.#{UCI_SEC}.#{option} 2>/dev/null"
  return nil unless fh
  val = fh\read "*l"
  fh\close!
  val if val and val ~= ""

--- Lit une option liste UCI.
-- @tparam string option Nom de l'option UCI (minuscules)
-- @treturn table|nil Liste de chaînes, ou nil si l'option est absente
uci_get_list = (option) ->
  fh = io.popen "uci show #{UCI_PKG}.#{UCI_SEC}.#{option} 2>/dev/null"
  return nil unless fh
  content = fh\read "*a"
  fh\close!
  return nil if not content or content\match "^%s*$"
  result = {}
  for val in content\gmatch "'([^']*)'"
    table.insert result, val
  result

-- ── Résolution ───────────────────────────────────────────────────

--- Coerce une valeur UCI brute (string) vers le type de la valeur par défaut.
-- @tparam string   raw     Valeur brute lue par uci_get
-- @tparam any      default Valeur par défaut (détermine le type cible)
-- @treturn any
coerce = (raw, default) ->
  switch type default
    when "number"  then tonumber(raw) or default
    when "boolean"
      return true  if raw == "1" or raw == "true"
      return false if raw == "0" or raw == "false"
      default
    else raw

--- Résout la configuration complète : UCI en surcharge, config.moon en défaut.
-- @treturn table Configuration résolue (mêmes clés que config.moon)
resolve = ->
  cfg = {}
  for k, v in pairs C
    option = k\lower!
    if type(v) == "table"
      cfg[k] = uci_get_list(option) or v
    else
      raw = uci_get option
      cfg[k] = if raw then coerce(raw, v) else v
  cfg

-- ── Génération Lua ────────────────────────────────────────────────

--- Sérialise une valeur Lua en littéral de code.
-- Supporte : number, boolean, string, table (array homogène).
-- @tparam any v
-- @treturn string
serialize = (v) ->
  switch type v
    when "number"  then tostring v
    when "boolean" then tostring v
    when "string"  then string.format '"%s"', v\gsub("\\", "\\\\")\gsub('"', '\\"')
    when "table"
      items = [serialize item for item in *v]
      #items == 0 and "{}" or "{ #{table.concat items, ', '} }"
    else error "serialize: type non supporté : #{type v} (#{tostring v})"

--- Génère le contenu complet de config.lua depuis la config résolue.
-- Toutes les clés de config.moon sont émises ; ordre alphabétique pour
-- un diff stable.
-- @tparam table cfg Configuration résolue
-- @treturn string Contenu Lua valide
generate_config = (cfg) ->
  lines = {
    "-- config.lua — généré par uci_config.lua depuis /etc/config/custos"
    "-- Ne pas modifier : écrasé au démarrage/rechargement du service."
    ""
  }
  keys = [k for k, _ in pairs cfg]
  table.sort keys
  for k in *keys
    table.insert lines, string.format "local %-32s = %s", k, serialize cfg[k]
  table.insert lines, ""
  table.insert lines, "return {"
  for k in *keys
    table.insert lines, string.format "  %-32s = %s,", k, k
  table.insert lines, "}"
  table.concat lines, "\n"

-- ── Point d'entrée ────────────────────────────────────────────────

main = ->
  cfg = resolve!

  if os.execute("mkdir -p #{OUTPUT_DIR}") ~= 0
    io.stderr\write "uci_config: impossible de créer #{OUTPUT_DIR}\n"
    os.exit 1

  tmp_path    = "#{OUTPUT_DIR}/config.lua.tmp"
  output_path = "#{OUTPUT_DIR}/config.lua"

  fh, err = io.open tmp_path, "w"
  unless fh
    io.stderr\write "uci_config: écriture impossible #{tmp_path}: #{err}\n"
    os.exit 1

  fh\write generate_config cfg
  fh\close!

  ok, mv_err = os.rename tmp_path, output_path
  unless ok
    io.stderr\write "uci_config: rename échoué: #{mv_err}\n"
    os.execute "rm -f #{tmp_path}"
    os.exit 1

  io.write "uci_config: #{output_path} écrit\n"

main!
