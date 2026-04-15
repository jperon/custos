-- src/filter/lib/load_config.moon
-- Charge une configuration de filtre depuis un fichier YAML.
--
-- Dépendance : lyaml (paquet Debian : lua-yaml / apt install lua-yaml).
-- Retourne une table compatible avec la structure attendue par filter/rule.moon
-- et les modules de conditions/actions.

ok, lyaml = pcall require, "lyaml"
unless ok
  error "lyaml introuvable — installer le paquet lua-yaml (apt install lua-yaml)"

--- Charge un fichier YAML de configuration du filtre.
-- Normalise la table résultante : les sections manquantes sont initialisées
-- à des tables vides pour éviter les nil dans le code appelant.
-- @tparam  string      path Chemin vers le fichier .yml
-- @treturn table|nil        Table de configuration, ou nil en cas d'erreur
-- @treturn nil|string       Message d'erreur
load_config = (path) ->
  fh, err = io.open path, "r"
  return nil, "impossible d'ouvrir #{path} : #{err}" unless fh
  content = fh\read "*a"
  fh\close!

  ok2, cfg = pcall lyaml.load, content
  return nil, "erreur de syntaxe YAML dans #{path} : #{cfg}" unless ok2
  return nil, "configuration vide ou invalide dans #{path}" unless type(cfg) == "table"

  -- Sections facultatives → tables vides par défaut
  cfg.nets             = cfg.nets             or {}
  cfg.macs             = cfg.macs             or {}
  cfg.times            = cfg.times            or {}
  cfg.sources          = cfg.sources          or {}
  cfg.rules            = cfg.rules            or {}
  cfg.users            = cfg.users            or {}
  cfg.ip_whitelist     = cfg.ip_whitelist     or {}
  -- cfg.custom_lists_dir : nil par défaut (chemin facultatif)

  -- Section auth : valeurs par défaut
  cfg.auth = cfg.auth or {}
  auth = cfg.auth
  auth.host              = auth.host              or "::"
  auth.port              = auth.port              or 33443
  auth.captive_port      = auth.captive_port      or 33080
  auth.session_ttl       = auth.session_ttl       or 86400
  auth.sessions_file     = auth.sessions_file     or "./tmp/sessions.lua"
  auth.heartbeat_interval = auth.heartbeat_interval or 30
  auth.idle_timeout      = auth.idle_timeout      or 120
  -- auth.cert, auth.key, auth.secrets : nil par défaut (optionnels)

  cfg, nil

{ :load_config }
