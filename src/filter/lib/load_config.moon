-- src/filter/lib/load_config.moon
-- Charge une configuration de filtre depuis un fichier MoonScript ou Lua.
-- Retourne une table compatible avec la structure attendue par filter/rule.moon
-- et les modules de conditions/actions.

moon_base = require "moonscript.base"

--- Charge un fichier de configuration du filtre (MoonScript ou Lua).
-- Normalise la table résultante : les sections manquantes sont initialisées
-- à des tables vides pour éviter les nil dans le code appelant.
-- @tparam  string      path Chemin vers le fichier .moon/.lua
-- @treturn table|nil        Table de configuration, ou nil en cas d'erreur
-- @treturn nil|string       Message d'erreur
load_config = (path) ->
  chunk, load_err = moon_base.loadfile path
  return nil, "impossible de charger #{path} : #{load_err}" unless chunk

  ok2, cfg = pcall chunk
  return nil, "erreur à l'exécution de #{path} : #{cfg}" unless ok2
  return nil, "configuration vide ou invalide dans #{path}" unless type(cfg) == "table"

  -- Sections facultatives → tables vides par défaut
  cfg.nets             = cfg.nets             or {}
  cfg.macs             = cfg.macs             or {}
  cfg.times            = cfg.times            or {}
  cfg.sources          = cfg.sources          or {}
  cfg.rules            = cfg.rules            or {}
  cfg.users            = cfg.users            or {}
  cfg.userlists        = cfg.userlists        or cfg.users or {}
  cfg.users            = cfg.users            or cfg.userlists or {}
  cfg.dest_whitelist     = cfg.dest_whitelist     or {}

  -- Section auth : valeurs par défaut
  cfg.auth = cfg.auth or {}
  auth = cfg.auth
  auth.host              = auth.host              or "::"
  auth.port              = auth.port              or 33443
  auth.captive_port      = auth.captive_port      or 33080
  auth.session_ttl       = auth.session_ttl       or 0
  auth.sessions_file     = auth.sessions_file     or "/tmp/sessions.lua"
  auth.heartbeat_interval = auth.heartbeat_interval or 30
  auth.idle_timeout      = auth.idle_timeout      or 120
  auth.secrets           = auth.secrets           or "/etc/custos/secrets"
  auth.sni_verdict       = auth.sni_verdict       or {}
  auth.sni_verdict.enabled = if auth.sni_verdict.enabled == nil then true else not not auth.sni_verdict.enabled
  auth.sni_verdict.mode = auth.sni_verdict.mode or "strict-443"
  auth.sni_verdict.protocols = auth.sni_verdict.protocols or "both"
  auth.sni_verdict.nft_failure_policy = auth.sni_verdict.nft_failure_policy or "fail-closed"

  cfg, nil

{ :load_config }
