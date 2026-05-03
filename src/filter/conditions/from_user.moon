-- src/filter/conditions/from_user.moon
-- Condition : vérifie si l'IP source a une session authentifiée active
-- pour l'utilisateur spécifié.
--
-- Supporte les valeurs spéciales :
--   - "_any" : match si n'importe quel utilisateur est authentifié.
--   - "_none" : match si aucun utilisateur n'est authentifié.
--
-- Le fichier de sessions est maintenu par le worker AUTH (auth/worker.moon)
-- et lu ici via un cache TTL de 5 secondes (sessions.read_cached).
-- Le chemin du fichier est issu de cfg.auth.sessions_file (ou la constante
-- AUTH_SESSIONS_FILE par défaut).

{ :session_for_mac, :enrich_session_ip, :bind_session_mac } = require "auth.sessions"
{ :AUTH_SESSIONS_FILE } = require "config"

-- get_mac est optionnel et utilisé seulement si le MAC learner est dispo
_get_mac = nil
_get_mac_tried = false
safe_get_mac = (ip_str) ->
  return nil unless ip_str
  if not _get_mac_tried
    _get_mac_tried = true
    ok, mod = pcall -> require "mac_learner_ipc"
    return nil unless ok
    _get_mac = mod.get_mac
  return nil unless _get_mac
  _get_mac ip_str

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (user: string) → (req) → bool, reason
(cfg) ->
  sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE

  (user) ->
    --- @tparam table req {src_ip: string, mac: string, ...}
    -- @treturn boolean, string
    (req) ->
      -- session_for_mac indexée par MAC évite le coût du fallback par get_mac
      -- dans la majorité des cas en mode bridge.
      s = session_for_mac req.mac, req.src_ip, sessions_file

      -- TODO: fallback via get_mac sera ajouté plus tard
      -- (actuellement causant issues au déploiement)

      if user == "_any"
        if s
          bind_session_mac s.mac, req.mac, req.src_ip, sessions_file
          enrich_session_ip req.mac, req.src_ip, sessions_file
        return s ~= nil, "from_user: session active (#{s and s.user or 'unknown'})"
      if user == "_none"
        return s == nil, "from_user: aucune session active"

      unless s
        return false, "from_user: aucune session valide pour #{req.src_ip}"
      if s.user ~= user
        return false, "from_user: #{req.src_ip} authentifié en tant que #{s.user}, attendu #{user}"

      -- Enrichir/réindexer la session avec la MAC courante (accumule IPv4+IPv6
      -- en disque). Cas important : authentification HTTPS via IPv6 routée où
      -- AUTH voit la MAC du routeur, puis DNS voit la vraie MAC cliente.
      bind_session_mac s.mac, req.mac, req.src_ip, sessions_file
      enrich_session_ip req.mac, req.src_ip, sessions_file

      true, "from_user: #{req.src_ip} → #{s.user}"
