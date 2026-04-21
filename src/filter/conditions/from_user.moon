-- src/filter/conditions/from_user.moon
-- Condition : vérifie si l'IP source a une session authentifiée active
-- pour l'utilisateur spécifié.
--
-- Le fichier de sessions est maintenu par le worker AUTH (auth/worker.moon)
-- et lu ici via un cache TTL de 5 secondes (sessions.read_cached).
-- Le chemin du fichier est issu de cfg.auth.sessions_file (ou la constante
-- AUTH_SESSIONS_FILE par défaut).

{ :session_for_ip } = require "auth.sessions"
{ :AUTH_SESSIONS_FILE } = require "config"

--- @tparam table cfg Configuration du filtre (cfg.auth.sessions_file optionnel)
-- @treturn function factory (user: string) → (req) → bool, reason
(cfg) ->
  sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE

  (user) ->
    --- @tparam table req {src_ip: string, ...}
    -- @treturn boolean, string
    (req) ->
      -- session_for_ip gère le fallback cross-family par MAC (un client
      -- authentifié en IPv6 est reconnu sur ses paquets IPv4 et vice-versa)
      -- et vérifie expiration + heartbeat. req.mac provient directement du
      -- paquet (L2), plus fiable que la table neigh locale en mode bridge.
      s = session_for_ip req.src_ip, sessions_file, req.mac

      unless s
        return false, "from_user: aucune session valide pour #{req.src_ip}"
      if s.user ~= user
        return false, "from_user: #{req.src_ip} authentifié en tant que #{s.user}, attendu #{user}"

      true, "from_user: #{req.src_ip} → #{s.user}"
