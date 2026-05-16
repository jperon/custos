-- src/filter/conditions/from_user.moon
-- Condition : vérifie si l'IP source a une session authentifiée active
-- pour l'utilisateur spécifié.
--
-- Supporte les valeurs spéciales :
--   - "_any" : match si n'importe quel utilisateur est authentifié.
--   - "_none" : match si aucun utilisateur n'est authentifié.
--
-- Sources de sessions configurables via le paramètre 'source':
--   - "sessions_file" (défaut) : fichier de sessions maintenu par worker AUTH
--   - "tls" ou "user_sessions" : sessions TLS/certificate via user_sessions
--
-- Le chemin du fichier est issu de cfg.auth.sessions_file (ou la constante
-- AUTH_SESSIONS_FILE par défaut).

{ :session_for_mac, :enrich_session_ip, :bind_session_mac } = require "auth.sessions"
{ :get_session } = require "auth.user_sessions"
config = require "config"

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

--- @tparam table cfg Configuration
-- @treturn function factory (user_or_opts) → enriched_condition
-- Note: worker-only due to dynamic session lookup.
(cfg) ->
  sessions_file = (cfg.auth and cfg.auth.sessions_file) or config.auth.sessions_file

  (user_or_opts) ->
    -- Détecter si on reçoit un string ou une table d'options
    user = user_or_opts
    source = "sessions_file"  -- défaut

    if type(user_or_opts) == "table"
      user = user_or_opts.user
      source = user_or_opts.source or source

    unless user
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "from_user: no user specified"
      }

    -- Source TLS/user_sessions (anciennement from_authenticated_user)
    if source == "tls" or source == "user_sessions"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        user: user
        source: source
        eval: (req) ->
          session = get_session user
          unless session
            return false, "from_user: user #{user} not authenticated (tls)"
          if req.src_ip and session.src_ip ~= req.src_ip
            return false, "from_user: IP mismatch for #{user} (tls)"
          if req.mac and session.mac ~= req.mac\lower()
            return false, "from_user: MAC mismatch for #{user} (tls)"
          true, "from_user: user #{user} authenticated (tls)"
      }

    -- Source sessions_file (défaut)
    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      user: user
      source: source
      eval: (req) ->
        hinted_user = req.user

        if hinted_user and hinted_user ~= "unknown"
          if user == "_any"
            return true, "from_user: session active (#{hinted_user})"
          if user == "_none"
            return false, "from_user: une session est déjà identifiée (#{hinted_user})"
          if hinted_user == user
            mac = req.mac
            unless mac
              mac = safe_get_mac req.src_ip
            s = session_for_mac mac, req.src_ip, sessions_file
            if s
              bind_session_mac s.mac, req.mac, req.src_ip, sessions_file
              enrich_session_ip req.mac, req.src_ip, sessions_file
            return true, "from_user: #{req.src_ip} → #{hinted_user}"

        -- session_for_mac indexée par MAC
        mac = req.mac
        unless mac
          mac = safe_get_mac req.src_ip
        s = session_for_mac mac, req.src_ip, sessions_file

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

        bind_session_mac s.mac, req.mac, req.src_ip, sessions_file
        enrich_session_ip req.mac, req.src_ip, sessions_file

        true, "from_user: #{req.src_ip} → #{s.user}"
    }
