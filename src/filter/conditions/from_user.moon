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
-- @treturn function factory (user) → enriched_condition
-- Note: worker-only due to dynamic session lookup.
(cfg) ->
  sessions_file = (cfg.auth and cfg.auth.sessions_file) or config.auth.sessions_file

  (user) ->
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      worker_only: true
      user: user
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
      compile_nft: -> nil, "from_user requires worker (dynamic sessions)"
      creates_dynamic_scope: false
    }
