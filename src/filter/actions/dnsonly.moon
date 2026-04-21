-- src/filter/actions/dnsonly.moon
-- Action : autoriser la résolution DNS mais ne pas ajouter les IPs dans
-- les sets nft (les redirections HTTP/80 restent actives — captive portal).
--
-- Retourne "dnsonly" (valeur truthy distincte de `true`).
-- Le worker Q0 la traite via write_dnsonly_msg ; Q1 patche le TTL + EDE
-- mais n'injecte aucune entrée dans mac4_allowed / mac6_allowed / ip4/ip6.
--
-- Cas particulier : si le client est déjà authentifié, `dnsonly` se comporte
-- comme `allow` (injection nft normale). Raison : le rôle du `dnsonly` est de
-- faire détecter l'état captif aux sondes (Firefox, Windows, macOS…) tant que
-- l'utilisateur n'est pas connecté. Une fois authentifié, ces mêmes sondes
-- doivent réussir pour retirer le bandeau « page de connexion du réseau ».

{ :session_for_ip } = require "auth.sessions"
{ :AUTH_SESSIONS_FILE } = require "config"

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → (req) → string|boolean, string
(cfg) ->
  sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE
  (rule) ->
    --- @tparam table req
    -- @treturn string|boolean, string
    (req) ->
      s = session_for_ip req.src_ip, sessions_file, req.mac
      if s
        return true, "allow (auth=#{s.user}) by rule: #{rule.description or '?'}"
      "dnsonly", "DNS only (no nft) by rule: #{rule.description or '?'}"
