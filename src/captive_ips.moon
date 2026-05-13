-- src/captive_ips.moon
-- Détection des adresses IP du portail captif.
-- Factorisé pour être partagé entre worker_captive (captive, construction des URLs
-- de redirection TCP) et worker_questions (question, forge des réponses DNS).
--
-- Ordre de priorité :
--   1. auth_cfg.captive_ip4 / auth_cfg.captive_ip6 (config explicite)
--   2. Variables d'environnement CAPTIVE_IP4 / CAPTIVE_IP6
--   3. Auto-détection via `ip addr show dev <bridge>` (IPv4 puis IPv6)
--   4. Fallback IPv4 via socket.connect (heuristique)

{ :log_info, :log_warn } = require "log"

--- Détecte les adresses IPv4 et IPv6 du portail captif.
-- Lit d'abord la configuration explicite et les variables d'environnement,
-- puis tente une auto-détection sur l'interface bridge si nécessaire.
-- Aucun appel ne lève d'exception : toutes les erreurs sont absorbées.
-- @tparam table auth_cfg Configuration auth issue de config.moon (peut être {})
-- @treturn string|nil Adresse IPv4 du portail captif, ou nil si introuvable
-- @treturn string|nil Adresse IPv6 du portail captif, ou nil si introuvable
detect = (auth_cfg) ->
  auth_cfg or= {}
  ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"

  -- ── 1 & 2 : config explicite + variables d'environnement ─────
  local_ip4 = auth_cfg.captive_ip4 or os.getenv "CAPTIVE_IP4"
  local_ip6 = auth_cfg.captive_ip6 or os.getenv "CAPTIVE_IP6"

  -- ── 3a : auto-détection IPv4 via `ip addr show dev <bridge>` ─
  if not local_ip4
    ok, out = pcall ->
      fh = io.popen "ip -4 addr show dev #{ifname} scope global 2>/dev/null | awk '/inet/{print $2}' | head -1 | cut -d'/' -f1"
      return nil unless fh
      s = fh\read "*a"
      fh\close!
      s\gsub "%s+", ""
    if ok and out and out != "" and out != "0.0.0.0"
      local_ip4 = out
      log_info { action: "captive_ip4_autodetected", ip: local_ip4, ifname: ifname }

  -- ── 4 : fallback IPv4 via socket.connect ─────────────────────
  if not local_ip4
    ok_sock, socket = pcall require, "socket"
    if ok_sock
      pcall ->
        ok_udp, u = pcall socket.udp
        u = ok_udp and u or nil
        if u
          ok_conn, _ = pcall u.connect, u, "1.1.1.1", 80
          if ok_conn
            ok_get, ip = pcall u.getsockname, u
            if ok_get and ip and ip != "" and ip != "0.0.0.0"
              local_ip4 = ip
              log_info { action: "captive_ip4_autodetected_socket", ip: local_ip4 }
          u\close!

  -- ── 3b : auto-détection IPv6 via `ip addr show dev <bridge>` ──
  if not local_ip6
    ok, ip = pcall ->
      f = io.popen "ip -6 addr show dev #{ifname} scope global 2>/dev/null | awk '/inet6/{print $2}' | head -1 | cut -d'/' -f1"
      return nil unless f
      addr = f\read "*a"
      f\close!
      addr\gsub "%s+", ""
    if ok and ip and ip != "" and ip != "::"
      local_ip6 = ip
      log_info { action: "captive_ip6_autodetected", ip: local_ip6, ifname: ifname }

  local_ip4, local_ip6

{ :detect }
