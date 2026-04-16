-- src/auth/nft_sessions.moon
-- Gestion des IPs authentifiées dans les sets nft du portail captif.
--
-- Utilisé exclusivement par le worker AUTH (processus séparé).
-- Charge libnftables directement via FFI minimal, sans dépendance à ffi_defs.moon.
-- Chaque ajout/retrait est appliqué immédiatement via nft_run_cmd_from_buffer.

{ :ffi, :libnft } = require "ffi_defs"

ctx = libnft.nft_ctx_new 0
error "nft_ctx_new() failed in auth worker" if ctx == nil

{ :NFT_FAMILY, :NFT_TABLE } = require "config"
NFT_SET4    = "authenticated_ips"
NFT_SET6    = "authenticated_ips6"
NFT_SET_MAC = "authenticated_macs"

--- Exécute une commande nft via FFI.
-- @tparam  string  cmd  Commande nft (ex. "add element ip … { … }")
-- @treturn boolean      true si succès (rc == 0)
run_nft = (cmd) ->
  rc = libnft.nft_run_cmd_from_buffer ctx, cmd
  rc == 0

--- Ajoute une IPv4 authentifiée dans le set nft avec TTL.
-- @tparam string ip  Adresse IPv4 du client
-- @tparam number ttl Durée de vie en secondes
-- @treturn boolean   true si succès
add_authenticated4 = (ip, ttl) ->
  run_nft "add element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET4} { #{ip} timeout #{ttl}s }"

--- Retire une IPv4 du set (logout explicite).
-- @tparam string ip  Adresse IPv4 du client
-- @treturn boolean   true si succès
del_authenticated4 = (ip) ->
  run_nft "delete element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET4} { #{ip} }"

--- Ajoute une IPv6 authentifiée dans le set nft avec TTL.
-- @tparam string ip  Adresse IPv6 du client
-- @tparam number ttl Durée de vie en secondes
-- @treturn boolean   true si succès
add_authenticated6 = (ip, ttl) ->
  run_nft "add element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET6} { #{ip} timeout #{ttl}s }"

--- Retire une IPv6 du set (logout explicite).
-- @tparam string ip  Adresse IPv6 du client
-- @treturn boolean   true si succès
del_authenticated6 = (ip) ->
  run_nft "delete element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET6} { #{ip} }"

--- Dispatche add_authenticated vers IPv4 ou IPv6 selon la présence de ':' dans l'IP.
-- @tparam string ip  Adresse IP du client (IPv4 ou IPv6)
-- @tparam number ttl Durée de vie en secondes
-- @treturn boolean   true si succès
add_authenticated = (ip, ttl) ->
  if ip\find ":"
    add_authenticated6 ip, ttl
  else
    add_authenticated4 ip, ttl

--- Dispatche del_authenticated vers IPv4 ou IPv6.
-- @tparam string ip  Adresse IP du client
-- @treturn boolean   true si succès
del_authenticated = (ip) ->
  if ip\find ":"
    del_authenticated6 ip
  else
    del_authenticated4 ip

--- Ajoute un MAC authentifié dans les sets ip et ip6 en une seule transaction nft.
-- Les sets authenticated_macs existent dans table ip et table ip6 (br_netfilter
-- expose le L2 dans les hooks L3 prerouting, évitant la dépendance au bridge mark).
-- @tparam string mac Adresse MAC du client (format "aa:bb:cc:dd:ee:ff")
-- @tparam number ttl Durée de vie en secondes
-- @treturn boolean   true si les deux insertions réussissent
add_authenticated_mac = (mac, ttl) ->
  run_nft "add element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET_MAC} { #{mac} timeout #{ttl}s }"

--- Retire un MAC des sets ip et ip6 (logout explicite ou expiration de session).
-- @tparam string mac Adresse MAC du client (format "aa:bb:cc:dd:ee:ff")
-- @treturn boolean   true si les deux suppressions réussissent
del_authenticated_mac = (mac) ->
  run_nft "delete element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET_MAC} { #{mac} }"

--- Libère le contexte nft (appelé à l'arrêt du worker AUTH).
cleanup = ->
  libnft.nft_ctx_free ctx if ctx != nil

{ :add_authenticated4, :del_authenticated4,
  :add_authenticated6, :del_authenticated6,
  :add_authenticated,  :del_authenticated,
  :add_authenticated_mac, :del_authenticated_mac,
  :cleanup }
