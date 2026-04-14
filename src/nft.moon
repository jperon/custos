-- src/nft.moon
-- Interface avec nftables via libnftables FFI.
-- Permet d'ajouter des IPs dans les sets ip4_allowed / ip6_allowed
-- sans fork() ni popen() — le contexte nft_ctx est réutilisé.

{ :ffi, :libnft } = require "ffi_defs"
{ :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_SET_MAC4, :NFT_SET_MAC6, :NFT_IP_TIMEOUT } = require "config"
{ :log_warn, :log_error } = require "log"

-- ── Initialisation du contexte ───────────────────────────────────
-- NFT_CTX_DEFAULT = 0
ctx = libnft.nft_ctx_new 0
error "nft_ctx_new() échoué" if ctx == nil

-- Silencer les sorties stdout/stderr du contexte nft
-- (on gère nos propres logs)
-- nft_ctx_set_output_fp et nft_ctx_set_error_fp nécessitent libc FILE* ;
-- on utilise plutôt dry_run=false et on ignore les sorties.

-- ── Exécution d'une commande nft ─────────────────────────────────
-- Retourne true si succès, false + log si erreur.
run_cmd = (cmd) ->
  rc = libnft.nft_run_cmd_from_buffer ctx, cmd
  if rc != 0
    log_warn { action: "nft_cmd_failed", cmd: cmd, rc: rc }
    return false
  true

-- ── API publique ─────────────────────────────────────────────────

--- Ajoute une paire (client IPv4, destination IPv4) dans le set ip4_allowed.
-- @tparam string client_ip Adresse IPv4 du client LAN (ex: "192.168.1.50")
-- @tparam string ip_str    Adresse IPv4 de destination (ex: "1.2.3.4")
-- @treturn boolean true si succès
add_ip4 = (client_ip, ip_str) ->
  cmd = "add element ip #{NFT_TABLE} #{NFT_SET_IP4} { #{client_ip} . #{ip_str} timeout #{NFT_IP_TIMEOUT} }"
  run_cmd cmd

--- Ajoute une paire (client IPv6, destination IPv6) dans le set ip6_allowed.
-- @tparam string client_ip Adresse IPv6 du client LAN (ex: "fd00:28::1")
-- @tparam string ip_str    Adresse IPv6 de destination (ex: "2001:db8::1")
-- @treturn boolean true si succès
add_ip6 = (client_ip, ip_str) ->
  cmd = "add element ip6 #{NFT_TABLE} #{NFT_SET_IP6} { #{client_ip} . #{ip_str} timeout #{NFT_IP_TIMEOUT} }"
  run_cmd cmd

--- Ajoute une paire (client, destination), famille détectée par ':' dans ip_str.
-- client_ip et ip_str doivent être de la même famille (IPv4 ou IPv6).
-- @tparam string client_ip Adresse IP du client LAN
-- @tparam string ip_str    Adresse IP de destination
-- @treturn boolean true si succès
add_ip = (client_ip, ip_str) ->
  if ip_str\find ":"
    add_ip6 client_ip, ip_str
  else
    add_ip4 client_ip, ip_str

--- Ajoute une paire (MAC client, destination IPv4) dans le set mac4_allowed.
-- @tparam string mac    Adresse MAC du client LAN (ex: "aa:bb:cc:dd:ee:ff")
-- @tparam string ip_str Adresse IPv4 de destination (ex: "1.2.3.4")
-- @treturn boolean true si succès
add_mac4 = (mac, ip_str) ->
  cmd = "add element ip #{NFT_TABLE} #{NFT_SET_MAC4} { #{mac} . #{ip_str} timeout #{NFT_IP_TIMEOUT} }"
  run_cmd cmd

--- Ajoute une paire (MAC client, destination IPv6) dans le set mac6_allowed.
-- @tparam string mac    Adresse MAC du client LAN (ex: "aa:bb:cc:dd:ee:ff")
-- @tparam string ip_str Adresse IPv6 de destination (ex: "2001:db8::1")
-- @treturn boolean true si succès
add_mac6 = (mac, ip_str) ->
  cmd = "add element ip6 #{NFT_TABLE} #{NFT_SET_MAC6} { #{mac} . #{ip_str} timeout #{NFT_IP_TIMEOUT} }"
  run_cmd cmd

--- Libère le contexte nftables (appelé à l'arrêt du processus).
-- @treturn nil
cleanup = ->
  libnft.nft_ctx_free ctx if ctx != nil

{ :add_ip4, :add_ip6, :add_ip, :add_mac4, :add_mac6, :run_cmd, :cleanup }
