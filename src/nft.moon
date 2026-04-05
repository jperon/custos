-- src/nft.moon
-- Interface avec nftables via libnftables FFI.
-- Permet d'ajouter des IPs dans les sets ip4_allowed / ip6_allowed
-- sans fork() ni popen() — le contexte nft_ctx est réutilisé.

{ :ffi, :libnft } = require "ffi_defs"
{ :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_IP_TIMEOUT } = require "config"
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

--- Ajoute une adresse IPv4 dans le set ip4_allowed avec timeout.
-- @tparam string ip_str Adresse IPv4 (ex: "1.2.3.4")
-- @treturn boolean true si succès
add_ip4 = (ip_str) ->
  cmd = "add element ip #{NFT_TABLE} #{NFT_SET_IP4} { #{ip_str} timeout #{NFT_IP_TIMEOUT} }"
  run_cmd cmd

--- Ajoute une adresse IPv6 dans le set ip6_allowed avec timeout.
-- @tparam string ip_str Adresse IPv6 (ex: "2001:db8::1")
-- @treturn boolean true si succès
add_ip6 = (ip_str) ->
  cmd = "add element ip6 #{NFT_TABLE} #{NFT_SET_IP6} { #{ip_str} timeout #{NFT_IP_TIMEOUT} }"
  run_cmd cmd

--- Ajoute une IP (v4 ou v6 détecté par la présence de ':').
-- @tparam string ip_str Adresse IP sous forme de chaîne
-- @treturn boolean true si succès
add_ip = (ip_str) ->
  if ip_str\find ":"
    add_ip6 ip_str
  else
    add_ip4 ip_str

--- Libère le contexte nftables (appelé à l'arrêt du processus).
-- @treturn nil
cleanup = ->
  libnft.nft_ctx_free ctx if ctx != nil

{ :add_ip4, :add_ip6, :add_ip, :run_cmd, :cleanup }
