-- src/nft.moon
-- Interface avec nftables via libnftables FFI.
-- Permet d'ajouter des IPs dans les sets ip4_allowed / ip6_allowed
-- sans fork() ni popen() — le contexte nft_ctx est réutilisé.

{ :ffi, :libnft } = require "ffi_defs"
config = require "config"
{ :log_warn, :log_error } = require "log"

-- ── Initialisation du contexte ───────────────────────────────────
-- NFT_CTX_DEFAULT = 0
ctx = libnft.nft_ctx_new 0
error "nft_ctx_new() échoué" if ctx == nil
ok_buf = pcall -> libnft.nft_ctx_buffer_error ctx

get_error_buffer = ->
  return nil unless ok_buf
  ok, ptr = pcall -> libnft.nft_ctx_get_error_buffer ctx
  return nil unless ok and ptr != nil
  msg = ffi.string ptr
  msg if msg and msg != ""

-- Silencer les sorties stdout/stderr du contexte nft
-- (on gère nos propres logs)
-- nft_ctx_set_output_fp et nft_ctx_set_error_fp nécessitent libc FILE* ;
-- on utilise plutôt dry_run=false et on ignore les sorties.

-- ── Exécution d'une commande nft ─────────────────────────────────
-- Retourne true si succès, false + log si erreur.
run_cmd = (cmd, opts=nil) ->
  rc = libnft.nft_run_cmd_from_buffer ctx, cmd
  if rc != 0
    ts = os.time!
    nft_err = get_error_buffer!
    busy = nft_err and nft_err\match "Resource busy"
    unless opts and opts.quiet
      log_warn { action: "nft_cmd_failed", cmd: cmd, rc: rc, ts: ts, nft_err: nft_err or "", transient: busy and "resource_busy" or "" }
    return false, nft_err
  true, nil

-- ── API publique ─────────────────────────────────────────────────

--- Ajoute une paire (client IPv4, destination IPv4) dans le set ip4_allowed.
-- @tparam string client_ip Adresse IPv4 du client LAN (ex: "192.168.1.50")
-- @tparam string ip_str    Adresse IPv4 de destination (ex: "1.2.3.4")
-- @treturn boolean true si succès
add_ip4 = (client_ip, ip_str) ->
  cmd = "add element #{config.nft.family} #{config.nft.table} #{config.nft.set_ip4} { #{client_ip} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  run_cmd cmd

add_ip4_quiet = (client_ip, ip_str) ->
  cmd = "add element #{config.nft.family} #{config.nft.table} #{config.nft.set_ip4} { #{client_ip} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  ok, err = run_cmd cmd, { quiet: true }
  ok, err or "nft add ip4 failed"

--- Ajoute une paire (client IPv6, destination IPv6) dans le set ip6_allowed.
-- @tparam string client_ip Adresse IPv6 du client LAN (ex: "fd00:28::1")
-- @tparam string ip_str    Adresse IPv6 de destination (ex: "2001:db8::1")
-- @treturn boolean true si succès
add_ip6 = (client_ip, ip_str) ->
  return false unless client_ip\find ":"
  cmd = "add element #{config.nft.family6} #{config.nft.table} #{config.nft.set_ip6} { #{client_ip} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  run_cmd cmd

add_ip6_quiet = (client_ip, ip_str) ->
  return false unless client_ip\find ":"
  cmd = "add element #{config.nft.family6} #{config.nft.table} #{config.nft.set_ip6} { #{client_ip} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  ok, err = run_cmd cmd, { quiet: true }
  ok, err or "nft add ip6 failed"

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
  return false unless config.nft.set_mac4
  cmd = "add element #{config.nft.family} #{config.nft.table} #{config.nft.set_mac4} { #{mac} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  run_cmd cmd

add_mac4_quiet = (mac, ip_str) ->
  return false unless config.nft.set_mac4
  cmd = "add element #{config.nft.family} #{config.nft.table} #{config.nft.set_mac4} { #{mac} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  ok, err = run_cmd cmd, { quiet: true }
  ok, err or "nft add mac4 failed"

--- Ajoute une paire (MAC client, destination IPv6) dans le set mac6_allowed.
-- @tparam string mac    Adresse MAC du client LAN (ex: "aa:bb:cc:dd:ee:ff")
-- @tparam string ip_str Adresse IPv6 de destination (ex: "2001:db8::1")
-- @treturn boolean true si succès
add_mac6 = (mac, ip_str) ->
  return false unless config.nft.set_mac6
  cmd = "add element #{config.nft.family6} #{config.nft.table} #{config.nft.set_mac6} { #{mac} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  run_cmd cmd

add_mac6_quiet = (mac, ip_str) ->
  return false unless config.nft.set_mac6
  cmd = "add element #{config.nft.family6} #{config.nft.table} #{config.nft.set_mac6} { #{mac} . #{ip_str} timeout #{config.nft.ip_timeout} }"
  ok, err = run_cmd cmd, { quiet: true }
  ok, err or "nft add mac6 failed"

--- Libère le contexte nftables (appelé à l'arrêt du processus).
-- @treturn nil
cleanup = ->
  libnft.nft_ctx_free ctx if ctx != nil

{
  :add_ip4, :add_ip6, :add_ip, :add_mac4, :add_mac6
  :add_ip4_quiet, :add_ip6_quiet, :add_mac4_quiet, :add_mac6_quiet
  :run_cmd, :cleanup
}
