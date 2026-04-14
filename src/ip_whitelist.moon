-- src/ip_whitelist.moon
-- Gestion des sets nft ip4_dest_whitelist / ip6_dest_whitelist.
--
-- Ces sets contiennent des destinations statiques (IPs ou CIDRs) accessibles
-- par n'importe quel client, sans résolution DNS préalable.
-- Rechargeable à chaud via filter.reload() (déclenché par SIGHUP sur Q0).

ffi = require "ffi"

ffi.cdef [[
  typedef struct nft_ctx nft_ctx;
  nft_ctx* nft_ctx_new(unsigned int flags);
  void     nft_ctx_free(nft_ctx *ctx);
  int      nft_run_cmd_from_buffer(nft_ctx *ctx, const char *buf);
]]

libnft = ffi.load "libnftables.so.1"

ctx = libnft.nft_ctx_new 0
error "nft_ctx_new() échoué dans ip_whitelist" if ctx == nil

TABLE = "dns-filter"
SET4  = "ip4_dest_whitelist"
SET6  = "ip6_dest_whitelist"

--- Exécute une commande nft via FFI.
-- @tparam  string  cmd Commande nft
-- @treturn boolean     true si succès (rc == 0)
run_nft = (cmd) ->
  rc = libnft.nft_run_cmd_from_buffer ctx, cmd
  rc == 0

--- Peuple ip4_dest_whitelist et ip6_dest_whitelist depuis une liste d'IPs/CIDRs.
-- Purge d'abord les deux sets, puis ajoute les entrées.
-- Supporte les adresses simples (10.0.0.1) et les CIDRs (10.0.0.0/24).
-- La famille est détectée par la présence de ':' (IPv6) ou son absence (IPv4).
-- @tparam table entries  Liste de strings (IPs ou CIDRs, IPv4 ou IPv6). Peut être vide.
-- @treturn nil
init = (entries) ->
  run_nft "flush set ip  #{TABLE} #{SET4}"
  run_nft "flush set ip6 #{TABLE} #{SET6}"
  return if not entries or #entries == 0

  v4, v6 = {}, {}
  for e in *entries
    e = tostring(e)\gsub "%s+", ""
    continue if #e == 0
    if e\find ":"
      v6[#v6 + 1] = e
    else
      v4[#v4 + 1] = e

  if #v4 > 0
    run_nft "add element ip  #{TABLE} #{SET4} { #{table.concat v4, ", "} }"
  if #v6 > 0
    run_nft "add element ip6 #{TABLE} #{SET6} { #{table.concat v6, ", "} }"

--- Libère le contexte nftables (appelé à l'arrêt du processus).
-- @treturn nil
cleanup = ->
  libnft.nft_ctx_free ctx if ctx != nil

{ :init, :cleanup }
