-- src/nft.moon
-- Interface avec nftables via libnftables FFI : exécution de commandes avec
-- un contexte réutilisé (ni fork() ni popen()).
-- Les insertions de sets passent par nft_queue/worker_nft ; ce module ne
-- fournit que run_cmd et cleanup.

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
      log_warn -> { action: "nft_cmd_failed", cmd: cmd, rc: rc, ts: ts, nft_err: nft_err or "", transient: busy and "resource_busy" or "" }
    return false, nft_err
  true, nil

-- ── API publique ─────────────────────────────────────────────────

--- Libère le contexte nftables (appelé à l'arrêt du processus).
-- @treturn nil
cleanup = ->
  libnft.nft_ctx_free ctx if ctx != nil

{ :run_cmd, :cleanup }
