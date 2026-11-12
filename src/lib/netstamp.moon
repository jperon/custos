-- src/lib/netstamp.moon
-- Active l'horodatage noyau des paquets reçus (static key
-- `netstamp_needed_key`), sans lequel NFQUEUE ne joint jamais NFQA_TIMESTAMP
-- et le délestage précoce des questions (`nfqueue.max_age_ms`) reste
-- silencieusement inerte.
--
-- Le noyau n'horodate un paquet à la réception que si `netstamp_needed_key`
-- est active (include/linux/skbuff.h, `skb_tstamp_cond`). Un seul socket avec
-- `SO_TIMESTAMP` suffit à l'activer pour tout le système ; il doit rester
-- ouvert, sinon la clé retombe. On ouvre donc un socket UDP sans bind ni
-- trafic, conservé jusqu'à la fin du processus (jamais fermé).
--
-- Constantes (voir src/ffi_defs.moon et les en-têtes Linux v6.12) :
--   include/uapi/asm-generic/socket.h : SO_TIMESTAMP_OLD = 29,
--     SO_TIMESTAMP_NEW = 63 ; sur x86_64/arm/arm64, SO_TIMESTAMP = OLD = 29.
--   arch/mips/include/uapi/asm/socket.h : SO_TIMESTAMP_OLD = 29, mais
--     SOL_SOCKET = 0xffff (au lieu de 1). Sur 32 bits avec time_t 64 bits
--     (musl d'OpenWrt), SO_TIMESTAMP vaut SO_TIMESTAMP_NEW (63).
-- Le noyau accepte indifféremment OLD et NEW à setsockopt ; seul le format
-- d'horodatage livré change, et ce socket n'est jamais lu. On essaie donc les
-- deux variantes, et les deux niveaux SOL_SOCKET (générique puis MIPS).
--
-- Un échec n'est pas fatal : WARN `netstamp_enable_failed` et poursuite du
-- worker ; le délestage sera simplement inactif (comportement historique).

{ :ffi, :libc, :SO_TIMESTAMP, :SO_TIMESTAMP_NEW, :SOL_SOCKET,
  :SOL_SOCKET_MIPS } = require "ffi_defs"
{ :log_warn } = require "log"

AF_INET    = 2
SOCK_DGRAM = 2

_fd = nil

--- Ouvre un socket UDP et active SO_TIMESTAMP dessus.
-- Aucun bind, aucun trafic : le socket ne sert qu'à maintenir active la
-- static key `netstamp_needed_key`. Il est rendu à l'appelant, qui doit le
-- conserver (ne jamais le fermer).
-- @tparam table c Table libc (ffi.C en production, faux libc en test).
-- @treturn number|nil fd du socket, ou nil si l'activation a échoué (WARN).
open_socket = (c) ->
  fd = c.socket AF_INET, SOCK_DGRAM, 0
  unless fd and fd >= 0
    errno = tonumber c.__errno_location()[0]
    log_warn -> { action: "netstamp_enable_failed", stage: "socket", errno: errno }
    return nil
  one    = ffi.new "int[1]", 1
  optlen = ffi.sizeof "int"
  last_errno = 0
  for sol in *{ SOL_SOCKET, SOL_SOCKET_MIPS }
    for ts in *{ SO_TIMESTAMP, SO_TIMESTAMP_NEW }
      rc = c.setsockopt fd, sol, ts, one, optlen
      return fd if rc == 0
      last_errno = tonumber c.__errno_location()[0]
  -- Toutes les variantes ont échoué : ne pas laisser fuiter le fd.
  c.close fd
  log_warn -> { action: "netstamp_enable_failed", stage: "setsockopt", errno: last_errno }
  nil

--- Active l'horodatage noyau (une fois au démarrage du worker).
-- @treturn number|nil fd conservé, ou nil en cas d'échec (WARN, non fatal).
enable = ->
  _fd = open_socket libc
  _fd

--- fd du socket d'horodatage, ou nil si l'activation a échoué.
-- @treturn number|nil
get_fd = -> _fd

{ :enable, :get_fd, :open_socket, :AF_INET, :SOCK_DGRAM,
  :SO_TIMESTAMP, :SO_TIMESTAMP_NEW, :SOL_SOCKET, :SOL_SOCKET_MIPS }
