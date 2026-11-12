-- tests/unit/nfq_loop_age_spec.moon
-- Couvre le calcul d'âge noyau utilisé par le délestage précoce
-- (nfqueue.max_age_ms) : conversion NFQA_TIMESTAMP → millisecondes, absence
-- d'attribut, et robustesse aux sauts d'horloge. Le vrai ffi_defs est chargé
-- une fois pour ses cdefs (timespec_t, struct timeval), puis remplacé par un
-- stub dont `libnfq.nfq_get_timestamp` est contrôlable.

ffi = require "ffi"
-- busted_setup précharge un stub ffi_defs : ses cdefs ne sont pas appliqués.
-- Charger lib.socket d'abord (il déclare struct timeval, pollfd, sockaddr_in6
-- dans un bloc atomique) : déclarer timeval avant le ferait échouer en bloc.
pcall require, "lib.socket"
pcall ffi.cdef, [[struct timeval { long tv_sec; long tv_usec; };]]
real_ffi_defs = require "ffi_defs"

saved_ffi_defs = package.loaded["ffi_defs"]
saved_nfq_loop = package.loaded["nfq_loop"]

-- Recharge nfq_loop avec un stub libnfq. `get_ts` nil = symbole absent.
load_with = (get_ts) ->
  libnfq = {}
  libnfq.nfq_get_timestamp = get_ts if get_ts
  package.loaded["ffi_defs"] = {
    :ffi
    libc: real_ffi_defs.libc
    :libnfq
  }
  package.loaded["nfq_loop"] = nil
  require "nfq_loop"

describe "nfq_loop.packet_age_ms", ->
  after_each ->
    package.loaded["ffi_defs"] = saved_ffi_defs
    package.loaded["nfq_loop"] = saved_nfq_loop

  it "rend nil quand le noyau n'a pas joint NFQA_TIMESTAMP (-1)", ->
    m = load_with (nfad, tv) -> -1
    assert.is_true m.have_packet_timestamp
    assert.is_nil m.packet_age_ms {}

  it "rend nil quand la libnetfilter_queue n'expose pas le symbole", ->
    m = load_with nil
    assert.is_false m.have_packet_timestamp
    assert.is_nil m.packet_age_ms {}

  it "rend nil sans nfad (callback de test)", ->
    m = load_with (nfad, tv) -> 0
    assert.is_nil m.packet_age_ms nil

  it "convertit l'horodatage noyau (sec/usec) en âge millisecondes", ->
    os_time = os.time
    m = load_with (nfad, tv) ->
      tv[0].tv_sec = os_time! - 2
      tv[0].tv_usec = 250000
      0
    age = m.packet_age_ms {}
    -- CLOCK_REALTIME a une partie fractionnaire (0-999 ms) que os.time tronque.
    assert.is_true age >= 1700, "âge trop faible : #{age}"
    assert.is_true age < 2800, "âge trop grand : #{age}"

  it "ramène un âge négatif (horloge reculée) à 0", ->
    os_time = os.time
    m = load_with (nfad, tv) ->
      tv[0].tv_sec = os_time! + 100
      tv[0].tv_usec = 0
      0
    assert.equals 0, m.packet_age_ms {}
