-- tests/unit/log_timing_spec.moon
-- Couvre l'instrumentation du coût d'écriture de log.moon (benchmark) :
--   * coût nul en mode nominal : aucun appel d'horloge supplémentaire ;
--   * durée exposée en µs entières quand l'instrumentation est active ;
--   * la valeur est celle du write TERMINÉ (pas de récursion).
--
-- ffi_defs et libc sont stubbés : `write` ne touche pas stdout, `clock_gettime`
-- avance de 100 µs à chaque appel, ce qui rend la durée mesurée déterministe.

ffi = require "ffi"

describe "log timing (instrumentation benchmark)", ->
  local log, saved_log, saved_config, saved_ffi_defs
  local clock_calls, writes, tick, fake_libc

  setup ->
    saved_log      = package.loaded["log"]
    saved_config   = package.loaded["config"]
    saved_ffi_defs = package.loaded["ffi_defs"]

    clock_calls = 0
    writes      = {}
    tick        = 0

    fake_libc = {
      write: (fd, buf, n) ->
        writes[#writes + 1] = { fd: fd, buf: ffi.string(buf, n), n: n }
        n
      clock_gettime: (clk, tp) ->
        clock_calls += 1
        tick += 100000   -- 100 µs en nanosecondes
        tp.tv_sec  = 0
        tp.tv_nsec = tick
        0
    }

    package.loaded["ffi_defs"] = {
      :ffi
      libc: fake_libc
      libnfq: {}
      libnft: {}
    }
    package.loaded["config"] = { runtime: { log_level: "INFO" } }
    package.loaded["log"] = nil
    log = require "log"

  teardown ->
    package.loaded["log"]      = saved_log
    package.loaded["config"]   = saved_config
    package.loaded["ffi_defs"] = saved_ffi_defs

  before_each ->
    log.set_timing false
    log._rl_reset!
    clock_calls = 0
    writes      = {}
    tick        = 0

  it "expose 0 avant toute mesure", ->
    assert.equals 0, log.get_last_write_us!

  it "mode nominal : aucun appel d'horloge supplémentaire, valeur 0", ->
    log.write_log "INFO", -> { action: "timing_off" }
    -- Une seule horloge : celle de l'epoch, déjà présente avant l'ajout.
    assert.equals 1, clock_calls
    assert.equals 1, #writes
    assert.equals 0, log.get_last_write_us!

  it "mode actif : mesure le write en microsecondes entières", ->
    log.set_timing true
    log.write_log "INFO", -> { action: "timing_on" }
    -- epoch + t0 + t1
    assert.equals 3, clock_calls
    assert.equals 1, #writes
    assert.equals 100, log.get_last_write_us!
    assert.equals "number", type log.get_last_write_us!
    assert.equals math.floor(log.get_last_write_us!), log.get_last_write_us!
    assert.is_true writes[1].buf\find("action=timing_on", 1, true) != nil

  it "désactiver après coup arrête la collecte (valeur figée, horloge inchangée)", ->
    log.set_timing true
    log.write_log "INFO", -> { action: "timing_on" }
    measured = log.get_last_write_us!
    assert.equals 100, measured

    log.set_timing false
    clock_calls = 0
    log.write_log "INFO", -> { action: "timing_off_again" }
    assert.equals 1, clock_calls   -- seulement l'epoch
    assert.equals measured, log.get_last_write_us!
