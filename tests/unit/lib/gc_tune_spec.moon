-- tests/unit/lib/gc_tune_spec.moon
-- Réglage du GC LuaJIT par worker : normalisation des clés `gc` de config,
-- application de setpause/setstepmul, pas de GC sur temps mort et garde-fou
-- mémoire. Le collectgarbage est injecté pour ne jamais perturber le GC réel
-- du processus de test.

gc_tune = require "lib.gc_tune"

-- Faux collectgarbage : enregistre les appels, rend un tas scripté (Kio).
make_fake = (heap_kb) ->
  calls = {}
  heap = { heap_kb }
  gc = (what, arg) ->
    calls[#calls + 1] = { :what, :arg }
    if what == "count"
      heap[1]
  {:gc, :calls, :heap}

describe "gc_tune.normalize", ->
  it "applique les défauts sur une section absente ou vide", ->
    for section in *{nil, {}}
      values = gc_tune.normalize section
      assert.are.equal gc_tune.DEFAULTS.pause, values.pause
      assert.are.equal gc_tune.DEFAULTS.stepmul, values.stepmul
      assert.are.equal gc_tune.DEFAULTS.idle_step, values.idle_step
      assert.are.equal gc_tune.DEFAULTS.max_heap_mb, values.max_heap_mb

  it "accepte les valeurs numériques (y compris chaînes numériques)", ->
    values = gc_tune.normalize {
      pause: "250", stepmul: 300, idle_step: 50, max_heap_mb: "8"
    }
    assert.are.equal 250, values.pause
    assert.are.equal 300, values.stepmul
    assert.are.equal 50, values.idle_step
    assert.are.equal 8, values.max_heap_mb

  it "rejette les valeurs non numériques ou hors bornes et les signale", ->
    values, invalid = gc_tune.normalize {
      pause: "beaucoup", stepmul: 0, idle_step: -3, max_heap_mb: "x"
    }
    assert.are.equal gc_tune.DEFAULTS.pause, values.pause
    assert.are.equal gc_tune.DEFAULTS.stepmul, values.stepmul
    assert.are.equal gc_tune.DEFAULTS.idle_step, values.idle_step
    assert.are.equal gc_tune.DEFAULTS.max_heap_mb, values.max_heap_mb
    seen = {}
    seen[k] = true for k in *invalid
    assert.is_true seen.pause
    assert.is_true seen.stepmul
    assert.is_true seen.idle_step
    assert.is_true seen.max_heap_mb

  it "borne supérieurement les valeurs démesurées", ->
    values = gc_tune.normalize { pause: 999999, stepmul: 999999999 }
    assert.is_true values.pause <= gc_tune.MAX.pause
    assert.is_true values.stepmul <= gc_tune.MAX.stepmul

describe "gc_tune state", ->
  it "apply! applique setpause et setstepmul", ->
    fake = make_fake 1000
    state = gc_tune.new { pause: 200, stepmul: 400 }, { gc: fake.gc }
    state.apply!
    assert.are.same { what: "setpause", arg: 200 }, fake.calls[1]
    assert.are.same { what: "setstepmul", arg: 400 }, fake.calls[2]

  it "idle! fait un pas de GC borné quand idle_step > 0", ->
    fake = make_fake 1000
    state = gc_tune.new { idle_step: 64 }, { gc: fake.gc }
    assert.is_true state.idle!
    assert.are.same { what: "step", arg: 64 }, fake.calls[1]

  it "idle! ne fait rien quand idle_step vaut 0", ->
    fake = make_fake 1000
    state = gc_tune.new { idle_step: 0 }, { gc: fake.gc }
    assert.is_false state.idle!
    assert.are.equal 0, #fake.calls

  it "guard! est inactif quand max_heap_mb vaut 0", ->
    fake = make_fake 999999
    state = gc_tune.new { max_heap_mb: 0 }, { gc: fake.gc, clock: -> 100 }
    assert.are.equal 0, state.guard!
    assert.are.equal 0, #fake.calls

  it "guard! ne force rien sous le plafond", ->
    fake = make_fake 3000   -- 3 Mio
    state = gc_tune.new { max_heap_mb: 4 }, { gc: fake.gc, clock: -> 100 }
    assert.are.equal 0, state.guard!
    assert.are.equal 1, #fake.calls
    assert.are.equal "count", fake.calls[1].what

  it "guard! force des pas jusqu'au retour sous le plafond", ->
    -- Le faux tas baisse à chaque pas : deux pas suffisent.
    calls = 0
    values = {}
    gc = (what, arg) ->
      values[#values + 1] = { :what, :arg }
      if what == "count"
        calls += 1
        return if calls == 1 then 6000 else (if calls == 2 then 5000 else 3000)
      "step"
    state = gc_tune.new { max_heap_mb: 4 }, { gc: gc, clock: -> 100 }
    steps = state.guard!
    assert.are.equal 2, steps
    n_steps = 0
    n_steps += 1 for v in *values when v.what == "step"
    assert.are.equal 2, n_steps

  it "guard! est borné : au plus MAX_FORCE_STEPS pas par vérification", ->
    fake = make_fake 7000
    state = gc_tune.new { max_heap_mb: 1 }, { gc: fake.gc, clock: -> 100 }
    steps = state.guard!
    assert.are.equal gc_tune.MAX_FORCE_STEPS, steps
    n_steps = 0
    n_steps += 1 for c in *fake.calls when c.what == "step"
    assert.are.equal gc_tune.MAX_FORCE_STEPS, n_steps

  it "guard! vérifie le tas au plus une fois par seconde", ->
    fake = make_fake 3000
    now = 100
    state = gc_tune.new { max_heap_mb: 4 }, { gc: fake.gc, clock: -> now }
    state.guard!
    state.guard!
    n_counts = 0
    n_counts += 1 for c in *fake.calls when c.what == "count"
    assert.are.equal 1, n_counts
    now = 101
    state.guard!
    n_counts = 0
    n_counts += 1 for c in *fake.calls when c.what == "count"
    assert.are.equal 2, n_counts

  it "guard! logue au plus une fois toutes les 10 s", ->
    fake = make_fake 8000
    now = 100
    warnings = {}
    warn = (fields) -> warnings[#warnings + 1] = fields
    state = gc_tune.new { max_heap_mb: 1 },
      { gc: fake.gc, clock: (-> now), warn: warn }
    state.guard!
    assert.are.equal 1, #warnings
    assert.are.equal "gc_heap_guard", warnings[1].action
    assert.are.equal 1, warnings[1].max_heap_mb
    -- Nouvelle vérification 2 s plus tard : toujours au-dessus, pas de log.
    now = 102
    state.guard!
    assert.are.equal 1, #warnings
    -- 11 s après le premier log : réémission.
    now = 111
    state.guard!
    assert.are.equal 2, #warnings
