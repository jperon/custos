-- src/lib/gc_tune.moon
-- Réglage du GC LuaJIT par worker (machines à RAM limitée).
--
-- Trois mécanismes, sans changement de comportement fonctionnel :
--   • `apply!` applique `gc.pause`/`gc.stepmul` (collectgarbage setpause /
--     setstepmul) au démarrage du worker ;
--   • `idle!` effectue un pas de GC borné (`gc.idle_step`) quand une boucle
--     est au repos (file NFQUEUE ou tube vide), ce qui évite de laisser le tas
--     grossir pendant les trous de trafic ;
--   • `guard!` vérifie `collectgarbage "count"` au plus une fois par seconde et
--     force des pas si le tas dépasse `gc.max_heap_mb` ; il ne peut donc jamais
--     rester un GC « arrêté » sans borne de mémoire. Le log est lui-même limité
--     (un `gc_heap_guard` au plus toutes les 10 s par worker).
--
-- Les dépendances (collectgarbage, horloge, log) sont injectables : le module
-- est testable sans toucher au GC réel ni attendre une seconde.

DEFAULTS = {
  pause: 200
  stepmul: 400
  idle_step: 100
  max_heap_mb: 32
}

-- Bornes de validation (config.moon rejette hors bornes avec un warn).
MIN = { pause: 0, stepmul: 1, idle_step: 0, max_heap_mb: 0 }
MAX = { pause: 10000, stepmul: 100000, idle_step: 100000, max_heap_mb: 65536 }

HEAP_CHECK_INTERVAL = 1   -- s entre deux lectures de collectgarbage "count"
LOG_INTERVAL        = 10  -- s entre deux logs gc_heap_guard
MAX_FORCE_STEPS     = 8   -- pas de GC forcés au plus par vérification
FORCE_STEP          = 200 -- taille d'un pas forcé (unités collectgarbage "step")

--- Entier dans [lo, hi] ou nil si absent/invalide.
-- @tparam any raw Valeur brute (nombre ou chaîne numérique).
-- @tparam number default Valeur de repli si absente.
-- @tparam number lo Borne basse (incluse).
-- @tparam number hi Borne haute (incluse).
-- @treturn number|nil Valeur entière validée.
int_value = (raw, default, lo, hi) ->
  return nil if raw == nil
  n = tonumber raw
  return nil if n == nil
  n = math.floor n
  return nil if n < lo or n > hi
  n

--- Normalise la section `gc` de la configuration.
-- Les clés absentes prennent le défaut ; les valeurs non numériques ou hors
-- bornes aussi, et sont signalées dans la seconde valeur de retour.
-- @tparam table|nil section Table `gc` brute.
-- @treturn table Valeurs validées { pause, stepmul, idle_step, max_heap_mb }.
-- @treturn table Liste des clés rejetées.
normalize = (section) ->
  section = {} unless type(section) == "table"
  values = {}
  invalid = {}
  for key in *{"pause", "stepmul", "idle_step", "max_heap_mb"}
    raw = section[key]
    v = int_value raw, DEFAULTS[key], MIN[key], MAX[key]
    if v == nil
      values[key] = DEFAULTS[key]
      invalid[#invalid + 1] = key if raw != nil
    else
      values[key] = v
  values, invalid

--- Construit l'état GC d'un worker.
-- @tparam table|nil section Section `gc` de config (valeurs déjà validées ou non).
-- @tparam table|nil deps    Dépendances injectables : gc, clock, warn.
-- @treturn table État { values, apply!, idle!, guard! }.
new = (section, deps) ->
  values = normalize section
  gc = (deps and deps.gc) or collectgarbage
  clock = (deps and deps.clock) or os.time
  warn = deps and deps.warn
  unless warn
    warn = (fields) ->
      { :log_warn } = require "log"
      log_warn -> fields

  state = { last_check: nil, last_log: nil, forced: 0 }

  api = { :values }

  --- Applique pause/stepmul au GC du processus courant.
  -- @treturn boolean true.
  api.apply = ->
    gc "setpause", values.pause
    gc "setstepmul", values.stepmul
    true

  --- Pas de GC borné sur temps mort (file/tube vide).
  -- @treturn boolean true si un pas a été effectué.
  api.idle = ->
    return false unless values.idle_step > 0
    gc "step", values.idle_step
    true

  --- Garde-fou mémoire : force des pas si le tas dépasse le plafond.
  -- @tparam[opt] number now Horloge (secondes) injectable, défaut clock!.
  -- @treturn number Nombre de pas forcés (0 si sous le plafond ou hors échéance).
  api.guard = (now) ->
    return 0 unless values.max_heap_mb > 0
    now = clock! unless now
    if state.last_check and now - state.last_check < HEAP_CHECK_INTERVAL
      return 0
    state.last_check = now
    limit_kb = values.max_heap_mb * 1024
    used = gc "count"
    return 0 if used <= limit_kb
    steps = 0
    while steps < MAX_FORCE_STEPS
      gc "step", FORCE_STEP
      steps += 1
      used = gc "count"
      break if used <= limit_kb
    state.forced += 1
    if not state.last_log or now - state.last_log >= LOG_INTERVAL
      state.last_log = now
      warn {
        action: "gc_heap_guard"
        heap_kb: used
        max_heap_mb: values.max_heap_mb
        steps: steps
      }
    steps

  api

_shared = nil

--- État GC partagé du processus worker, construit depuis `config.gc`.
-- @treturn table État GC.
shared = ->
  unless _shared
    section = (require "config").gc or {}
    _shared = new section
  _shared

--- Oublie l'état partagé (tests, changement de configuration).
-- @treturn nil
reset = ->
  _shared = nil

{ :DEFAULTS, :MIN, :MAX, :HEAP_CHECK_INTERVAL, :LOG_INTERVAL,
  :MAX_FORCE_STEPS, :FORCE_STEP, :normalize, :new, :shared, :reset }
