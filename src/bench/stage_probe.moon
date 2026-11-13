--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Sondes par étape du micro-banc hot path (`src/bench/hotpath.moon`).
--
-- Enveloppe les fonctions de module appelées par les handlers RÉELS des
-- workers pour mesurer, par étape, le temps CPU (`os.clock`) et l'allocation
-- (`collectgarbage "count"`, à relever GC arrêté) SANS modifier le code mesuré.
--
-- Deux contraintes dictent l'ordre d'installation (`hotpath.install_probes`) :
--   * le wrapper doit être posé AVANT que les workers ne capturent la fonction
--     (destructuration `{ :f } = require "m"` faite au chargement du module) ;
--   * une fonction appelée par son propre module via une variable locale
--     (ex. `ipc.set_pending` appelée par `ipc.drain_pipe`) n'est PAS
--     interceptable : la sonde du point d'entrée englobe alors ce travail.
--     Les temps sont donc INCLUSIFS (une sonde peut en contenir une autre).
--
-- Le coût propre du wrapper (2 appels d'horloge + 2 relevés de tas + varargs)
-- est de l'ordre de 0,2-0,4 µs par appel : il gonfle le total d'un passage
-- instrumenté, jamais celui du cycle mesuré sans sondes (cas `mixed_*`).
--
-- Limite : les fonctions enveloppées ne doivent pas rendre plus de 5 valeurs
-- (toutes celles des workers en rendent ≤ 5 : `parse_dns_packet` en rend 5).

--- Crée un jeu de sondes vide.
-- @treturn table { wrap, wrap_state, reset, results, labels }
new = ->
  probes = {}
  order = {}

  register = (label) ->
    p = (probes[label] or {
      label: label
      time: 0    -- secondes CPU cumulées (os.clock)
      alloc: 0   -- Kio cumulés (collectgarbage "count")
      calls: 0
    })
    unless probes[label]
      probes[label] = p
      order[#order + 1] = label
    p

  probe_fn = (label, fn) ->
    p = register label
    (...) ->
      t0 = os.clock!
      a0 = collectgarbage "count"
      r1, r2, r3, r4, r5 = fn ...
      p.time += os.clock! - t0
      p.alloc += (collectgarbage "count") - a0
      p.calls += 1
      r1, r2, r3, r4, r5

  --- Enveloppe `mod[field]` (fonction) par une sonde nommée `label`.
  -- @tparam table  mod   Module.
  -- @tparam string field Nom du champ.
  -- @tparam string label Nom de la sonde.
  -- @treturn boolean true si la fonction a été enveloppée
  wrap = (mod, field, label) ->
    return false unless type(mod) == "table" and type(mod[field]) == "function"
    mod[field] = probe_fn label, mod[field]
    true

  --- Enveloppe les méthodes des états rendus par une fabrique `mod[field]`.
  -- Utilisé pour `second_opinion.new`, dont l'état est local au worker.
  -- @tparam table  mod    Module.
  -- @tparam string field  Nom de la fabrique.
  -- @tparam table  labels Noms des méthodes à envelopper (sondes préfixées).
  -- @treturn boolean true si la fabrique a été enveloppée
  wrap_state = (mod, field, labels) ->
    return false unless type(mod) == "table" and type(mod[field]) == "function"
    orig = mod[field]
    mod[field] = (...) ->
      st = orig ...
      for label in *labels
        if type(st) == "table" and type(st[label]) == "function"
          st[label] = probe_fn "so.#{label}", st[label]
      st
    true

  --- Remet tous les compteurs à zéro (avant un passage instrumenté).
  -- @treturn nil
  reset = ->
    for _, p in pairs probes
      p.time  = 0
      p.alloc = 0
      p.calls = 0
    nil

  --- Résultats triés par temps décroissant.
  -- @tparam number iters Nombre d'itérations du passage.
  -- @treturn table Liste { label, us, bytes, calls, calls_req, us_call } (µs et
  --   octets par itération, appels par itération, µs par appel).
  results = (iters) ->
    out = {}
    n = iters > 0 and iters or 1
    for label in *order
      p = probes[label]
      out[#out + 1] = {
        label: label
        us: p.time * 1e6 / n
        bytes: p.alloc * 1024 / n
        calls: p.calls
        calls_req: p.calls / n
        us_call: p.calls > 0 and (p.time * 1e6 / p.calls) or 0
      }
    table.sort out, (a, b) -> a.us > b.us
    out

  --- Noms des sondes installées, dans l'ordre de création.
  -- @treturn table
  labels = -> [p for p in *order]

  { :wrap, :wrap_state, :reset, :results, :labels }

{ :new }
