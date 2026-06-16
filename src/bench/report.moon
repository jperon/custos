--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Mise en forme et persistance des résultats de benchmark.
-- Fonctions pures : agrégation de latences en percentiles, (dé)sérialisation
-- d'une baseline sous forme de table Lua, calcul de deltas % et rendu texte.
-- Aucune dépendance réseau ni FFI : entièrement testable hors ligne.

floor   = math.floor
ceil    = math.ceil
sort    = table.sort
concat  = table.concat
fmt     = string.format

--- Calcule les percentiles d'un échantillon de mesures.
-- @tparam table samples Liste de nombres (latences, etc.).
-- @treturn table { p50, p95, p99, min, max, count }.
percentiles = (samples) ->
  n = #samples
  return { p50: 0, p95: 0, p99: 0, min: 0, max: 0, count: 0 } if n == 0
  -- Copie pour ne pas réordonner la table de l'appelant.
  copy = [ v for v in *samples ]
  sort copy
  pick = (q) -> copy[math.max 1, math.min n, ceil(q * n)]
  {
    p50: pick 0.50
    p95: pick 0.95
    p99: pick 0.99
    min: copy[1]
    max: copy[n]
    count: n
  }

--- Sérialise une valeur Lua (table/nombre/chaîne/booléen) en littéral chargeable.
local _ser
_ser = (v) ->
  t = type v
  if t == "table"
    parts = {}
    -- Détecte une séquence pure (1..n) pour un rendu en liste.
    is_seq = true
    cnt = 0
    for _ in pairs v
      cnt += 1
    is_seq = cnt == #v and cnt > 0
    if is_seq
      for item in *v
        parts[#parts + 1] = _ser item
    else
      keys = [ k for k in pairs v ]
      sort keys, (a, b) -> tostring(a) < tostring(b)
      for k in *keys
        parts[#parts + 1] = "[" .. _ser(k) .. "]=" .. _ser v[k]
    "{" .. concat(parts, ",") .. "}"
  elseif t == "string"
    fmt "%q", v
  elseif t == "number" or t == "boolean"
    tostring v
  else
    "nil"

--- Sérialise un résultat en chaîne `return {...}` rechargeable par deserialize.
-- @tparam table result Résultat de benchmark.
-- @treturn string Code Lua.
serialize = (result) -> "return " .. _ser result

--- Recharge une chaîne produite par serialize.
-- @tparam string s Code Lua `return {...}`.
-- @treturn table|nil Table décodée, ou nil + message d'erreur.
deserialize = (s) ->
  loader = loadstring or load
  chunk, err = loader s, "baseline"
  return nil, "chargement impossible : " .. tostring(err) unless chunk
  ok, val = pcall chunk
  return nil, "évaluation impossible : " .. tostring(val) unless ok
  return nil, "la baseline n'est pas une table" unless type(val) == "table"
  val

--- Calcule la variation relative (%) de chaque métrique numérique partagée.
-- @tparam table cur  Résultat courant (plat : métrique → nombre).
-- @tparam table base Baseline (même forme).
-- @treturn table métrique → delta % (nil si base 0 ou absente).
deltas = (cur, base) ->
  out = {}
  for k, v in pairs cur
    bv = base[k]
    continue unless type(v) == "number" and type(bv) == "number"
    continue if bv == 0
    out[k] = (v - bv) / bv * 100
  out

_fmt_delta = (d) -> d and fmt(" (%+.1f%%)", d) or ""

--- Rend un rapport texte lisible, avec deltas % si une baseline est fournie.
-- @tparam table result Résultat courant ({ micro, load, ts }).
-- @tparam ?table baseline Baseline pour comparaison.
-- @treturn string Rapport multi-lignes.
format = (result, baseline) ->
  lines = {}
  add = (s) -> lines[#lines + 1] = s
  add "=== CustosVirginum — rapport de benchmark ==="
  add "date : " .. (result.ts or "?")
  if result.micro
    add ""
    add "--- micro-bench (in-process) ---"
    base_by_name = {}
    if baseline and baseline.micro
      for c in *baseline.micro
        base_by_name[c.name] = c
    for c in *result.micro
      d = nil
      if bc = base_by_name[c.name]
        dd = deltas { ns: c.ns_per_op }, { ns: bc.ns_per_op }
        d = dd.ns
      add fmt "%-46s %10.1f ns/op   ~%7.0f KB%s",
        c.name, c.ns_per_op, c.kb_alloc, _fmt_delta d
  if result.load
    l = result.load
    bl = baseline and baseline.load
    add ""
    add "--- charge DNS (bout-en-bout) ---"
    show = (label, key, unit = "") ->
      d = bl and (deltas { x: l[key] }, { x: bl[key] }).x or nil
      add fmt "  %-22s %12.2f %s%s", label, l[key] or 0, unit, _fmt_delta d
    show "qps",       "qps"
    show "sent",      "sent"
    show "received",  "received"
    show "dropped",   "dropped"
    show "timeouts",  "timeouts"
    show "latence p50", "p50", "ms"
    show "latence p95", "p95", "ms"
    show "latence p99", "p99", "ms"
  concat lines, "\n"

{ :percentiles, :serialize, :deserialize, :deltas, :format }
