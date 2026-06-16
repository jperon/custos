--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Micro-benchmarks in-process des hot-paths du filtre.
-- Mesure ns/op et KB alloués par opération, GC forcé avant chaque cas.
-- Déterministe, sans réseau. Les cas standards requièrent leurs modules en
-- best-effort : un module absent (ex. libxxhash sur certains hôtes) marque le
-- cas « skipped » au lieu de faire échouer le run.

ffi = require "ffi"

--- Mesure une fonction sur `iters` itérations.
-- @tparam string name  Libellé du cas.
-- @tparam number iters Nombre d'itérations (fn reçoit ce compte).
-- @tparam function fn  Boucle à mesurer : fn(iters).
-- @treturn table { name, ns_per_op, kb_alloc }.
bench = (name, iters, fn) ->
  collectgarbage "collect"
  m0 = collectgarbage "count"
  t0 = os.clock!
  fn iters
  t1 = os.clock!
  m1 = collectgarbage "count"
  {
    name: name
    ns_per_op: (t1 - t0) / iters * 1e9
    kb_alloc: m1 - m0
  }

-- Paquet DNS d'exemple (IP + UDP + DNS query A google.com) en octets bruts.
_sample_raw = do
  hex = "4500003a0000400040113c90c0a80101c0a80102" ..
        "80d9003500260000" ..
        "12340100000100000000000006676f6f676c6503636f6d0000010001"
  (hex\gsub "..", (cc) -> string.char tonumber cc, 16)

--- Cas standards : { name, setup } où setup() renvoie la fonction à mesurer
-- (ou lève une erreur si une dépendance manque → cas skippé).
_standard_cases = {
  {
    name: "ipparse ip4+udp+dns parse"
    setup: ->
      { parse: parse_ip4 } = require "ipparse.l3.ip4"
      { parse: parse_udp } = require "ipparse.l4.udp"
      { parse: parse_dns } = require "ipparse.l7.dns"
      raw = _sample_raw
      (n) ->
        for _ = 1, n
          _, off = parse_ip4 raw
          _, off2 = parse_udp raw, off
          parse_dns raw, off2, false
  }
  {
    name: "bin48 truncate"
    setup: ->
      { :truncate } = require "filter.lib.bin48"
      h = 0x123456789abcdefULL
      (n) ->
        for _ = 1, n
          truncate h
  }
  {
    name: "xxhash xxh64 (domaine)"
    setup: ->
      { :xxh64 } = require "ffi_xxhash"
      s = "www.example.com"
      (n) ->
        for _ = 1, n
          xxh64 s
  }
}

--- Lance les cas standards (et optionnels) et renvoie leurs résultats.
-- @tparam ?table opts { iters = 1e6, extra_cases = {...} }.
-- @treturn table Liste de { name, ns_per_op, kb_alloc, skipped? }.
run = (opts = {}) ->
  iters = opts.iters or 1e6
  cases = [ c for c in *_standard_cases ]
  if opts.extra_cases
    for c in *opts.extra_cases
      cases[#cases + 1] = c
  results = {}
  for c in *cases
    ok, fn_or_err = pcall c.setup
    if ok and type(fn_or_err) == "function"
      results[#results + 1] = bench c.name, iters, fn_or_err
    else
      results[#results + 1] = {
        name: c.name
        ns_per_op: 0
        kb_alloc: 0
        skipped: true
        reason: tostring fn_or_err
      }
  results

{ :bench, :run }
