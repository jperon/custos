--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Orchestrateur CLI du harnais de benchmark.
-- Parse les arguments, lance les volets micro et/ou charge, écrit un rapport
-- texte + une sauvegarde rechargeable dans `tmp/bench/`, et compare à une
-- baseline si demandé.

micro  = require "bench.micro"
load   = require "bench.load"
report = require "bench.report"

BENCH_DIR = "tmp/bench"
BASELINE  = BENCH_DIR .. "/baseline.lua"

--- Parse argv (liste de chaînes) en table d'options.
-- @tparam table argv Arguments (sans le nom du programme).
-- @treturn table options normalisées.
parse_args = (argv) ->
  o = {
    micro: true, load: false
    target: nil, port: 53
    duration: 5, rate: nil, iters: 1e6
    max_queries: nil
    domains_file: nil
    save_baseline: false
  }
  explicit_micro = false
  i = 1
  next_val = ->
    i += 1
    argv[i]
  while i <= #argv
    a = argv[i]
    switch a
      when "--micro"
        o.micro = true
        explicit_micro = true
      when "--load" then o.load = true
      when "--all"
        o.micro = true
        o.load = true
        explicit_micro = true
      when "--target"
        host = next_val!
        if host
          h, p = host\match "^(.+):(%d+)$"
          if h
            o.target = h
            o.port = tonumber p
          else
            o.target = host
      when "--duration" then o.duration = tonumber next_val!
      when "--rate" then o.rate = tonumber next_val!
      when "--iters" then o.iters = tonumber next_val!
      when "--max-queries" then o.max_queries = tonumber next_val!
      when "--domains" then o.domains_file = next_val!
      when "--save-baseline" then o.save_baseline = true
    i += 1
  -- --load seul (sans --micro/--all explicite) ⇒ charge uniquement.
  o.micro = false if o.load and not explicit_micro
  o

--- Charge une liste de domaines depuis un fichier (1/ligne, # commentaires).
-- @tparam string path Chemin du fichier.
-- @treturn table|nil Liste de domaines.
load_domains = (path) ->
  return nil unless path
  f = io.open path, "r"
  return nil unless f
  out = {}
  for line in f\lines!
    line = line\gsub("%s+$", "")\gsub("^%s+", "")
    continue if line == "" or line\sub(1, 1) == "#"
    out[#out + 1] = line
  f\close!
  out

_write_file = (path, content) ->
  f = io.open path, "w"
  return false unless f
  f\write content
  f\close!
  true

--- Point d'entrée : exécute les volets demandés et produit le rapport.
-- @tparam table argv Arguments CLI.
-- @treturn table résultat agrégé.
main = (argv) ->
  o = parse_args argv
  os.execute "mkdir -p " .. BENCH_DIR
  ts = os.date "%Y-%m-%dT%H:%M:%S"
  result = { ts: ts }

  if o.micro
    io.write "[bench] micro-bench (iters=#{o.iters})...\n"
    result.micro = micro.run iters: o.iters

  if o.load
    unless o.target
      io.write "[bench] --load requiert --target host[:port]\n"
      os.exit 1
    io.write "[bench] charge DNS → #{o.target}:#{o.port} (durée=#{o.duration}s)...\n"
    result.load = load.run {
      target: o.target, port: o.port
      duration: o.duration, rate: o.rate
      max_queries: o.max_queries or (o.rate and o.rate * o.duration) or 1e5
      domains: load_domains o.domains_file
    }

  -- Baseline : comparaison et/ou sauvegarde.
  baseline = nil
  if not o.save_baseline
    if bf = io.open BASELINE, "r"
      content = bf\read "*a"
      bf\close!
      baseline = report.deserialize content

  io.write "\n" .. report.format(result, baseline) .. "\n"

  _write_file "#{BENCH_DIR}/report-#{ts}.txt", report.format result, baseline
  _write_file "#{BENCH_DIR}/result-#{ts}.lua", report.serialize result
  if o.save_baseline
    _write_file BASELINE, report.serialize result
    io.write "\n[bench] baseline sauvegardée dans #{BASELINE}\n"

  result

{ :parse_args, :load_domains, :main }
