-- tests/unit/webui/schema/config_schema_spec.moon
-- Garde-fou sur la section `doh` du schéma webui : chaque clé annoncée doit
-- exister dans les DEFAULTS de src/config.moon ou être lue par le runtime.
-- Deux clés fantômes (`cert_path`/`key_path`) y avaient été déclarées alors
-- que le runtime lit `doh.cert` et `doh.key`.

schema = require "webui.schema.config_schema"

read_file = (path) ->
  fh = assert io.open path, "r"
  content = fh\read "*a"
  fh\close!
  content

-- Bloc `doh: { … }` des DEFAULTS de src/config.moon (même indentation que la
-- déclaration : deux espaces pour l'ouverture, quatre pour les clés).
defaults_doh_block = ->
  src = read_file "src/config.moon"
  start = assert src\find "  doh: {", 1, true
  rest = src\sub start
  stop = assert rest\find "\n  }\n", 1, true
  rest\sub 1, stop

-- Modules runtime qui consomment la section doh (main construit doh_cfg,
-- worker_doh lit les clés de transport).
runtime_doh_sources = ->
  read_file("src/main.moon") .. "\n" .. read_file "src/worker_doh.moon"

describe "webui.schema.config_schema — section doh", ->

  it "n'annonce ni cert_path ni key_path (noms jamais lus)", ->
    assert.is_nil schema.doh.cert_path
    assert.is_nil schema.doh.key_path

  it "annonce cert et key, réellement lues par le runtime", ->
    assert.is_not_nil schema.doh.cert
    assert.is_not_nil schema.doh.key
    runtime = runtime_doh_sources!
    for key in *{"cert", "key"}
      assert.truthy (runtime\find "config.doh.#{key}", 1, true), key

  it "chaque clé doh du schéma existe dans les DEFAULTS ou est lue par le runtime", ->
    defaults = defaults_doh_block!
    runtime = runtime_doh_sources!
    for key in pairs schema.doh
      continue if key\sub(1, 1) == "_"
      in_defaults = defaults\find "\n    #{key}:", 1, true
      in_runtime = runtime\find ".doh.#{key}", 1, true
      assert.truthy in_defaults or in_runtime, "clé doh sans source : #{key}"
