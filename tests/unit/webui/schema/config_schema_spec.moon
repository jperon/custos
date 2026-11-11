-- tests/unit/webui/schema/config_schema_spec.moon
-- Garde-fou bidirectionnel sur la section `doh` du schéma webui :
--  1. chaque clé annoncée existe dans les DEFAULTS de src/config.moon ou est
--     lue par le runtime ;
--  2. chaque clé `config.doh.<x>` lue par le runtime est annoncée.
-- Deux clés fantômes (`cert_path`/`key_path`) y avaient été déclarées alors
-- que le runtime lit `doh.cert` et `doh.key` ; quatre clés réelles
-- (`upstream_doh_url`, `upstream_doh_tls_verify`,
-- `upstream_fallback_insecure`, `upstream_fallback_ca_file`) étaient lues mais
-- absentes du schéma.
--
-- Les correspondances sont des **identifiants complets** : une recherche de
-- sous-chaîne ferait matcher la clé `upstream_doh` dans
-- `config.doh.upstream_doh_url`.

schema = require "webui.schema.config_schema"

read_file = (path) ->
  fh = assert io.open path, "r"
  content = fh\read "*a"
  fh\close!
  content

-- Clés du bloc `doh: { … }` des DEFAULTS de src/config.moon, extraites par un
-- motif d'affectation strict `^\s+<clé>\s*:` (et non par recherche de
-- sous-chaîne dans tout le fichier).
defaults_doh_keys = ->
  src = read_file "src/config.moon"
  start = assert src\find "  doh: {", 1, true
  rest = src\sub start
  stop = assert rest\find "\n  }\n", 1, true
  block = (rest\sub 1, stop)\gsub "^[^\n]*\n", "", 1  -- saute la ligne `doh: {`
  keys = {}
  for line in block\gmatch "[^\n]+"
    key = line\match "^%s+([%w_]+)%s*:"
    keys[key] = true if key
  keys

-- Vrai si `source` contient `prefix..key` en tant qu'identifiant complet :
-- le caractère suivant ne doit pas prolonger le nom (`upstream_doh` ne matche
-- pas `upstream_doh_url`).
reads_key = (source, prefix, key) ->
  pat = prefix .. key
  pos = 1
  while true
    s, e = source\find pat, pos, true
    return false unless s
    nxt = source\sub e + 1, e + 1
    return true unless nxt\match "[%w_]"
    pos = e + 1

-- Modules runtime qui consomment la section doh (main construit doh_cfg,
-- worker_doh lit les clés de transport).
runtime_doh_sources = ->
  read_file("src/main.moon") .. "\n" .. read_file "src/worker_doh.moon"

-- Identifiants complets `config.doh.<clé>` lus par le runtime.
runtime_doh_keys = (runtime) ->
  keys = {}
  for key in runtime\gmatch "config%.doh%.([%w_]+)"
    keys[key] = true
  keys

describe "webui.schema.config_schema — section doh", ->

  it "n'annonce ni cert_path ni key_path (noms jamais lus)", ->
    assert.is_nil schema.doh.cert_path
    assert.is_nil schema.doh.key_path

  it "annonce cert et key, réellement lues par le runtime", ->
    assert.is_not_nil schema.doh.cert
    assert.is_not_nil schema.doh.key
    runtime = runtime_doh_sources!
    for key in *{"cert", "key"}
      assert.is_true reads_key(runtime, "config.doh.", key), key

  it "chaque clé doh du schéma existe dans les DEFAULTS ou est lue par le runtime", ->
    defaults = defaults_doh_keys!
    runtime = runtime_doh_sources!
    for key in pairs schema.doh
      continue if key\sub(1, 1) == "_"
      in_defaults = defaults[key] == true
      in_runtime = reads_key runtime, "config.doh.", key
      assert.truthy in_defaults or in_runtime, "clé doh sans source : #{key}"

  it "le garde-fou ne matche pas une clé préfixe d'une autre (upstream_doh != upstream_doh_url)", ->
    source = 'url = config.doh.upstream_doh_url'
    assert.is_false reads_key source, "config.doh.", "upstream_doh"
    assert.is_true reads_key source, "config.doh.", "upstream_doh_url"
    -- Une clé en fin de ligne/chaîne est bien détectée.
    assert.is_true reads_key 'x = config.doh.enabled', "config.doh.", "enabled"
    assert.is_true reads_key 'config.doh.cert and', "config.doh.", "cert"

  it "sens inverse : toute clé config.doh.* lue par le runtime est au schéma", ->
    runtime = runtime_doh_sources!
    keys = runtime_doh_keys runtime
    assert.truthy keys.upstream_fallback_ca_file
    for key in pairs keys
      assert.is_not_nil schema.doh[key], "clé doh lue mais absente du schéma : #{key}"
    -- Et toute clé des DEFAULTS est annoncée (aucune omission silencieuse).
    for key in pairs defaults_doh_keys!
      assert.is_not_nil schema.doh[key], "clé des DEFAULTS absente du schéma : #{key}"

  it "doh.cert_dir n'est pas une clé doh : le runtime lit auth.cert_dir", ->
    -- main.moon construit `cert_dir: config.auth.cert_dir` ; il n'existe donc
    -- aucune clé `doh.cert_dir` à annoncer dans le schéma.
    assert.is_nil schema.doh.cert_dir
    assert.is_nil defaults_doh_keys!["cert_dir"]
    assert.is_true reads_key(read_file("src/main.moon"), "config.auth.", "cert_dir")
