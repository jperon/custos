-- tests/unit/tools/simplify_spec.moon
-- Tests du cœur d'orchestration tools/classifier/simplify.moon, sur le chemin
-- SANS IA (suppression des sous-domaines redondants), de bout en bout : lecture
-- du fichier, réécriture, récapitulatif. Le repli IA (judge_*) n'est pas testé
-- ici (il dépend d'un appel réseau) — il est couvert par les e2e/manuels.
--
-- Les modules vivent dans tools/classifier/ (non compilés par `make all`) : on
-- charge leurs SOURCES .moon via le runtime moonscript présent dans lua/, en les
-- injectant dans package.loaded pour satisfaire les `require` internes.

simplify = do
  package.path = "tools/classifier/?.lua;#{package.path}"  -- json.lua
  base = require "moonscript.base"
  load_moon = (name, path) ->
    package.loaded[name] = assert(base.loadfile path)!
  load_moon "simplify_lib", "tools/classifier/simplify_lib.moon"
  load_moon "common",       "tools/classifier/common.moon"
  assert(base.loadfile "tools/classifier/simplify.moon")!

write_list = (path, lines) ->
  fh = assert io.open path, "w"
  fh\write table.concat(lines, "\n") .. "\n"
  fh\close!

read_lines = (path) ->
  out = {}
  for line in io.lines path
    out[#out + 1] = line
  out

describe "simplify.simplify_categories (redondance, sans IA)", ->
  lists_dir = "tmp/simplify_spec"
  before_each ->
    os.execute "mkdir -p #{lists_dir}"
  after_each ->
    os.execute "rm -rf #{lists_dir}"

  make_ctx = -> {
    lists_dir:    lists_dir
    models:       {}
    min_children: 3
    batch_size:   30
    max_retries:  1
    samples:      5
    dry_run:      false
    warn:         (->)            -- silencieux
    run_state:    { consecutive: 0, aborted: false, model_idx: 1 }
  }

  it "supprime les sous-domaines couverts par un parent présent", ->
    write_list "#{lists_dir}/t.txt", {
      "userapi.com", "a.userapi.com", "b.userapi.com", "keep.com"
    }
    res = simplify.simplify_categories { "t" }, make_ctx!
    assert.equal 2, res.redundant
    assert.equal 2, res.dropped
    assert.equal 0, res.parents
    assert.same { "t" }, res.touched
    -- Le fichier ne contient plus que le parent et l'entrée indépendante.
    assert.same { "keep.com", "userapi.com" }, read_lines "#{lists_dir}/t.txt"

  it "ne touche pas une liste sans redondance ni candidat", ->
    write_list "#{lists_dir}/t.txt", { "a.com", "b.com", "c.org" }
    res = simplify.simplify_categories { "t" }, make_ctx!
    assert.equal 0, res.dropped
    assert.same {}, res.touched
    assert.same { "a.com", "b.com", "c.org" }, read_lines "#{lists_dir}/t.txt"

  it "dry-run : n'écrit rien mais compte la redondance", ->
    write_list "#{lists_dir}/t.txt", { "foo.net", "x.foo.net", "y.foo.net" }
    ctx = make_ctx!
    ctx.dry_run = true
    res = simplify.simplify_categories { "t" }, ctx
    assert.equal 2, res.redundant
    assert.same {}, res.touched   -- pas de catégorie « modifiée » en dry-run
    -- Fichier intact.
    assert.same { "foo.net", "x.foo.net", "y.foo.net" }, read_lines "#{lists_dir}/t.txt"
