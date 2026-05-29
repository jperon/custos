-- tests/unit/filter/to_domainlist_bin_spec.moon
-- Couvre le chargement des listes .bin via mmap (lecture seule partagée) :
-- lookup exact, lookup par suffixe, et cas d'erreur (mmap impossible).

ffi = require "ffi"
{ :factory } = require "filter.conditions.to_domainlist"
{ :xxh64 } = require "ffi_xxhash"

-- Répertoire de travail confiné au projet (cf. AGENTS.md : jamais /tmp système).
TMP_DIR = "./tmp/to_domainlist_bin_spec"

-- Écrit un .bin trié à partir d'une liste de domaines (N × uint64 LE).
write_bin = (path, domains) ->
  hashes = [ xxh64(d) for d in *domains ]
  table.sort hashes, (a, b) -> a < b
  n = #hashes
  arr = ffi.new "uint64_t[?]", n
  for i = 1, n
    arr[i - 1] = hashes[i]
  fh = assert io.open path, "wb"
  fh\write ffi.string ffi.cast("const char*", arr), n * 8
  fh\close!

setup ->
  os.execute "mkdir -p #{TMP_DIR}/lists"
  write_bin "#{TMP_DIR}/lists/blocked.bin", { "evil.example", "ads.tracker.net" }

teardown ->
  os.execute "rm -rf #{TMP_DIR}"

describe "filter.conditions.to_domainlist (.bin via mmap)", ->
  cfg = { domainlists_dir: "#{TMP_DIR}/lists" }

  it "match exact sur un domaine présent", ->
    cond = (factory cfg) "blocked"
    ok, _ = cond.eval { domain: "evil.example" }
    assert.is_true ok

  it "match par suffixe (sous-domaine)", ->
    cond = (factory cfg) "blocked"
    ok, _ = cond.eval { domain: "pixel.ads.tracker.net" }
    assert.is_true ok

  it "domaine absent → faux", ->
    cond = (factory cfg) "blocked"
    ok, _ = cond.eval { domain: "good.example" }
    assert.is_false ok

  it "liste inexistante (ni .bin ni .domains) → erreur explicite", ->
    cond = (factory cfg) "missing"
    ok, msg = cond.eval { domain: "evil.example" }
    assert.is_false ok
    assert.is_truthy msg\match "Cannot load domain list"
