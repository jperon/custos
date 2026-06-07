-- tests/unit/filter/to_domainlist_bin_spec.moon
-- Couvre le chargement des listes .bin via mmap (lecture seule partagée) :
-- lookup exact, lookup par suffixe, et cas d'erreur (mmap impossible).

{ :factory } = require "filter.conditions.to_domainlist"
bin48 = require "filter.lib.bin48"

-- Répertoire de travail confiné au projet (cf. AGENTS.md : jamais /tmp système).
TMP_DIR = "./tmp/to_domainlist_bin_spec"

-- Écrit un .bin trié à partir d'une liste de domaines (N × 6 octets, 48 bits).
write_bin = (path, domains) ->
  payload = bin48.pack_domains domains
  fh = assert io.open path, "wb"
  fh\write payload
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

  it "lookup répété (cache hit) renvoie le même verdict", ->
    cond = (factory cfg) "blocked"
    a, _ = cond.eval { domain: "evil.example" }
    b, _ = cond.eval { domain: "evil.example" }   -- second appel = hit cache
    assert.is_true a
    assert.is_true b

  it "cache O(1) : éviction générationnelle sous churn ne corrompt pas les verdicts", ->
    cond = (factory cfg) "blocked"
    -- Force > CACHE_MAX_SIZE (1000) entrées distinctes pour déclencher au moins
    -- une passe d'éviction générationnelle, puis vérifie que les verdicts
    -- (exact, suffixe, absent) restent corrects.
    for i = 1, 2500
      cond.eval { domain: "absent-#{i}.example" }
    assert.is_true (cond.eval { domain: "evil.example" })
    assert.is_true (cond.eval { domain: "pixel.ads.tracker.net" })
    assert.is_false (cond.eval { domain: "good.example" })

  it "lookup répété (cache hit) renvoie le même verdict", ->
    cond = (factory cfg) "blocked"
    a, _ = cond.eval { domain: "evil.example" }
    b, _ = cond.eval { domain: "evil.example" }   -- second appel = hit cache
    assert.is_true a
    assert.is_true b

  it "cache O(1) : éviction générationnelle sous churn ne corrompt pas les verdicts", ->
    cond = (factory cfg) "blocked"
    -- Force > CACHE_MAX_SIZE (1000) entrées distinctes pour déclencher au moins
    -- une passe d'éviction, puis vérifie que les verdicts restent corrects.
    for i = 1, 2500
      cond.eval { domain: "absent-#{i}.example" }
    -- Présents (exact + suffixe) et absents toujours correctement classés.
    assert.is_true (cond.eval { domain: "evil.example" })
    assert.is_true (cond.eval { domain: "pixel.ads.tracker.net" })
    assert.is_false (cond.eval { domain: "good.example" })
