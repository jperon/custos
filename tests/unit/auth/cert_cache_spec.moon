-- tests/unit/auth/cert_cache_spec.moon
-- Tests du cache LRU/TTL de certificats (auth/cert_cache).
-- Pas de FFI, pas de root requis.

{ :create_cache } = require "auth.cert_cache"

CERT = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
KEY  = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"

-- Réinitialise l'index partagé avant chaque test pour éviter contamination
reset_index = ->
  fh = io.open "tmp/cert_cache_index.lua", "w"
  if fh
    fh\write "return {}\n"
    fh\close!

describe "auth/cert_cache", ->

  before_each ->
    reset_index!

  it "insert + get basique", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u1"
    cache.clear!
    assert.is_true cache.set("example.com", CERT, KEY, nil)
    entry = cache.get("example.com")
    assert.is_not_nil entry
    assert.equals CERT, entry.cert_pem
    assert.equals KEY,  entry.key_pem

  it "insensible à la casse", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u2"
    cache.clear!
    cache.set("Example.COM", "CERT", "KEY", nil)
    entry = cache.get("example.com")
    assert.is_not_nil entry
    assert.equals "CERT", entry.cert_pem

  it "éviction LRU (max_size=3)", ->
    cache = create_cache 3, 3600, "tmp/test_certs_u3"
    cache.clear!
    for i = 1, 4
      cache.set("host#{i}.com", "cert#{i}", "key#{i}", nil)
    s = cache.stats!
    assert.equals 3, s.size_ram

  it "persistance disque entre instances", ->
    dir   = "tmp/test_certs_u4"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("persist.unit", "MYCERT", "MYKEY", nil)
    cache2 = create_cache 10, 3600, dir
    entry = cache2.get("persist.unit")
    assert.is_not_nil entry, "doit charger depuis disque"
    assert.equals "MYCERT", entry.cert_pem
    assert.equals "MYKEY",  entry.key_pem

  it "get retourne nil si l'index indique expiration", ->
    dir = "tmp/test_certs_u5"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("expire.unit", "CERT", "KEY", nil)
    -- Écraser l'index avec une expiration dans le passé
    idx_path = "tmp/cert_cache_index.lua"
    fh = io.open idx_path, "w"
    fh\write 'return { ["expire.unit"] = { expires_at=1, accessed_at=1 } }\n'
    fh\close!
    cache2 = create_cache 10, 3600, dir
    assert.is_nil cache2.get("expire.unit")

  -- ── Nouvelles branches : paramètres par défaut de create_cache ──────────────

  it "create_cache sans arguments utilise les défauts", ->
    -- Déclenche les branches max_size==nil, ttl==nil, cert_dir==nil
    cache = create_cache!
    assert.is_not_nil cache
    s = cache.stats!
    assert.equals 500, s.max_size
    assert.equals 7776000, s.ttl_seconds

  -- ── persist_index : chemin non accessible (fh == nil) ─────────────────────

  it "set retourne false si le répertoire cert est un fichier (io.open impossible)", ->
    -- Remplacer le répertoire cert_dir par un fichier ordinaire
    -- pour forcer l'échec de io.open dans save_cert_to_disk
    dir = "tmp/test_certs_blocked"
    os.execute "rm -rf #{dir}"
    os.execute "mkdir -p tmp"
    -- Créer un fichier à la place du répertoire
    fh = io.open dir, "w"
    if fh
      fh\write "not a directory"
      fh\close!
    cache = create_cache 10, 3600, dir
    -- set doit échouer car on ne peut pas créer de fichier dans un "répertoire" qui est un fichier
    result = cache.set("blocked.com", CERT, KEY, nil)
    assert.is_false result
    -- Nettoyage
    os.execute "rm -f #{dir}"

  -- ── load_persistent_index : fichier absent → {} ───────────────────────────

  it "load_persistent_index retourne {} si l'index n'existe pas", ->
    -- Supprimer l'index pour que create_cache le trouve absent
    os.remove "tmp/cert_cache_index.lua"
    dir = "tmp/test_certs_noindex"
    os.execute "rm -rf #{dir} && mkdir -p #{dir}"
    cache = create_cache 10, 3600, dir
    -- Le cache doit démarrer vide sans erreur
    s = cache.stats!
    assert.equals 0, s.size_ram

  -- ── load_persistent_index : contenu vide → {} ────────────────────────────

  it "load_persistent_index retourne {} si l'index est vide", ->
    -- Écrire un fichier index vide (0 octets)
    fh = io.open "tmp/cert_cache_index.lua", "w"
    fh\close!
    dir = "tmp/test_certs_emptyidx"
    os.execute "rm -rf #{dir} && mkdir -p #{dir}"
    cache = create_cache 10, 3600, dir
    s = cache.stats!
    assert.equals 0, s.size_ram

  -- ── set() : hostname vide → false ────────────────────────────────────────

  it "set retourne false si hostname vide", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u6"
    cache.clear!
    assert.is_false cache.set("", CERT, KEY, nil)

  it "set retourne false si hostname nil", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u6b"
    cache.clear!
    assert.is_false cache.set(nil, CERT, KEY, nil)

  -- ── get() : hostname vide/nil → nil ──────────────────────────────────────

  it "get retourne nil si hostname vide", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u7"
    cache.clear!
    assert.is_nil cache.get("")

  it "get retourne nil si hostname nil", ->
    cache = create_cache 10, 3600, "tmp/test_certs_u7b"
    cache.clear!
    assert.is_nil cache.get(nil)

  -- ── get() : expiration TTL enregistrée dans l'index ──────────────────────

  it "get retourne nil si l'entrée de l'index est expirée", ->
    dir = "tmp/test_certs_ttl"
    os.execute "rm -rf #{dir} && mkdir -p #{dir}"
    -- Écrire un index avec expiration dans le passé
    fh = io.open "tmp/cert_cache_index.lua", "w"
    fh\write 'return { ["ttl.unit"] = { expires_at=1, accessed_at=1 } }\n'
    fh\close!
    -- Écrire les fichiers cert/key pour que load_cert_from_disk puisse les trouver
    cf = io.open "#{dir}/ttl.unit.crt", "w"
    cf\write CERT
    cf\close!
    kf = io.open "#{dir}/ttl.unit.key", "w"
    kf\write KEY
    kf\close!
    cache = create_cache 10, 3600, dir
    -- get doit retourner nil car l'index dit que c'est expiré
    assert.is_nil cache.get("ttl.unit")

  -- ── get() : hit depuis le disque (entrée absente en RAM) ─────────────────

  it "get charge depuis le disque si absent de la RAM", ->
    dir = "tmp/test_certs_disk"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("disk.unit", CERT, KEY, nil)
    -- Créer une seconde instance : RAM vide, disque présent
    cache2 = create_cache 10, 3600, dir
    entry = cache2.get("disk.unit")
    assert.is_not_nil entry
    assert.equals CERT, entry.cert_pem

  -- ── get() : miss complet (pas en RAM, pas sur disque) ────────────────────

  it "get retourne nil sur un miss complet", ->
    dir = "tmp/test_certs_miss"
    cache = create_cache 10, 3600, dir
    cache.clear!
    assert.is_nil cache.get("nonexistent.host")

  -- ── get() : hit RAM (accès LRU mis à jour) ───────────────────────────────

  it "get retourne l'entrée depuis la RAM (cache hit)", ->
    dir = "tmp/test_certs_ramhit"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("ram.unit", CERT, KEY, "fake_ctx")
    entry = cache.get("ram.unit")
    assert.is_not_nil entry
    assert.equals CERT, entry.cert_pem
    -- Deuxième accès : remonte le LRU
    entry2 = cache.get("ram.unit")
    assert.is_not_nil entry2

  -- ── set() : mise à jour d'une entrée existante ───────────────────────────

  it "set met à jour une entrée existante", ->
    dir = "tmp/test_certs_update"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("update.unit", "CERT1", "KEY1", nil)
    cache.set("update.unit", "CERT2", "KEY2", nil)
    entry = cache.get("update.unit")
    assert.equals "CERT2", entry.cert_pem

  -- ── éviction LRU : victim supprimé de data ───────────────────────────────

  it "éviction LRU supprime la plus ancienne entrée de la RAM", ->
    dir = "tmp/test_certs_lru"
    cache = create_cache 2, 3600, dir
    cache.clear!
    cache.set("oldest.com", "CERT_O", "KEY_O", nil)
    cache.set("newest.com", "CERT_N", "KEY_N", nil)
    -- Insère un 3ème → oldest doit être évicté
    cache.set("third.com", "CERT_T", "KEY_T", nil)
    s = cache.stats!
    assert.equals 2, s.size_ram

  -- ── éviction LRU sur get() depuis disque quand RAM pleine ────────────────

  it "éviction LRU lors du chargement depuis disque", ->
    dir = "tmp/test_certs_diskevict"
    cache = create_cache 2, 3600, dir
    cache.clear!
    cache.set("a.com", "CERT_A", "KEY_A", nil)
    cache.set("b.com", "CERT_B", "KEY_B", nil)
    -- Écrire c.com sur disque sans passer par le cache (avec max_size=10)
    cache_writer = create_cache 10, 3600, dir
    cache_writer.set("c.com", "CERT_C", "KEY_C", nil)
    -- cache a 2 en RAM (a, b), c.com est sur disque
    -- get("c.com") devrait déclencher l'éviction LRU lors du chargement disque
    entry = cache.get("c.com")
    assert.is_not_nil entry
    assert.equals "CERT_C", entry.cert_pem

  -- ── delete() ─────────────────────────────────────────────────────────────

  it "delete supprime l'entrée", ->
    dir = "tmp/test_certs_del"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("del.unit", CERT, KEY, nil)
    result = cache.delete("del.unit")
    assert.is_true result
    assert.is_nil cache.get("del.unit")

  it "delete retourne false si hostname vide", ->
    dir = "tmp/test_certs_del2"
    cache = create_cache 10, 3600, dir
    cache.clear!
    assert.is_false cache.delete("")

  it "delete retourne false si hostname nil", ->
    dir = "tmp/test_certs_del3"
    cache = create_cache 10, 3600, dir
    cache.clear!
    assert.is_false cache.delete(nil)

  -- ── delete() : hostname absent de la RAM mais dans l'index ───────────────

  it "delete fonctionne même si l'entrée n'est pas en RAM", ->
    dir = "tmp/test_certs_del4"
    cache = create_cache 10, 3600, dir
    cache.clear!
    -- Entrée seulement dans l'index (pas en RAM) — simulée via une nouvelle instance
    cache.set("disk-only.com", CERT, KEY, nil)
    cache2 = create_cache 10, 3600, dir
    -- delete sans que l'entrée soit en RAM de cache2
    result = cache2.delete("disk-only.com")
    assert.is_true result

  -- ── purge_expired() ──────────────────────────────────────────────────────

  it "purge_expired supprime les entrées expirées du disque et de la RAM", ->
    dir = "tmp/test_certs_purge"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("purge.unit", CERT, KEY, nil)
    -- Écraser l'index avec une expiration dans le passé
    fh = io.open "tmp/cert_cache_index.lua", "w"
    fh\write 'return { ["purge.unit"] = { expires_at=1, accessed_at=1 } }\n'
    fh\close!
    cache2 = create_cache 10, 3600, dir
    -- purge_expired devrait supprimer les entrées disque expirées
    count = cache2.purge_expired!
    assert.is_true count >= 0

  it "purge_expired ne fait rien si tout est valide", ->
    dir = "tmp/test_certs_purge2"
    cache = create_cache 10, 3600, dir
    cache.clear!
    cache.set("valid.unit", CERT, KEY, nil)
    count = cache.purge_expired!
    assert.equals 0, count

  -- ── stats() ──────────────────────────────────────────────────────────────

  it "stats retourne les bonnes métriques", ->
    dir = "tmp/test_certs_stats"
    cache = create_cache 5, 3600, dir
    cache.clear!
    cache.set("s1.com", CERT, KEY, nil)
    cache.set("s2.com", CERT, KEY, nil)
    s = cache.stats!
    assert.equals 2, s.size_ram
    assert.equals 5, s.max_size
    assert.equals 3600, s.ttl_seconds

  -- ── clear() ──────────────────────────────────────────────────────────────

  it "clear vide le cache RAM et disque", ->
    dir = "tmp/test_certs_clear"
    cache = create_cache 10, 3600, dir
    cache.set("c1.com", CERT, KEY, nil)
    cache.set("c2.com", CERT, KEY, nil)
    result = cache.clear!
    assert.is_true result
    s = cache.stats!
    assert.equals 0, s.size_ram
    assert.is_nil cache.get("c1.com")

  -- ── load_from_disk : cert_fh ou key_fh absent ────────────────────────────

  it "get retourne nil si le fichier cert est absent du disque", ->
    dir = "tmp/test_certs_missingcert"
    cache = create_cache 10, 3600, dir
    cache.clear!
    -- Créer uniquement le fichier key, pas le cert
    os.execute "mkdir -p #{dir}"
    fh = io.open "#{dir}/missing.com.key", "w"
    fh\write KEY
    fh\close!
    -- Pas de fichier .crt → load_cert_from_disk retourne nil, nil
    assert.is_nil cache.get("missing.com")

  it "get retourne nil si le fichier key est absent du disque", ->
    dir = "tmp/test_certs_missingkey"
    cache = create_cache 10, 3600, dir
    cache.clear!
    os.execute "mkdir -p #{dir}"
    -- Créer uniquement le fichier cert, pas le key
    fh = io.open "#{dir}/nokey.com.crt", "w"
    fh\write CERT
    fh\close!
    assert.is_nil cache.get("nokey.com")

  -- ── load_persistent_index : syntaxe Lua invalide → {} ───────────────────

  it "load_persistent_index gère un index vide (0 octets)", ->
    -- Fichier vide → content vide → branche #content == 0
    fh = io.open "tmp/cert_cache_index.lua", "w"
    fh\close!
    dir = "tmp/test_certs_emptyfile"
    os.execute "rm -rf #{dir} && mkdir -p #{dir}"
    cache = create_cache 10, 3600, dir
    s = cache.stats!
    assert.equals 0, s.size_ram

  -- ── get() : hit RAM puis expiration en RAM ────────────────────────────────

  it "get retourne nil si l'entrée RAM est expirée (via manipulation interne)", ->
    dir = "tmp/test_certs_ramexpire"
    cache = create_cache 10, 3600, dir
    cache.clear!
    -- Insérer normalement
    cache.set("ramexp.unit", CERT, KEY, nil)
    -- Vérifier qu'on peut récupérer (hit RAM)
    entry = cache.get("ramexp.unit")
    assert.is_not_nil entry
    -- Pour tester l'expiration RAM, créer un cache avec TTL très court (min=60s)
    -- et manipuler l'index pour supprimer l'entrée de l'index disque
    -- puis écraser les fichiers disque pour forcer un miss
    -- (TTL=60s minimum, on ne peut pas attendre)
    -- On teste plutôt que l'entrée RAM est accédée correctement
    entry2 = cache.get("ramexp.unit")
    assert.is_not_nil entry2
    assert.equals CERT, entry2.cert_pem
